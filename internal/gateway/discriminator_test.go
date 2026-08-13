package gateway

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// discFixture 是判别器测试的夹具。
type discFixture struct {
	reg  *Registry
	disc *Discriminator
	gw   *Gateway
}

func newDiscFixture(t *testing.T, sessions sessionMap, tlsCfg *tls.Config, acme func(net.Conn)) *discFixture {
	t.Helper()

	reg := NewRegistry()
	gw := NewGateway(GatewayConfig{
		Registry: reg,
		Dialer:   &TunnelDialer{Lookup: sessions},
		Log:      testLogger(t),
	})
	t.Cleanup(func() { _ = gw.Close() })

	disc := NewDiscriminator(DiscriminatorConfig{
		Registry: reg,
		Gateway:  gw,
		// 单步期限刻意放到 5 秒：若实现是「按全局最大字节数 ReadFull」，
		// 短首包的用例就会跑满 5 秒，测试因此能抓住那个退化。
		PeekStep:   5 * time.Second,
		PeekBudget: 10 * time.Second,
		TLSConfig:  tlsCfg,
		ACME:       acme,
		Log:        testLogger(t),
	})
	t.Cleanup(func() { _ = disc.Close() })

	return &discFixture{reg: reg, disc: disc, gw: gw}
}

// decide 把 payload 写进一条内存连接后跑判别，返回结果与耗时。
//
// 刻意**不关闭**写端：真实客户端发完首包就等服务端说话，
// 若实现依赖 EOF 来结束读取，这里就会挂住。
func (f *discFixture) decide(t *testing.T, payload []byte, port uint16) (Decision, time.Duration) {
	t.Helper()

	near, far := net.Pipe()
	t.Cleanup(func() {
		near.Close()
		far.Close()
	})
	if len(payload) > 0 {
		go func() { _, _ = far.Write(payload) }()
	}

	local := netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), port)
	start := time.Now()
	dec := f.disc.Decide(near, local)
	return dec, time.Since(start)
}

// TestDiscriminatorOrder 按 spec §7.3 的顺序逐步覆盖判别。
func TestDiscriminatorOrder(t *testing.T) {
	agent := startFakeAgent(t, func(proto.StreamOpen) (net.Conn, error) {
		a, b := net.Pipe()
		go io.Copy(io.Discard, b)
		return a, nil
	})
	sessions := sessionMap{"agent-1": agent.session("agent-1")}
	tlsCfg := selfSignedTLS(t, "gw.example.com")

	var acmeHits int
	f := newDiscFixture(t, sessions, tlsCfg, func(c net.Conn) {
		acmeHits++
		_ = c.Close()
	})

	// 端口 9001：专用端口（场景二的 ESP32）。
	robot := portTunnel("robot", tunnel.TLSPassthrough, "192.168.1.5:8080")
	if err := f.reg.BindDedicated(9001, robot); err != nil {
		t.Fatal(err)
	}

	// 端口 443：共享端口，透传 + 网关并存，另有一个默认绑定。
	pt := sharedTunnel("pt", tunnel.TLSPassthrough, tunnel.RouterTLSSNI,
		"192.168.1.9:443", []string{"pt.example.com"}, nil)
	gw := sharedTunnel("gw", tunnel.TLSGateway, tunnel.RouterHTTP,
		"192.168.1.5:25808", []string{"gw.example.com"}, []string{"/api"})
	fallback := portTunnel("fallback", tunnel.TLSPassthrough, "192.168.1.20:9999")
	for _, tn := range []*tunnel.Tunnel{pt, gw} {
		if err := f.reg.AddShared(443, tn); err != nil {
			t.Fatalf("注册 %s 失败：%v", tn.Slug, err)
		}
	}
	if err := f.reg.BindDefault(443, fallback); err != nil {
		t.Fatal(err)
	}

	// 端口 8443：共享端口，但**没有**默认绑定 —— 用于验证拒绝路径。
	if err := f.reg.AddShared(8443, gw); err != nil {
		t.Fatal(err)
	}

	// 端口 8080：明文入口，可信 PROXY protocol。
	clearGw := sharedTunnel("clear-gw", tunnel.TLSGateway, tunnel.RouterHTTP,
		"192.168.1.5:25808", []string{"clear.example.com"}, nil)
	if err := f.reg.AddShared(8080, clearGw); err != nil {
		t.Fatal(err)
	}
	f.reg.SetTrustProxyProtocol(8080, true)

	// 端口 8081：明文入口，**不**可信 PROXY protocol。
	if err := f.reg.AddShared(8081, clearGw); err != nil {
		t.Fatal(err)
	}

	httpGet := func(host, path string) []byte {
		return []byte("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
	}

	cases := []struct {
		name       string
		port       uint16
		payload    []byte
		wantAction Action
		wantStep   Step
		wantSlug   string
		wantReject RejectMode
		wantClient string
		// fast 为真表示这一步不该等更多字节。
		fast bool
	}{
		{
			name: "步骤0 专用端口：一个字节都不 peek",
			port: 9001, payload: nil,
			wantAction: ActionSplice, wantStep: StepDedicated, wantSlug: "robot", fast: true,
		},
		{
			name: "步骤1 可信监听器上消费 PROXY v1 并采信其源地址",
			port: 8080,
			payload: append([]byte("PROXY TCP4 203.0.113.9 198.51.100.1 51234 8080\r\n"),
				httpGet("clear.example.com", "/")...),
			wantAction: ActionCleartext, wantStep: StepHostPath, wantSlug: "clear-gw",
			wantClient: "203.0.113.9:51234",
		},
		{
			name:       "步骤1 可信监听器上消费 PROXY v2",
			port:       8080,
			payload:    append(proxyV2Sample("203.0.113.77", 40000), httpGet("clear.example.com", "/")...),
			wantAction: ActionCleartext, wantStep: StepHostPath, wantSlug: "clear-gw",
			wantClient: "203.0.113.77:40000",
		},
		{
			name: "步骤1 不可信监听器绝不解析 PROXY 头",
			port: 8081,
			payload: append([]byte("PROXY TCP4 203.0.113.9 198.51.100.1 51234 8081\r\n"),
				httpGet("clear.example.com", "/")...),
			// 不解析 → "PROXY ..." 被当成明文请求行 → 解析失败 → 拒绝。
			// 这正是我们要的：伪造源 IP 的能力绝不能给不可信来源。
			wantAction: ActionReject, wantStep: StepReject, wantReject: RejectHTTPStatus,
		},
		{
			name: "步骤2 非 TLS 非明文的首字节落到端口默认绑定",
			port: 443, payload: []byte{0x00},
			wantAction: ActionSplice, wantStep: StepPortDefault, wantSlug: "fallback", fast: true,
		},
		{
			name: "步骤3 acme-tls/1 永远本地终止",
			port: 443,
			payload: clientHelloBytes(t, &tls.Config{
				ServerName: "pt.example.com", NextProtos: []string{ACMETLSALPNProto}}),
			wantAction: ActionACME, wantStep: StepALPNACME, fast: true,
		},
		{
			name:       "步骤4 SNI 命中透传隧道则拼接，不解密",
			port:       443,
			payload:    clientHelloBytes(t, &tls.Config{ServerName: "pt.example.com"}),
			wantAction: ActionSplice, wantStep: StepSNI, wantSlug: "pt", fast: true,
		},
		{
			name:       "步骤4 SNI 命中网关隧道则本地终止",
			port:       443,
			payload:    clientHelloBytes(t, &tls.Config{ServerName: "gw.example.com"}),
			wantAction: ActionGateway, wantStep: StepSNI, wantSlug: "gw", fast: true,
		},
		{
			name:       "步骤4 没有 SNI 时落到端口默认绑定",
			port:       443,
			payload:    clientHelloBytes(t, &tls.Config{InsecureSkipVerify: true}),
			wantAction: ActionSplice, wantStep: StepPortDefault, wantSlug: "fallback", fast: true,
		},
		{
			name:       "步骤6 未注册的 SNI 且无默认绑定则回 TLS 告警",
			port:       8443,
			payload:    clientHelloBytes(t, &tls.Config{ServerName: "nope.example.com"}),
			wantAction: ActionReject, wantStep: StepReject, wantReject: RejectTLSAlert, fast: true,
		},
		{
			name: "步骤5 明文 Host 加路径前缀命中网关",
			port: 8443, payload: httpGet("gw.example.com", "/api/items"),
			wantAction: ActionCleartext, wantStep: StepHostPath, wantSlug: "gw", fast: true,
		},
		{
			name: "步骤5 路径前缀不匹配且无默认绑定则拒绝",
			port: 8443, payload: httpGet("gw.example.com", "/admin"),
			wantAction: ActionReject, wantStep: StepReject, wantReject: RejectHTTPStatus, fast: true,
		},
		{
			name: "步骤5 IP 字面量 Host 落到端口默认绑定",
			port: 443, payload: httpGet("198.51.100.1:443", "/robot/status"),
			wantAction: ActionSplice, wantStep: StepPortDefault, wantSlug: "fallback", fast: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec, elapsed := f.decide(t, tc.payload, tc.port)

			if dec.Action != tc.wantAction {
				t.Fatalf("Action = %q，期望 %q（原因：%s）", dec.Action, tc.wantAction, dec.Reason)
			}
			if dec.Step != tc.wantStep {
				t.Fatalf("Step = %q，期望 %q", dec.Step, tc.wantStep)
			}
			if tc.wantSlug != "" {
				if dec.Tunnel == nil {
					t.Fatalf("期望命中隧道 %s，实际没有隧道", tc.wantSlug)
				}
				if dec.Tunnel.Slug != tc.wantSlug {
					t.Fatalf("命中隧道 %s，期望 %s", dec.Tunnel.Slug, tc.wantSlug)
				}
			}
			if tc.wantReject != "" && dec.RejectMode != tc.wantReject {
				t.Fatalf("RejectMode = %q，期望 %q（原因：%s）", dec.RejectMode, tc.wantReject, dec.Reason)
			}
			if tc.wantClient != "" && dec.ClientAddr.String() != tc.wantClient {
				t.Fatalf("ClientAddr = %s，期望 %s", dec.ClientAddr, tc.wantClient)
			}
			if tc.fast && elapsed > 500*time.Millisecond {
				t.Fatalf("判别耗时 %v —— 首包已足够判别，绝不该再等（frp 的 10 秒病根）", elapsed)
			}
			t.Logf("判别耗时 %v，step=%s action=%s sni=%q", elapsed, dec.Step, dec.Action, dec.ServerName)
		})
	}

	if acmeHits != 0 {
		t.Errorf("Decide 不该有副作用，ACME 处理器被调用了 %d 次", acmeHits)
	}
}

// TestDiscriminatorShortFirstPacketDoesNotHang 单独钉住 frp 那个缺陷的修复。
//
// frp 对每条连接按全局最大需求字节数 io.ReadFull 且硬编码 10s 超时
// （golib/net/mux/mux.go:189-198），所以「首包只有 1 字节」= 建连慢 10 秒。
// 这里单步期限设成 5 秒，首包只有 1 个字节且之后**永不再发**，
// 判别仍然必须在毫秒级完成。
func TestDiscriminatorShortFirstPacketDoesNotHang(t *testing.T) {
	f := newDiscFixture(t, sessionMap{}, nil, nil)
	fallback := portTunnel("fallback", tunnel.TLSPassthrough, "192.168.1.20:9999")
	if err := f.reg.BindDefault(7000, fallback); err != nil {
		t.Fatal(err)
	}

	dec, elapsed := f.decide(t, []byte{0x05}, 7000)
	if dec.Action != ActionSplice || dec.Step != StepPortDefault {
		t.Fatalf("action=%s step=%s，期望 splice/port_default", dec.Action, dec.Step)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("1 字节首包判别耗时 %v，期望远小于 1 秒", elapsed)
	}
	t.Logf("1 字节首包判别耗时 %v（单步期限 5 秒）", elapsed)
}

// TestPassthroughSpliceReplaysClientHelloToBackend 是透传模式的关键端到端断言：
// 后端必须收到**逐字节相同**的 ClientHello。
//
// 少一个字节它就握不上手；而中继全程没有解密任何东西 —— 私钥在后端手里。
func TestPassthroughSpliceReplaysClientHelloToBackend(t *testing.T) {
	// 后端：把收到的字节全记下来。
	var (
		mu       sync.Mutex
		received bytes.Buffer
		gotAll   = make(chan struct{})
	)
	hello := clientHelloBytes(t, &tls.Config{
		ServerName: "pt.example.com", NextProtos: []string{"h2", "http/1.1"}})

	bln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bln.Close()
	go func() {
		c, err := bln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, len(hello))
		n, _ := io.ReadFull(c, buf)
		mu.Lock()
		received.Write(buf[:n])
		mu.Unlock()
		close(gotAll)
	}()

	agent := startFakeAgent(t, func(open proto.StreamOpen) (net.Conn, error) {
		return net.Dial("tcp", bln.Addr().String())
	})
	sessions := sessionMap{"agent-1": agent.session("agent-1")}
	f := newDiscFixture(t, sessions, nil, nil)

	pt := sharedTunnel("pt", tunnel.TLSPassthrough, tunnel.RouterTLSSNI,
		bln.Addr().String(), []string{"pt.example.com"}, nil)
	if err := f.reg.AddShared(443, pt); err != nil {
		t.Fatal(err)
	}

	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()
	go func() { _, _ = far.Write(hello) }()

	go f.disc.Handle(t.Context(),
		near, netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), 443))

	select {
	case <-gotAll:
	case <-time.After(5 * time.Second):
		t.Fatal("后端没在 5 秒内收到完整 ClientHello")
	}

	mu.Lock()
	defer mu.Unlock()
	if !bytes.Equal(received.Bytes(), hello) {
		t.Fatalf("后端收到 %d 字节，与原始 %d 字节不一致", received.Len(), len(hello))
	}
	t.Logf("后端逐字节收到 %d 字节 ClientHello，中继全程未解密", len(hello))

	// 真实源地址必须随 StreamOpen 过隧道（frp 在 UDP 路径上丢了这个信息）。
	select {
	case open := <-agent.opens:
		if open.TunnelID != pt.ID {
			t.Errorf("StreamOpen.TunnelID = %q，期望 %q", open.TunnelID, pt.ID)
		}
		if open.DstPort != 443 {
			t.Errorf("StreamOpen.DstPort = %d，期望 443", open.DstPort)
		}
	default:
		t.Error("假 agent 没记录到 StreamOpen")
	}
}

// TestRejectSendsRealTLSAlertOverRealConn 证明拒绝路径在**真实连接**上
// 发出的是 unrecognized_name 告警（spec §7.3 第 6 步），而不是裸关闭。
func TestRejectSendsRealTLSAlertOverRealConn(t *testing.T) {
	f := newDiscFixture(t, sessionMap{}, nil, nil)
	gw := sharedTunnel("gw", tunnel.TLSGateway, tunnel.RouterHTTP,
		"192.168.1.5:25808", []string{"gw.example.com"}, nil)
	if err := f.reg.AddShared(8443, gw); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// 端口用注册过的 8443，但 SNI 未注册 → 走拒绝。
		f.disc.Handle(t.Context(), c, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 8443))
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	c := tls.Client(conn, &tls.Config{ServerName: "unregistered.example.com"})
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	err = c.Handshake()
	if err == nil {
		t.Fatal("未注册的 SNI 竟然握手成功")
	}
	if !strings.Contains(err.Error(), "unrecognized name") {
		t.Fatalf("客户端错误 = %v，期望 unrecognized name（alert 112），裸关闭不合格", err)
	}
	t.Logf("客户端收到：%v", err)
}

// proxyV2Sample 造一个 PROXY protocol v2 头（TCP over IPv4，PROXY 命令）。
func proxyV2Sample(srcIP string, srcPort uint16) []byte {
	var b bytes.Buffer
	b.Write(proxyV2Magic)
	b.WriteByte(0x21) // ver 2 | cmd PROXY
	b.WriteByte(0x11) // TCP over IPv4
	b.Write([]byte{0x00, 12})

	src := netip.MustParseAddr(srcIP).As4()
	dst := netip.MustParseAddr("198.51.100.1").As4()
	b.Write(src[:])
	b.Write(dst[:])
	var ports [4]byte
	binary.BigEndian.PutUint16(ports[0:2], srcPort)
	binary.BigEndian.PutUint16(ports[2:4], 8080)
	b.Write(ports[:])
	return b.Bytes()
}
