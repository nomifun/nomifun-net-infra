//go:build e2e

// Package e2e 用真实的 QUIC 承载、真实的握手、真实的后端服务，
// 在 loopback 上跑通场景一与场景二。
//
// 单元测试能证明各个零件正确，但只有这里能证明**流量真的通了**。
// 需要 -tags e2e 才编译，跑 `make e2e`。
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/agent"
	"github.com/nomifun/nomifun-net-infra/internal/carrier"
	"github.com/nomifun/nomifun-net-infra/internal/policy"
	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/relay"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// ── 测试用的内存鉴权后端 ────────────────────────────────────────────────────

type memAuth struct {
	mu     sync.Mutex
	keys   map[string][]byte
	tokens map[string]bool // 令牌 → 是否已用
	seq    int
}

func newMemAuth() *memAuth {
	return &memAuth{keys: make(map[string][]byte), tokens: make(map[string]bool)}
}

func (a *memAuth) issueToken(tok string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tokens[tok] = false
}

func (a *memAuth) LookupKey(agentID string) ([]byte, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	k, ok := a.keys[agentID]
	return k, ok
}

func (a *memAuth) RedeemEnrolToken(token string, _ relay.AgentProfile) (string, []byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	used, exists := a.tokens[token]
	if !exists {
		return "", nil, errors.New("令牌不存在")
	}
	if used {
		// 一次性令牌必须只能用一次。
		return "", nil, errors.New("令牌已被使用")
	}
	a.tokens[token] = true

	a.seq++
	id := fmt.Sprintf("agent-%d", a.seq)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", nil, err
	}
	a.keys[id] = key
	return id, key, nil
}

// ── 测试夹具 ────────────────────────────────────────────────────────────────

// harness 是一套跑起来的中继 + agent。
type harness struct {
	t *testing.T

	auth     *memAuth
	sessions *relay.SessionManager
	tunnels  *agent.TunnelSet

	agentID string
	session *relay.Session

	// agentCarrier 是 agent 侧的承载句柄。
	//
	// UDP 路径需要它：数据报是**连接级**的，agent 侧的处理器要直接
	// 拿着承载去 ReceiveDatagram，而不是像流那样从 AcceptStream 里等。
	agentCarrier carrier.Carrier

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func selfSigned(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "e2e-relay"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"e2e-relay"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

// setup 拉起中继与 agent，完成入网握手，并启动 agent 的流处理循环。
// setup 起一套真实的中继 + agent。
//
// agentPolicy 可选：不传则用 policy.DefaultConfig()。需要它是因为
// 「拨号期策略否决」这条路要求 allow 段不含后端解析出的地址，
// 而默认配置放行整个回环段。
func setup(t *testing.T, agentPolicy ...policy.Config) *harness {
	t.Helper()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, cancel := context.WithCancel(context.Background())

	h := &harness{
		t:        t,
		auth:     newMemAuth(),
		sessions: relay.NewSessionManager(log),
		tunnels:  agent.NewTunnelSet(),
		cancel:   cancel,
	}
	t.Cleanup(func() {
		cancel()
		h.wg.Wait()
		h.sessions.CloseAll("测试结束")
	})

	cert, leaf := selfSigned(t)

	// ── 中继侧：监听 QUIC ──
	ln, err := carrier.ListenQUIC("127.0.0.1:0", carrier.QUICConfig{
		TLSConfig: carrier.ServerTLSConfig(cert),
		Rung:      carrier.RungQUIC,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	const enrolToken = "nf_enrol_e2e_token"
	h.auth.issueToken(enrolToken)

	guard := proto.NewReplayGuard(0, 0)
	relayAccepted := make(chan *relay.Session, 1)
	relayErr := make(chan error, 1)

	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		c, err := ln.Accept(ctx)
		if err != nil {
			relayErr <- err
			return
		}
		// 控制流是 agent 开的第一条流。
		st, err := c.AcceptStream(ctx)
		if err != nil {
			relayErr <- err
			return
		}
		binding, err := c.ChannelBinding()
		if err != nil {
			relayErr <- fmt.Errorf("中继侧取信道绑定材料失败：%w", err)
			return
		}
		out, err := relay.Handshake(st, binding, relay.HandshakeConfig{
			Auth:               h.auth,
			Guard:              guard,
			RelayVersion:       "e2e",
			MinProtocolVersion: 1,
			Log:                log,
		})
		if err != nil {
			relayErr <- fmt.Errorf("中继侧握手失败：%w", err)
			return
		}
		s := &relay.Session{
			AgentID:      out.AgentID,
			Carrier:      c,
			Capabilities: out.Capabilities,
			ConnectedAt:  time.Now(),
		}
		h.sessions.Add(s)
		relayAccepted <- s
	}()

	// ── agent 侧：拨号并握手 ──
	clientTLS, err := carrier.ClientTLSConfig("e2e-relay", nil, carrier.SPKIPin(leaf))
	if err != nil {
		t.Fatal(err)
	}
	dialCtx, dialCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dialCancel()

	ac, err := carrier.DialQUIC(dialCtx, ln.Addr().String(), carrier.QUICConfig{
		TLSConfig: clientTLS,
		Rung:      carrier.RungQUIC,
	})
	if err != nil {
		t.Fatalf("agent 拨号失败：%v", err)
	}
	t.Cleanup(func() { ac.CloseWithError(0, "测试结束") })

	ctrl, err := ac.OpenStream(dialCtx)
	if err != nil {
		t.Fatal(err)
	}

	agentBinding, err := ac.ChannelBinding()
	if err != nil {
		t.Fatalf("agent 侧取信道绑定材料失败：%v", err)
	}
	res, err := agent.Handshake(ctrl, agent.Credential{}, enrolToken, agentBinding,
		agent.Identity{Version: "e2e", Hostname: "e2e-host"})
	if err != nil {
		t.Fatalf("agent 握手失败：%v", err)
	}
	if res.IssuedKey == "" {
		t.Fatal("首次入网应当下发密钥")
	}
	h.agentID = res.AgentID

	select {
	case err := <-relayErr:
		t.Fatalf("中继侧出错：%v", err)
	case s := <-relayAccepted:
		h.session = s
	case <-time.After(10 * time.Second):
		t.Fatal("中继侧握手超时")
	}

	// ── agent 侧：启动流处理循环 ──
	polCfg := policy.DefaultConfig()
	if len(agentPolicy) > 0 {
		polCfg = agentPolicy[0]
	}
	pol, err := policy.New(polCfg)
	if err != nil {
		t.Fatal(err)
	}
	handler := &agent.StreamHandler{Tunnels: h.tunnels, Policy: pol, Log: log}

	h.agentCarrier = ac

	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		for {
			st, err := ac.AcceptStream(ctx)
			if err != nil {
				return
			}
			h.wg.Add(1)
			go func() {
				defer h.wg.Done()
				if err := handler.Serve(ctx, st); err != nil && ctx.Err() == nil {
					log.Warn("处理隧道流失败", "err", err)
				}
			}()
		}
	}()

	return h
}

// publish 把一条隧道下发给 agent（模拟控制面的 TunnelSet 推送）。
// ── relay.TunnelLookup ──────────────────────────────────────────────────────
//
// UDP 入口每包都要现取隧道定义与会话，所以夹具要实现这个接口。
// 直接复用 agent 侧的 TunnelSet 作为隧道来源：这个用例里两侧看到的
// 是同一份集合，正好也验证了「两侧的短标识必须一致」。

func (h *harness) TunnelByID(id string) (*tunnel.Tunnel, bool) {
	return h.tunnels.Get(id)
}

func (h *harness) TunnelByListenPort(uint16) (*tunnel.Tunnel, bool) {
	return nil, false
}

func (h *harness) SessionFor(agentID string) (*relay.Session, bool) {
	if agentID == "" {
		return nil, false
	}
	s, ok := h.sessions.Get(agentID)
	if !ok || !s.Alive() {
		return nil, false
	}
	return s, true
}

func (h *harness) publish(tn *tunnel.Tunnel) {
	h.t.Helper()
	tn.Complete()
	if err := tn.Validate(); err != nil {
		h.t.Fatalf("隧道定义非法：%v", err)
	}
	rejected := h.tunnels.Reconcile([]*tunnel.Tunnel{tn}, mustPolicy(h.t))
	if len(rejected) > 0 {
		h.t.Fatalf("隧道被 agent 策略否决：%v", rejected)
	}
}

func mustPolicy(t *testing.T) *policy.Policy {
	t.Helper()
	p, err := policy.New(policy.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// dialThroughTunnel 模拟「中继收到一个用户连接」：主动向 agent 开流。
//
// 真实的中继会在入口端口 Accept 之后做这件事；这里直接调用同一个函数，
// 以便测试聚焦于数据面是否通。
func (h *harness) dialThroughTunnel(t *testing.T, tunnelID string, src string) carrier.Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ap := netip.MustParseAddrPort(src)
	st, err := relay.OpenTunnelStream(ctx, h.session, proto.StreamOpen{
		TunnelID: tunnelID,
		SrcAddr:  ap.Addr().String(),
		SrcPort:  ap.Port(),
		DstAddr:  "127.0.0.1",
		DstPort:  8443,
	})
	if err != nil {
		t.Fatalf("中继开流失败：%v", err)
	}

	// 读掉 agent 的 StreamOK，之后流上就是纯业务字节了。
	fr, err := proto.NewReader(st).ReadFrame()
	if err != nil {
		st.Close()
		t.Fatalf("读 StreamOK 失败：%v", err)
	}
	if fr.Header.Type == proto.TypeError {
		var e proto.Error
		_ = proto.Decode(fr, &e)
		st.Close()
		t.Fatalf("agent 拒绝了这条流：%s: %s", e.Code, e.Message)
	}
	if fr.Header.Type != proto.TypeStreamOK {
		st.Close()
		t.Fatalf("期望 StreamOK，收到 %s", fr.Header.Type)
	}
	return st
}

// ── 场景一：HTTP ────────────────────────────────────────────────────────────

// TestS1_HTTPThroughTunnel 证明 HTTP 请求真的穿过了隧道并拿到了响应。
func TestS1_HTTPThroughTunnel(t *testing.T) {
	h := setup(t)

	// 后端：一个真实的 HTTP 服务，扮演家里的桌面服务器。
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"msg":"来自家里的桌面服务器","host":%q}`, r.Host)
	})
	backend := &http.Server{Handler: mux}
	bln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go backend.Serve(bln)

	h.publish(&tunnel.Tunnel{
		ID:      "t-http",
		Slug:    "home-api",
		AgentID: h.agentID,
		Kind:    tunnel.KindService,
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: bln.Addr().String()},
	})

	// 用一个 http.Client，其 DialContext 走隧道 —— 这样走的是真实 HTTP 栈，
	// 而不是手搓一个看起来像 HTTP 的字符串。
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return streamConn{h.dialThroughTunnel(t, "t-http", "203.0.113.9:50000")}, nil
			},
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("http://tunnel.invalid/api/hello")
	if err != nil {
		t.Fatalf("经隧道发 HTTP 请求失败：%v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "来自家里的桌面服务器") {
		t.Fatalf("响应体不对：%s", body)
	}
	t.Logf("经隧道拿到响应：%s", body)
}

// TestS1_WebSocketThroughTunnel 证明 WebSocket 升级与双向消息真的能穿透。
//
// 场景一明确要求 WebSocket。这里用真实的 HTTP Upgrade 握手 + Hijack，
// 而不是假设「TCP 通了 WS 就通」。
func TestS1_WebSocketThroughTunnel(t *testing.T) {
	h := setup(t)

	// 后端：接受 Upgrade 然后回显每一行。
	bln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bln.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				http.Error(w, "需要 Upgrade", http.StatusBadRequest)
				return
			}
			conn, buf, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
				"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			_ = buf.Flush()

			// 升级后按行回显，前缀标明来自后端。
			for {
				line, err := buf.ReadString('\n')
				if err != nil {
					return
				}
				if _, err := buf.WriteString("echo:" + line); err != nil {
					return
				}
				if err := buf.Flush(); err != nil {
					return
				}
			}
		}),
	}
	go srv.Serve(bln)

	h.publish(&tunnel.Tunnel{
		ID:      "t-ws",
		Slug:    "home-ws",
		AgentID: h.agentID,
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: bln.Addr().String()},
	})

	st := h.dialThroughTunnel(t, "t-ws", "203.0.113.9:50001")
	defer st.Close()

	// 手写 Upgrade 请求，这样能确认 101 与升级后的字节都原样穿过。
	req := "GET /ws HTTP/1.1\r\nHost: tunnel.invalid\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	if _, err := st.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(st)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("读状态行失败：%v", err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("状态行 = %q，期望含 101", statusLine)
	}
	// 吃掉响应头直到空行。
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	// 升级完成，验证双向消息。
	for i := range 3 {
		msg := fmt.Sprintf("消息%d\n", i)
		if _, err := st.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		got, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("读回显失败：%v", err)
		}
		if want := "echo:" + msg; got != want {
			t.Fatalf("回显 = %q，期望 %q", got, want)
		}
	}
	t.Log("WebSocket 升级与双向消息均穿透成功")
}

// ── 场景二：机器人只填 IP+端口 ───────────────────────────────────────────────

// TestS2_BarePortToRemoteTarget 模拟场景二：一个只会连裸 TCP 端口的设备
// （ESP32 机器人）经中继抵达远端桌面服务。
//
// 关键点：设备侧**零客户端软件、零协议感知**，它只是连一个 TCP 端口。
func TestS2_BarePortToRemoteTarget(t *testing.T) {
	h := setup(t)

	// 远端桌面服务：一个极简的行协议服务，模拟机器人要访问的接口。
	bln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bln.Close()
	go func() {
		for {
			c, err := bln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimSpace(line) == "STATUS" {
						_, _ = c.Write([]byte("OK 桌面服务在线\n"))
						continue
					}
					_, _ = c.Write([]byte("ERR 未知指令\n"))
				}
			}()
		}
	}()

	h.publish(&tunnel.Tunnel{
		ID:       "t-robot",
		Slug:     "robot-hmi",
		AgentID:  h.agentID,
		Kind:     tunnel.KindReverse, // 场景二
		Exposure: tunnel.ExposurePort,
		Backend:  tunnel.Backend{Kind: tunnel.BackendAddr, Addr: bln.Addr().String()},
	})

	// 中继侧起一个真实的入口监听器，机器人连它。
	// 这才是场景二的完整形态：机器人配置里只有 IP+端口。
	entry, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer entry.Close()

	go func() {
		for {
			userConn, err := entry.Accept()
			if err != nil {
				return
			}
			go func() {
				defer userConn.Close()
				st := h.dialThroughTunnel(t, "t-robot", "203.0.113.9:50002")
				defer st.Close()

				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); io.Copy(st, userConn) }()
				go func() { defer wg.Done(); io.Copy(userConn, st) }()
				wg.Wait()
			}()
		}
	}()

	// 机器人：只知道中继的 IP:端口，什么协议都不懂。
	robot, err := net.DialTimeout("tcp", entry.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("机器人连中继入口失败：%v", err)
	}
	defer robot.Close()

	if _, err := robot.Write([]byte("STATUS\n")); err != nil {
		t.Fatal(err)
	}
	robot.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply, err := bufio.NewReader(robot).ReadString('\n')
	if err != nil {
		t.Fatalf("机器人读响应失败：%v", err)
	}
	if !strings.Contains(reply, "OK 桌面服务在线") {
		t.Fatalf("响应 = %q，期望含「OK 桌面服务在线」", reply)
	}
	t.Logf("机器人只填 IP+端口即抵达远端桌面：%s", strings.TrimSpace(reply))
}

// ── 安全：本地策略在数据面真的生效 ──────────────────────────────────────────

// TestAgentPolicyBlocksMetadataTargetAtDataPlane 验证 SSRF 防线在**数据面**生效，
// 而不只是在校验期。
//
// 这里绕过 publish 的预检，直接把一条指向云元数据的隧道塞进 agent，
// 然后确认拨号仍然被拒。
func TestAgentPolicyBlocksMetadataTargetAtDataPlane(t *testing.T) {
	h := setup(t)

	metadata := &tunnel.Tunnel{
		ID:      "t-ssrf",
		Slug:    "ssrf-attempt",
		AgentID: h.agentID,
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "169.254.169.254:80"},
	}
	metadata.Complete()

	// Reconcile 应当直接否决它，并给出原因。
	rejected := h.tunnels.Reconcile([]*tunnel.Tunnel{metadata}, mustPolicy(t))
	reason, ok := rejected["t-ssrf"]
	if !ok {
		t.Fatal("指向云元数据的隧道必须被 agent 本地策略否决")
	}
	if !strings.Contains(reason, "元数据") {
		t.Errorf("拒绝原因应当说明是元数据地址，实际：%s", reason)
	}
	t.Logf("agent 否决了该隧道，原因：%s", reason)

	// 且它确实没有进入可服务集合 —— 中继开流会拿到 unknown_tunnel。
	if _, present := h.tunnels.Get("t-ssrf"); present {
		t.Fatal("被否决的隧道不该出现在可服务集合里")
	}
}

func TestAgentDeniesTargetAtDialTimeWithACodeDistinctFromInternal(t *testing.T) {
	// 配置期预检只判 IP 字面量，主机名一律放过、留给拨号时判定 ——
	// 这正是 DNS 重绑定防护：预检时解析到的地址可能与拨号时不同，
	// 所以真正的裁决必须发生在每次拨号。
	//
	// 于是「主机名后端 + 拨号期否决」是一条真实可达的路径，
	// 而它必须给出与「拨号失败」**不同**的错误码：策略否决永不可重试，
	// 控制台该说的是「改策略或改目标」，而不是「内部错误，请重试」。
	// 两者混用还会毁掉错误码看板 —— internal 那一格本该是「原因未知」。
	h := setup(t, policy.Config{Allow: []netip.Prefix{
		netip.MustParsePrefix("10.99.0.0/16"),
	}})

	// localhost 解析到回环，而上面的 allow 段不含回环。
	tn := &tunnel.Tunnel{
		ID:      "t-dialtime-deny",
		Slug:    "dialtime-deny",
		AgentID: h.agentID,
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "localhost:9"},
	}
	tn.Complete()

	// 预检必须放过它，否则就测不到拨号期那条路了。
	if rejected := h.tunnels.Reconcile([]*tunnel.Tunnel{tn}, mustPolicy(t)); len(rejected) > 0 {
		t.Fatalf("主机名后端应当通过配置期预检（DNS 可变），却被拒：%v", rejected)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ap := netip.MustParseAddrPort("203.0.113.7:1234")
	st, err := relay.OpenTunnelStream(ctx, h.session, proto.StreamOpen{
		TunnelID: tn.ID,
		SrcAddr:  ap.Addr().String(),
		SrcPort:  ap.Port(),
		DstAddr:  "127.0.0.1",
		DstPort:  8443,
	})
	if err != nil {
		t.Fatalf("中继开流失败：%v", err)
	}
	defer st.Close()

	_, _, err = relay.AwaitStreamOK(st, 10*time.Second)
	var rej *relay.StreamRejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("应当拿到结构化拒绝，得到 %#v", err)
	}
	if rej.Code != proto.ErrCodeTargetDenied {
		t.Fatalf("策略否决的错误码应为 %q，实际 %q", proto.ErrCodeTargetDenied, rej.Code)
	}
	if rej.Retryable {
		t.Fatal("策略否决不可重试 —— 让用户重试一个永远不会成功的操作是误导")
	}
	if !strings.Contains(rej.Message, "策略") {
		t.Errorf("拒绝原因应当点明是策略否决，实际：%s", rej.Message)
	}
	t.Logf("拨号期否决：code=%s retryable=%v msg=%s", rej.Code, rej.Retryable, rej.Message)
}

// TestS1_UDPMediaThroughTunnel 验证场景一要求的 UDP 真的通了。
//
// 需求原文：「必须支持 HTTP、WebSocket 和 UDP 以便音视频通话」。前两条已由
// 上面两个用例覆盖，这一条走的是完全不同的代码路径 —— **QUIC 不可靠数据报**
// （RFC 9221），不经过流、不经过 StreamOpen 握手。
//
// 这个用例必须在真实 QUIC 承载上跑：数据报路径上有三件事只有真承载才能验证 ——
// 两端是否都协商出了 EnableDatagrams、载荷上限的反应式学习、
// 以及「一条连接一条数据报流」这个前提（正是它逼出了按短标识解复用的设计）。
func TestS1_UDPMediaThroughTunnel(t *testing.T) {
	h := setup(t)

	// 家里的「媒体服务」：把收到的包原样回送。
	backend := udpEchoServer(t)

	// 中继侧：UDP 入口。短标识由控制面分配，两侧必须用同一个值。
	const shortID = 41
	tn := &tunnel.Tunnel{
		ID:       "t-udp",
		Slug:     "udp-media",
		AgentID:  h.agentID,
		ShortID:  shortID,
		Kind:     tunnel.KindService,
		Exposure: tunnel.ExposurePort,
		L4:       tunnel.L4UDP,
		Backend:  tunnel.Backend{Kind: tunnel.BackendAddr, Addr: backend.String()},
	}
	h.publish(tn)

	entry, err := relay.NewDatagramEntry("127.0.0.1:0", tn, h, relay.DatagramOptions{})
	if err != nil {
		t.Fatalf("起 UDP 入口失败：%v", err)
	}
	defer entry.Close()

	router := relay.NewDatagramRouter(nil)
	router.Register(entry)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = entry.Serve(ctx) }()
	go relay.RunDatagramLoop(ctx, h.session, router, nil)

	// agent 侧：数据报处理器。
	pol, err := policy.New(policy.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	udp := &agent.UDPHandler{Tunnels: h.tunnels, Policy: pol}
	go func() { _ = udp.Serve(ctx, h.agentCarrier) }()

	// 手机侧：往中继的入口端口发包，期待原样收回。
	client, err := net.Dial("udp", entry.Addr().String())
	if err != nil {
		t.Fatalf("客户端拨号失败：%v", err)
	}
	defer client.Close()

	const want = "一帧 Opus 音频"
	deadline := time.Now().Add(10 * time.Second)
	var got string
	for time.Now().Before(deadline) && got == "" {
		// UDP 不可靠，且承载刚建立时可能还在协商 —— 重发直到收到或超时。
		// 这不是掩盖问题：不可靠传输上「第一包必达」本就不是可断言的性质。
		if _, err := client.Write([]byte(want)); err != nil {
			t.Fatalf("客户端发包失败：%v", err)
		}
		_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 2048)
		n, err := client.Read(buf)
		if err == nil {
			got = string(buf[:n])
		}
	}

	if got != want {
		t.Fatalf("UDP 往返失败。收到 %q，期望 %q\n"+
			"中继入口：上行 %d 包 / 下行 %d 包，丢弃：无会话 %d 不支持数据报 %d 未知流 %d\n"+
			"agent：下行 %d 包 / 上行 %d 包，丢弃：策略 %d 拨号 %d 未知隧道 %d 畸形 %d",
			got, want,
			entry.Stats().PacketsIn.Load(), entry.Stats().PacketsOut.Load(),
			entry.Stats().NoSession.Load(), entry.Stats().NoDatagram.Load(),
			entry.Stats().UnknownFlow.Load(),
			udp.Stats().PacketsOut.Load(), udp.Stats().PacketsIn.Load(),
			udp.Stats().Denied.Load(), udp.Stats().DialFailed.Load(),
			udp.Stats().UnknownTunnel.Load(), udp.Stats().Malformed.Load())
	}
	t.Logf("UDP 经隧道往返成功：%q（真实 QUIC 不可靠数据报）", got)

	// 且真的走了数据报而不是悄悄退化成流。
	if !h.session.SupportsDatagrams() {
		t.Error("会话应当报告支持数据报")
	}
	if entry.Stats().PacketsOut.Load() == 0 {
		t.Error("回向计数为 0 —— 包不是经这条路回来的")
	}
}

// TestS1_LargeUDPDatagramSurvivesFragmentation 验证超过承载数据报上限的
// 大报文能经分片+重组完整往返。
//
// 场景：IoT 设备发一个几 KiB 的报文（固件块、大 DNS 应答、应用自有协议）。
// QUIC 数据报**必须装进单个 QUIC 包**，所以超过约 1150 字节的载荷发不出去。
// 不分片就是静默数据丢失 —— 设备侧表现为「功能时好时坏，跟包长有关」。
//
// 这个用例必须在真实 QUIC 上跑：上限是**反应式学到**的
// （quic-go 不提供查询接口，只能从 DatagramTooLargeError 得知），
// 内存承载里那个写死的常量证明不了真实路径。
func TestS1_LargeUDPDatagramSurvivesFragmentation(t *testing.T) {
	h := setup(t)
	backend := udpEchoServer(t)

	const shortID = 43
	tn := &tunnel.Tunnel{
		ID:       "t-udp-big",
		Slug:     "udp-bulk",
		AgentID:  h.agentID,
		ShortID:  shortID,
		Kind:     tunnel.KindService,
		Exposure: tunnel.ExposurePort,
		L4:       tunnel.L4UDP,
		Backend:  tunnel.Backend{Kind: tunnel.BackendAddr, Addr: backend.String()},
		// 刻意**不**设 RealtimeDatagram：批量隧道要分片。
		// 默认就是分片，因为默认要错向安全的一侧。
	}
	h.publish(tn)

	entry, err := relay.NewDatagramEntry("127.0.0.1:0", tn, h, relay.DatagramOptions{})
	if err != nil {
		t.Fatalf("起 UDP 入口失败：%v", err)
	}
	defer entry.Close()

	router := relay.NewDatagramRouter(nil)
	router.Register(entry)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = entry.Serve(ctx) }()
	go relay.RunDatagramLoop(ctx, h.session, router, nil)

	pol, err := policy.New(policy.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	udp := &agent.UDPHandler{Tunnels: h.tunnels, Policy: pol}
	go func() { _ = udp.Serve(ctx, h.agentCarrier) }()

	client, err := net.Dial("udp", entry.Addr().String())
	if err != nil {
		t.Fatalf("客户端拨号失败：%v", err)
	}
	defer client.Close()

	// 4 KiB —— 稳稳超过任何真实路径的单包上限。
	// 用非重复图案：全同字节的话，分片拼错位置也看不出来。
	want := make([]byte, 4096)
	for i := range want {
		want[i] = byte(i % 251)
	}

	// 第一包会撞上「上限未知」——carrier 要靠 DatagramTooLargeError 才学到
	// 上限，所以第一次很可能整包发出去然后被拒。这是设计如此，不是缺陷：
	// 反应式学习必须有第一次失败。所以重发直到成功或超时。
	deadline := time.Now().Add(15 * time.Second)
	var got []byte
	for time.Now().Before(deadline) && got == nil {
		if _, err := client.Write(want); err != nil {
			t.Fatalf("客户端发包失败：%v", err)
		}
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 65535)
		n, err := client.Read(buf)
		if err == nil {
			got = buf[:n]
		}
	}

	if got == nil {
		rs := udp.ReassemblyStats()
		ss := h.session.DatagramSendStats()
		t.Fatalf("大报文没能往返。\n"+
			"中继入口：上行 %d 包 / 下行 %d 包\n"+
			"中继发送器：Sent=%d 分片=%d 超限=%d 队列满=%d\n"+
			"agent 重组：分片=%d 完成=%d 超时=%d 表满=%d 字节满=%d 重叠=%d\n"+
			"agent 交付：%d 包，重组丢弃 %d",
			entry.Stats().PacketsIn.Load(), entry.Stats().PacketsOut.Load(),
			ss.Sent.Load(), ss.Fragmented.Load(), ss.TooLarge.Load(), ss.QueueFull.Load(),
			rs.Fragments.Load(), rs.Completed.Load(), rs.TimedOut.Load(),
			rs.TableFull.Load(), rs.BytesFull.Load(), rs.Overlapping.Load(),
			udp.Stats().PacketsOut.Load(), udp.Stats().ReasmDropped.Load())
	}
	if len(got) != len(want) || !bytes.Equal(got, want) {
		t.Fatalf("往返后内容不符：收到 %d 字节，期望 %d", len(got), len(want))
	}

	// 必须真的走了分片，否则这个用例什么都没证明
	//（比如上限恰好比 4096 大的话）。
	if n := h.session.DatagramSendStats().Fragmented.Load(); n == 0 {
		t.Error("中继侧应当分片过 —— 否则本用例没有覆盖分片路径")
	}
	if n := udp.ReassemblyStats().Completed.Load(); n == 0 {
		t.Error("agent 侧应当重组过")
	}
	t.Logf("4 KiB 报文经分片+重组往返成功（中继分片 %d 次，agent 重组 %d 次，"+
		"当前学到的数据报上限 %d 字节）",
		h.session.DatagramSendStats().Fragmented.Load(),
		udp.ReassemblyStats().Completed.Load(),
		h.agentCarrier.MaxDatagramPayload())
}

// udpEchoServer 起一个原样回送的 UDP 服务，充当家里的媒体服务。
func udpEchoServer(t *testing.T) netip.AddrPort {
	t.Helper()

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("起 UDP 回显服务失败：%v", err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		// 按 UDP 载荷理论上限开缓冲，不按 MTU 猜 ——
		// 截断会让「重组对了但内容少了」看起来像重组缺陷。
		buf := make([]byte, 65535)
		for {
			n, src, err := pc.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDPAddrPort(buf[:n], src)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

// TestReplayedHandshakeIsRejected 验证重放防护在真实握手路径上生效。
func TestReplayedHandshakeIsRejected(t *testing.T) {
	auth := newMemAuth()
	guard := proto.NewReplayGuard(0, 0)

	// 先造一个已注册的 agent。
	const tok = "tok"
	auth.issueToken(tok)
	agentID, key, err := auth.RedeemEnrolToken(tok, relay.AgentProfile{})
	if err != nil {
		t.Fatal(err)
	}

	// 构造一次合法握手证明。
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	p := &proto.Proof{UnixMilli: time.Now().UnixMilli(), Nonce: hex.EncodeToString(nonce)}
	p.Sign(key, agent.ProtocolVersion, proto.ALPN, nil)

	hello := proto.Hello{
		ProtocolVersion: agent.ProtocolVersion,
		AgentID:         agentID,
		Auth:            p,
		Capabilities:    proto.AgentCapabilities(),
	}

	run := func() (*relay.HandshakeOutcome, error) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		go func() {
			w := proto.NewWriter(c1)
			_ = w.WriteMessage(proto.TypeHello, 1, 0, hello)
			// 读掉响应，避免对端写阻塞。
			_, _ = proto.NewReader(c1).ReadFrame()
		}()

		return relay.Handshake(pipeStream{c2}, nil, relay.HandshakeConfig{
			Auth:               auth,
			Guard:              guard,
			RelayVersion:       "e2e",
			MinProtocolVersion: 1,
		})
	}

	if out, err := run(); err != nil {
		t.Fatalf("首次握手应当成功：%v（outcome=%s）", err, out.Outcome)
	}

	out, err := run()
	if err == nil {
		t.Fatal("同一 nonce 的第二次握手必须被拒 —— 这正是 frp 缺失的那一层")
	}
	if out.Outcome != relay.OutcomeReplay {
		t.Errorf("outcome = %q，期望 %q", out.Outcome, relay.OutcomeReplay)
	}
	t.Logf("重放被拒，outcome=%s", out.Outcome)
}

// ── 适配器 ──────────────────────────────────────────────────────────────────

// streamConn 把 carrier.Stream 适配成 net.Conn，供 http.Transport 使用。
type streamConn struct{ carrier.Stream }

func (streamConn) LocalAddr() net.Addr  { return fakeAddr{} }
func (streamConn) RemoteAddr() net.Addr { return fakeAddr{} }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "nomirelay" }
func (fakeAddr) String() string  { return "tunnel" }

// pipeStream 把 net.Conn 适配成 carrier.Stream，供不需要真实 QUIC 的测试使用。
type pipeStream struct{ net.Conn }
