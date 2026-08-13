package gateway

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// TestReadProxyHeader 表驱动覆盖 PROXY protocol v1/v2 的解析。
//
// 自己解析而不引依赖：go.mod 里没有 proxyproto 库，而这段协议只有两种形态、
// 上限 107 字节，引一棵依赖树的代价远大于收益。
func TestReadProxyHeader(t *testing.T) {
	cases := []struct {
		name      string
		payload   []byte
		wantSrc   string // "" 表示不带可用地址
		wantLen   int
		wantNil   bool // 期望「这条连接上没有 PROXY 头」
		wantError bool
	}{
		{
			name:    "v1 TCP4",
			payload: []byte("PROXY TCP4 203.0.113.9 198.51.100.1 51234 443\r\n剩余业务数据"),
			wantSrc: "203.0.113.9:51234",
			wantLen: len("PROXY TCP4 203.0.113.9 198.51.100.1 51234 443\r\n"),
		},
		{
			name:    "v1 TCP6",
			payload: []byte("PROXY TCP6 2001:db8::1 2001:db8::2 51234 443\r\nX"),
			wantSrc: "[2001:db8::1]:51234",
			wantLen: len("PROXY TCP6 2001:db8::1 2001:db8::2 51234 443\r\n"),
		},
		{
			name: "v1 UNKNOWN 消费掉头但不编造来源",
			// 前置代理自己也不知道来源时，我们必须保持「不知道」，
			// 绝不能填一个看起来合理的地址 —— 那会污染审计与白名单判断。
			payload: []byte("PROXY UNKNOWN\r\nX"),
			wantSrc: "",
			wantLen: len("PROXY UNKNOWN\r\n"),
		},
		{
			name:      "v1 地址非法必须报错而不是当作没有头",
			payload:   []byte("PROXY TCP4 不是IP 198.51.100.1 51234 443\r\n"),
			wantError: true,
		},
		{
			name:      "v1 字段数不对",
			payload:   []byte("PROXY TCP4 203.0.113.9 51234\r\n"),
			wantError: true,
		},
		{
			name:      "v1 地址族与声明不符",
			payload:   []byte("PROXY TCP4 2001:db8::1 2001:db8::2 51234 443\r\n"),
			wantError: true,
		},
		{
			name:    "v2 TCP over IPv4",
			payload: append(proxyV2Sample("203.0.113.77", 40000), []byte("X")...),
			wantSrc: "203.0.113.77:40000",
			wantLen: proxyV2FixedLen + 12,
		},
		{
			name:    "v2 LOCAL 命令只消费头",
			payload: proxyV2Local(),
			wantSrc: "",
			wantLen: proxyV2FixedLen,
		},
		{
			name:    "明文 HTTP 请求不是 PROXY 头",
			payload: []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
			wantNil: true,
		},
		{
			name: "POST 请求在第二个字节就被否决",
			// 与 "PROXY " 共享首字节 'P'，必须逐字节确认而不是一口气要 6 字节。
			payload: []byte("POST /api HTTP/1.1\r\n\r\n"),
			wantNil: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			near, far := net.Pipe()
			defer near.Close()
			defer far.Close()
			go func() { _, _ = far.Write(tc.payload) }()

			pc := NewPeekConn(near)
			h, err := readProxyHeader(pc, time.Second)

			switch {
			case tc.wantError:
				if !errors.Is(err, ErrBadProxyHeader) {
					t.Fatalf("err = %v，期望 ErrBadProxyHeader —— 可信监听器上解析失败必须拒连", err)
				}
				return
			case err != nil:
				t.Fatalf("解析失败：%v", err)
			}

			if tc.wantNil {
				if h != nil {
					t.Fatalf("不该识别出 PROXY 头，实际 %+v", h)
				}
				return
			}
			if h == nil {
				t.Fatal("应当识别出 PROXY 头")
			}
			if h.Len != tc.wantLen {
				t.Errorf("头长度 = %d，期望 %d", h.Len, tc.wantLen)
			}
			got := ""
			if h.Src.IsValid() {
				got = h.Src.String()
			}
			if got != tc.wantSrc {
				t.Errorf("Src = %q，期望 %q", got, tc.wantSrc)
			}
		})
	}
}

// TestProxyHeaderDetectionBailsOnSecondByte 证明「与 PROXY 共享首字节」的协议
// 在第 2 个字节就被否决，不会为了凑够 6 字节签名而白等一整步。
func TestProxyHeaderDetectionBailsOnSecondByte(t *testing.T) {
	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()

	// 只发 "PO"，之后什么都不发。
	go func() { _, _ = far.Write([]byte("PO")) }()

	pc := NewPeekConn(near)
	start := time.Now()
	h, err := readProxyHeader(pc, 5*time.Second)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("不该报错：%v", err)
	}
	if h != nil {
		t.Fatalf("不该识别出 PROXY 头：%+v", h)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("否决耗时 %v —— 应当在第 2 个字节就返回", elapsed)
	}
}

// TestDiscriminatorEnforcesSourceCIDROnSharedPort 证明共享端口上隧道的
// 源 IP 白名单**照样生效**。
//
// 这道闸在 relay.EntryListener 里是 accept 之后立刻查（那里端口即隧道），
// 而共享端口上「属于哪条隧道」是判别之后才知道的，所以只能晚一步查 ——
// 但绝不能不查。
func TestDiscriminatorEnforcesSourceCIDROnSharedPort(t *testing.T) {
	dialed := make(chan struct{}, 1)
	agent := startFakeAgent(t, func(proto.StreamOpen) (net.Conn, error) {
		dialed <- struct{}{}
		a, b := net.Pipe()
		go io.Copy(io.Discard, b)
		return a, nil
	})
	f := newDiscFixture(t, sessionMap{"agent-1": agent.session("agent-1")}, nil, nil)

	robot := portTunnel("robot", tunnel.TLSPassthrough, "192.168.1.5:8080")
	// 只放行一个与测试客户端无关的网段。
	robot.Policy = &tunnel.Policy{AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16")}}
	if err := f.reg.BindDedicated(9100, robot); err != nil {
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
		f.disc.Handle(t.Context(), c, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 9100))
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("STATUS\n"))

	// 连接必须被断开，且**绝不能**为它向 agent 开流。
	// 断开表现为 EOF 或 RST（我们关连接时缓冲里还有对方未被读走的字节），
	// 两者都合格 —— 关键是一个字节的响应都不该有。
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 32)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("连接应当被断开，却读到 %d 字节：%q", n, buf[:n])
	}
	select {
	case <-dialed:
		t.Fatal("白名单外的来源竟然触发了向 agent 开流")
	default:
	}
	if n := f.disc.Stats().DeniedCIDR.Load(); n != 1 {
		t.Fatalf("DeniedCIDR 计数 = %d，期望 1", n)
	}
}

// proxyV2Local 造一个 LOCAL 命令的 v2 头（前置代理的健康检查用）。
func proxyV2Local() []byte {
	var b bytes.Buffer
	b.Write(proxyV2Magic)
	b.WriteByte(0x20) // ver 2 | cmd LOCAL
	b.WriteByte(0x00) // AF_UNSPEC
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], 0)
	b.Write(l[:])
	return b.Bytes()
}
