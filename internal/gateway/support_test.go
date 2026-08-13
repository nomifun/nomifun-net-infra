package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/carrier"
	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/relay"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// ── 内存承载：一条流一条 net.Pipe ───────────────────────────────────────────

// pipeCarrier 是 carrier.Carrier 的内存实现：OpenStream 造一对 net.Pipe，
// 近端给中继，远端塞进 accept 队列给「假 agent」。
//
// 用它而不是真 QUIC，是为了让本包的测试只测判别与七层逻辑；
// 真承载上的端到端在 test/e2e 里跑。
type pipeCarrier struct {
	accept chan net.Conn
	ctx    context.Context
	cancel context.CancelFunc
}

func newPipeCarrier() *pipeCarrier {
	ctx, cancel := context.WithCancel(context.Background())
	return &pipeCarrier{accept: make(chan net.Conn, 16), ctx: ctx, cancel: cancel}
}

func (c *pipeCarrier) OpenStream(ctx context.Context) (carrier.Stream, error) {
	near, far := net.Pipe()
	select {
	case c.accept <- far:
		return near, nil
	case <-ctx.Done():
		near.Close()
		far.Close()
		return nil, ctx.Err()
	case <-c.ctx.Done():
		near.Close()
		far.Close()
		return nil, carrier.ErrClosed
	}
}

func (c *pipeCarrier) AcceptStream(ctx context.Context) (carrier.Stream, error) {
	select {
	case s := <-c.accept:
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, carrier.ErrClosed
	}
}

func (c *pipeCarrier) SendDatagram([]byte) error { return carrier.ErrDatagramUnsupported }
func (c *pipeCarrier) ReceiveDatagram(context.Context) ([]byte, error) {
	return nil, carrier.ErrDatagramUnsupported
}
func (c *pipeCarrier) SupportsDatagrams() bool { return false }
func (c *pipeCarrier) MaxDatagramPayload() int { return 0 }
func (c *pipeCarrier) Rung() carrier.Rung      { return carrier.RungQUIC }

// ChannelBinding 返回空材料：这个假承载没有 TLS。
// 两端在同一条连接上都拿到空值，所以 MAC 仍然一致。
func (c *pipeCarrier) ChannelBinding() ([]byte, error) { return nil, nil }
func (c *pipeCarrier) Context() context.Context        { return c.ctx }
func (c *pipeCarrier) RTT() time.Duration              { return 0 }
func (c *pipeCarrier) LocalAddr() net.Addr             { return tunnelAddr{} }
func (c *pipeCarrier) RemoteAddr() net.Addr            { return tunnelAddr{} }
func (c *pipeCarrier) CloseWithError(uint64, string) error {
	c.cancel()
	return nil
}

// ── 假 agent ────────────────────────────────────────────────────────────────

// fakeAgent 扮演隧道另一端：读 StreamOpen、拨后端、回 StreamOK，然后双向搬字节。
//
// 这一段刻意与 internal/agent 的真实实现同形（读首帧 → 拨号 → 确认 → 拷贝），
// 这样测试覆盖的是真实的开流握手，而不是一个「假设已经通了」的桩。
type fakeAgent struct {
	car   *pipeCarrier
	opens chan proto.StreamOpen
}

// startFakeAgent 起一个假 agent。dial 返回 nil error 才回 StreamOK。
func startFakeAgent(t *testing.T, dial func(proto.StreamOpen) (net.Conn, error)) *fakeAgent {
	t.Helper()

	a := &fakeAgent{car: newPipeCarrier(), opens: make(chan proto.StreamOpen, 16)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = a.car.CloseWithError(0, "测试结束")
	})

	go func() {
		for {
			st, err := a.car.AcceptStream(ctx)
			if err != nil {
				return
			}
			go a.serve(st, dial)
		}
	}()
	return a
}

func (a *fakeAgent) serve(st carrier.Stream, dial func(proto.StreamOpen) (net.Conn, error)) {
	defer st.Close()

	fr, err := proto.NewReader(st).ReadFrame()
	if err != nil {
		return
	}
	var open proto.StreamOpen
	if err := proto.Decode(fr, &open); err != nil {
		return
	}
	select {
	case a.opens <- open:
	default:
	}

	w := proto.NewWriter(st)
	local, err := dial(open)
	if err != nil {
		_ = w.WriteMessage(proto.TypeError, fr.Header.CorrID, proto.FlagResponse, proto.Error{
			Code: proto.ErrCodeInternal, Message: "假 agent 拨号失败：" + err.Error(),
		})
		return
	}
	defer local.Close()

	if err := w.WriteMessage(proto.TypeStreamOK, fr.Header.CorrID, proto.FlagResponse,
		proto.StreamOK{LocalAddr: local.LocalAddr().String()}); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(local, st)
		if cw, ok := local.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(st, local)
		st.Close()
	}()
	wg.Wait()
}

// session 把假 agent 包成一个 relay.Session。
func (a *fakeAgent) session(agentID string) *relay.Session {
	return &relay.Session{AgentID: agentID, Carrier: a.car, ConnectedAt: time.Now()}
}

// sessionMap 是 SessionSource 的测试实现。
type sessionMap map[string]*relay.Session

func (m sessionMap) SessionFor(agentID string) (*relay.Session, bool) {
	s, ok := m[agentID]
	return s, ok
}

// ── 通用夹具 ────────────────────────────────────────────────────────────────

// testLogger 把测试期的日志接到 t.Log，避免污染测试输出又不丢信息。
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("日志：%s", bytes.TrimRight(p, "\n"))
	return len(p), nil
}

// sharedTunnel 造一条共享端口隧道。
func sharedTunnel(slug string, mode tunnel.TLSMode, kind tunnel.RouterKind,
	backend string, domains []string, locations []string) *tunnel.Tunnel {
	t := &tunnel.Tunnel{
		ID:       "t-" + slug,
		Slug:     slug,
		AgentID:  "agent-1",
		Kind:     tunnel.KindService,
		TLS:      mode,
		Exposure: tunnel.ExposureShared,
		L4:       tunnel.L4TCP,
		Router:   &tunnel.Router{Kind: kind, Domains: domains, Locations: locations},
		Backend:  tunnel.Backend{Kind: tunnel.BackendAddr, Addr: backend},
	}
	t.Complete()
	return t
}

// portTunnel 造一条独占端口隧道（场景二的形状）。
func portTunnel(slug string, mode tunnel.TLSMode, backend string) *tunnel.Tunnel {
	t := &tunnel.Tunnel{
		ID:       "t-" + slug,
		Slug:     slug,
		AgentID:  "agent-1",
		Kind:     tunnel.KindReverse,
		TLS:      mode,
		Exposure: tunnel.ExposurePort,
		L4:       tunnel.L4TCP,
		Backend:  tunnel.Backend{Kind: tunnel.BackendAddr, Addr: backend},
	}
	t.Complete()
	return t
}

// selfSignedTLS 造一张覆盖若干名字的自签证书，用于 gateway 模式终止 TLS。
//
// 按仓库约定 CurvePreferences 保持 nil：手动设置会静默关掉后量子曲线。
func selfSignedTLS(t *testing.T, names ...string) *tls.Config {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败：%v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发证书失败：%v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("解析证书失败：%v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
		MinVersion:   tls.VersionTLS12,
	}
}

// clientHelloBytes 用真实的 tls.Client 生成一份逐字节真实的 ClientHello。
//
// 不手搓 ClientHello：手搓的那份永远只覆盖自己想到的扩展组合，
// 而真实客户端会带 session ticket、key share、ALPN、GREASE 等一堆东西。
func clientHelloBytes(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()

	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()

	go func() {
		c := tls.Client(near, cfg)
		_ = near.SetDeadline(time.Now().Add(2 * time.Second))
		// 握手必然失败（对端不会回 ServerHello），我们只要它写出的第一条记录。
		_ = c.Handshake()
	}()

	_ = far.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16*1024)
	n, err := far.Read(buf)
	if err != nil {
		t.Fatalf("读 ClientHello 失败：%v", err)
	}
	return bytes.Clone(buf[:n])
}
