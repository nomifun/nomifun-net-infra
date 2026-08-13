package carrier

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"
)

// selfSigned 生成一张自签的 ECDSA P-256 证书，供测试使用。
func selfSigned(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nomirelay-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"nomirelay-test"},
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

// pair 建立一对已连通的 QUIC 承载（中继侧与 agent 侧）。
func pair(t *testing.T) (relaySide, agentSide Carrier) {
	t.Helper()

	cert, leaf := selfSigned(t)

	ln, err := ListenQUIC("127.0.0.1:0", QUICConfig{
		TLSConfig: ServerTLSConfig(cert),
		Rung:      RungQUIC,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	type result struct {
		c   Carrier
		err error
	}
	accepted := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := ln.Accept(ctx)
		accepted <- result{c, err}
	}()

	clientTLS, err := ClientTLSConfig("nomirelay-test", nil, SPKIPin(leaf))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	agentSide, err = DialQUIC(ctx, ln.Addr().String(), QUICConfig{
		TLSConfig: clientTLS,
		Rung:      RungQUIC,
	})
	if err != nil {
		t.Fatalf("拨号失败：%v", err)
	}
	t.Cleanup(func() { agentSide.CloseWithError(0, "测试结束") })

	r := <-accepted
	if r.err != nil {
		t.Fatalf("接受失败：%v", r.err)
	}
	t.Cleanup(func() { r.c.CloseWithError(0, "测试结束") })

	return r.c, agentSide
}

// TestRelayCanOpenStreamToAgent 是本包最重要的测试。
//
// 它证明**服务端（中继）也能主动开流**。frp 的 Connector 只有客户端能开流
// （client/connector.go:40-44），这一个限制迫使它走
// ReqWorkConn → NewWorkConn → StartWorkConn 三次往返（1.5×RTT）才能建立
// 一条被代理连接。中继能开流之后那三条消息全部消失，新连接降到 0 额外 RTT。
func TestRelayCanOpenStreamToAgent(t *testing.T) {
	relaySide, agentSide := pair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// agent 侧等待中继开来的流。
	accepted := make(chan Stream, 1)
	errc := make(chan error, 1)
	go func() {
		s, err := agentSide.AcceptStream(ctx)
		if err != nil {
			errc <- err
			return
		}
		accepted <- s
	}()

	// 中继侧主动开流，并把头与首包**一起**写出去（pipeline）。
	s, err := relaySide.OpenStream(ctx)
	if err != nil {
		t.Fatalf("中继开流失败：%v", err)
	}
	defer s.Close()

	payload := []byte("StreamOpen头+用户首包一起发出")
	if _, err := s.Write(payload); err != nil {
		t.Fatalf("写入失败：%v", err)
	}

	select {
	case err := <-errc:
		t.Fatalf("agent 侧接受流失败：%v", err)
	case got := <-accepted:
		defer got.Close()
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(got, buf); err != nil {
			t.Fatalf("读取失败：%v", err)
		}
		if !bytes.Equal(buf, payload) {
			t.Errorf("收到 %q，期望 %q", buf, payload)
		}
	case <-ctx.Done():
		t.Fatal("超时：agent 侧没有收到中继开来的流")
	}
}

// TestBidirectionalStreamsBothDirections 确认两个方向都能开流。
func TestBidirectionalStreamsBothDirections(t *testing.T) {
	relaySide, agentSide := pair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, tc := range []struct {
		name       string
		opener     Carrier
		accepter   Carrier
		wantString string
	}{
		{"中继→agent", relaySide, agentSide, "来自中继"},
		{"agent→中继", agentSide, relaySide, "来自agent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				s, err := tc.accepter.AcceptStream(ctx)
				if err != nil {
					done <- err
					return
				}
				defer s.Close()
				buf := make([]byte, len(tc.wantString))
				if _, err := io.ReadFull(s, buf); err != nil {
					done <- err
					return
				}
				if string(buf) != tc.wantString {
					done <- errors.New("载荷不符：" + string(buf))
					return
				}
				done <- nil
			}()

			s, err := tc.opener.OpenStream(ctx)
			if err != nil {
				t.Fatalf("开流失败：%v", err)
			}
			if _, err := s.Write([]byte(tc.wantString)); err != nil {
				t.Fatalf("写入失败：%v", err)
			}
			s.Close()

			if err := <-done; err != nil {
				t.Fatalf("接受端：%v", err)
			}
		})
	}
}

// TestDatagramsAreNegotiatedAndWork 验证 RFC 9221 不可靠数据报确实可用。
//
// 这是修 frp 队头阻塞的根本：frp 把全部 UDP 塞进一条可靠有序流
// （server/proxy/udp.go:50-52），而 UDP 本身不可靠无序 —— 语义错配才是病根。
// QUIC 数据报的语义（不可靠、无序、不重传）与 UDP 逐条对应。
func TestDatagramsAreNegotiatedAndWork(t *testing.T) {
	relaySide, agentSide := pair(t)

	if !relaySide.SupportsDatagrams() {
		t.Fatal("中继侧应当协商出数据报支持（两端都开了 EnableDatagrams）")
	}
	if !agentSide.SupportsDatagrams() {
		t.Fatal("agent 侧应当协商出数据报支持")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	want := []byte("RTP-like payload")
	if err := relaySide.SendDatagram(want); err != nil {
		t.Fatalf("发送数据报失败：%v", err)
	}

	got, err := agentSide.ReceiveDatagram(ctx)
	if err != nil {
		t.Fatalf("接收数据报失败：%v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("收到 %q，期望 %q", got, want)
	}
}

// TestOversizeDatagramReportsLearnableLimit 验证反应式 MTU 学习。
//
// quic-go **不提供**查询最大数据报尺寸的 getter，唯一途径是发送失败时从
// *quic.DatagramTooLargeError.MaxDatagramPayloadSize 读取。
// 所以实现必须把它翻译成我们自己的错误类型并缓存下来，
// 否则调用方无从得知该按多大分片。
func TestOversizeDatagramReportsLearnableLimit(t *testing.T) {
	relaySide, _ := pair(t)

	// 远超任何可能的路径 MTU。
	oversize := make([]byte, 64*1024)
	err := relaySide.SendDatagram(oversize)
	if err == nil {
		t.Fatal("64 KiB 的数据报不可能装进单个 QUIC 包，应当报错")
	}

	var tooLarge *DatagramTooLargeError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("应当返回 *DatagramTooLargeError，得到 %T: %v", err, err)
	}
	if tooLarge.MaxPayload <= 0 {
		t.Error("MaxPayload 必须是正数，否则调用方无从得知该按多大分片")
	}
	if tooLarge.Attempted != len(oversize) {
		t.Errorf("Attempted = %d，期望 %d", tooLarge.Attempted, len(oversize))
	}

	// 上限必须已被缓存下来，供后续分片决策使用。
	if got := relaySide.MaxDatagramPayload(); got != tooLarge.MaxPayload {
		t.Errorf("MaxDatagramPayload() = %d，期望已缓存为 %d", got, tooLarge.MaxPayload)
	}

	// 用学到的上限重发，应当成功。
	fitting := make([]byte, relaySide.MaxDatagramPayload())
	if err := relaySide.SendDatagram(fitting); err != nil {
		t.Errorf("按学到的上限发送应当成功，却失败：%v", err)
	}
}

// TestStreamCloseCancelsReadDirection 守护那个会导致流泄漏的坑。
//
// quic.Stream.Close() **只关闭写方向**，读方向仍然挂着，对端不写就永远不返回，
// 于是流与它的 goroutine 一起泄漏。我们的 quicStream.Close 额外调 CancelRead
// 做真正的双向关闭 —— 这个测试确认那个补丁在。
func TestStreamCloseCancelsReadDirection(t *testing.T) {
	relaySide, agentSide := pair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opened := make(chan Stream, 1)
	go func() {
		s, err := agentSide.AcceptStream(ctx)
		if err == nil {
			opened <- s
		}
	}()

	s, err := relaySide.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// 必须先写点东西，否则对端不会感知到这条流的存在。
	if _, err := s.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}

	var peer Stream
	select {
	case peer = <-opened:
	case <-ctx.Done():
		t.Fatal("对端没有接受到流")
	}
	defer peer.Close()

	// 关闭本端。若只关了写方向，下面这个读会一直挂到 ctx 超时。
	if err := s.Close(); err != nil {
		t.Fatalf("Close 失败：%v", err)
	}

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 16)
		// 关闭后再读应当立刻返回错误，而不是永久阻塞。
		_, _ = s.Read(buf)
	}()

	select {
	case <-readDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close 后读方向仍在阻塞 —— quicStream.Close 缺少 CancelRead，流会泄漏")
	}
}

// TestRungMetadata 确认梯级信息被正确携带，控制台要显示它。
func TestRungMetadata(t *testing.T) {
	relaySide, agentSide := pair(t)

	if relaySide.Rung() != RungQUIC || agentSide.Rung() != RungQUIC {
		t.Errorf("梯级 = %v/%v，期望都是 %v", relaySide.Rung(), agentSide.Rung(), RungQUIC)
	}
	if RungQUIC.Reliable() {
		t.Error("QUIC 梯级不应被标记为「仅可靠」——它有不可靠数据报")
	}
	if !RungTLS443.Reliable() || !RungWSS443.Reliable() {
		t.Error("smux 承载的梯级必须标记为「仅可靠」，控制台要据此提示 UDP 延迟不保证")
	}
	for _, r := range []Rung{RungQUIC, RungQUIC443, RungTLS443, RungWSS443} {
		if r.String() == "未知梯级" {
			t.Errorf("梯级 %d 缺少可读名", r)
		}
	}
}

// ── SPKI 指纹绑定 ──────────────────────────────────────────────────────────

// TestClientTLSRefusesInsecureDefault 是一条安全底线的断言。
//
// frp 在没配 CA 时把 InsecureSkipVerify 设为 true（pkg/transport/tls.go:150-152），
// 于是它宣传的「默认开启 TLS」只有加密没有服务端认证，MITM 门槛为零。
// 我们必须拒绝提供那样的默认值。
func TestClientTLSRefusesInsecureDefault(t *testing.T) {
	_, err := ClientTLSConfig("example.com", nil, nil)
	if err == nil {
		t.Fatal("既无 rootCAs 又无 pinnedSPKI 时必须报错，绝不能静默退化为跳过校验")
	}
}

// TestSPKIPinMismatchIsRejected 验证指纹不符时握手失败。
func TestSPKIPinMismatchIsRejected(t *testing.T) {
	serverCert, _ := selfSigned(t)
	_, otherLeaf := selfSigned(t) // 另一张证书的指纹

	ln, err := ListenQUIC("127.0.0.1:0", QUICConfig{
		TLSConfig: ServerTLSConfig(serverCert),
		Rung:      RungQUIC,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if c, err := ln.Accept(ctx); err == nil {
			c.CloseWithError(0, "")
		}
	}()

	clientTLS, err := ClientTLSConfig("nomirelay-test", nil, SPKIPin(otherLeaf))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := DialQUIC(ctx, ln.Addr().String(), QUICConfig{TLSConfig: clientTLS}); err == nil {
		t.Fatal("指纹不匹配时握手必须失败")
	}
}

// TestSPKIPinIsStableAcrossCertRenewal 验证钉公钥而非钉整证书。
//
// 证书续期时只要沿用同一密钥对，指纹就应保持不变 ——
// 否则每次续期都要重新分发指纹，运维上必然被绕过。
func TestSPKIPinIsStableAcrossCertRenewal(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	mkCert := func(serial int64, notAfter time.Time) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "same-key"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     notAfter,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// 两张不同的证书（不同序列号与有效期），同一密钥对。
	old := mkCert(1, time.Now().Add(24*time.Hour))
	renewed := mkCert(2, time.Now().Add(365*24*time.Hour))

	if bytes.Equal(old.Raw, renewed.Raw) {
		t.Fatal("测试前提不成立：两张证书应当不同")
	}
	if !bytes.Equal(SPKIPin(old), SPKIPin(renewed)) {
		t.Error("同一密钥对签出的两张证书的 SPKI 指纹必须相同，否则续期就会打断指纹绑定")
	}
}

func TestParseSPKIPinRoundTrip(t *testing.T) {
	_, leaf := selfSigned(t)
	encoded := SPKIPinBase64(leaf)

	got, err := ParseSPKIPin(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, SPKIPin(leaf)) {
		t.Error("指纹往返后不一致")
	}

	for _, bad := range []string{"", "not-base64!!", "c2hvcnQ="} {
		if _, err := ParseSPKIPin(bad); err == nil {
			t.Errorf("非法指纹 %q 应当被拒", bad)
		}
	}
}
