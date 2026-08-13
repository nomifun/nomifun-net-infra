package gateway

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// ACMETLSALPNProto 是 TLS-ALPN-01 挑战的 ALPN 标识（RFC 8737）。
//
// 判别顺序第 3 步：带这个 ALPN 的连接**永远**本地终止，
// 这样即使一个端口上同时挂着透传隧道，ACME 挑战也能完成。
const ACMETLSALPNProto = "acme-tls/1"

// recordTypeHandshake 是 TLS 握手记录的首字节（0x16）。
//
// DTLS 也用 0x16，但 DTLS 只跑 UDP，所以在 TCP 判别器上不存在歧义。
const recordTypeHandshake = 0x16

// ErrNoClientHello 表示对端发来的不是一个可解析的 TLS ClientHello。
var ErrNoClientHello = errors.New("gateway: 没能从首包里解析出 ClientHello")

// peekClientHello 在**不解密、不终止 TLS**的前提下读出 ClientHello。
//
// # 手法来源与为什么它是对的
//
// 抄自 frp（Apache-2.0）：/mnt/hgfs/share/net-infra/frp/pkg/util/vhost/https.go:39-90。
// 那里的 readClientHello（:53-71）构造一个假的 readOnlyConn（:79-90，Write 直接
// 返回 io.ErrClosedPipe，所以一个字节都不会流出去），交给 tls.Server，
// 在 GetConfigForClient 回调里把 *tls.ClientHelloInfo 抄走，然后无视那个
// **必然失败**的 handshake error（原注释：「Handshake always fails because the
// readOnlyConn is not a real connection… we only care about the error if hello
// was never set」）。零手写 TLS 解析，全部由 crypto/tls 承担。
//
// 一次 peek 同时拿到 ServerName 与 SupportedProtos —— 判别顺序的第 3 步（ALPN）
// 与第 4 步（SNI）因此共用同一次读取，而不是读两遍。
//
// # ECH 会破坏这一点
//
// Encrypted ClientHello 会把真实 SNI 加密进 ECH 扩展，届时这里只能看到
// public_name。设计上保留两条兜底：ALPN token 分流，或一条隧道一个专用端口
// （判别顺序第 0 步，根本不 peek）。spec §7.2 已把这条写成告警而不是脚注。
func peekClientHello(c *PeekConn, step time.Duration) (*tls.ClientHelloInfo, error) {
	return readClientHello(c.PeekReader(step))
}

// readClientHello 从一个只读流里解析 ClientHello。
//
// 单独拆出来是为了让 fuzz 目标能直接喂字节（见 FuzzClientHello）。
func readClientHello(r io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo

	err := tls.Server(readOnlyConn{reader: r}, &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			// 必须复制：回调返回后 crypto/tls 会复用/丢弃这个结构。
			h := *argHello
			hello = &h
			// 返回 nil 让握手继续走原配置，它随后会因为「没有证书」而失败 ——
			// 那正是我们想要的：ClientHello 已经拿到，握手死掉是免费的。
			return nil, nil
		},
	}).Handshake()

	if hello == nil {
		return nil, fmt.Errorf("%w：%w", ErrNoClientHello, err)
	}
	return hello, nil
}

// sendUnrecognizedName 用一个**真正的** TLS alert 拒绝连接，而不是裸 close。
//
// 裸 close 会让浏览器显示 ERR_CONNECTION_CLOSED 之类无信息的错误，
// 用户与运维都无法据此判断「是域名没注册」还是「中继挂了」。
// 手法同 frp 的 vhostFailed（https.go:73-77）：起一个**无证书**的 tls.Server，
// 让 crypto/tls 自己在 getCertificate 失败时发 alertUnrecognizedName
// （/usr/local/go/src/crypto/tls/handshake_server.go:279-280 与
// handshake_server_tls13.go:489-490，errNoCertificates → sendAlert(112)）。
//
// 传进来的必须是**能重放 ClientHello 的**连接（PeekConn），否则握手读不到首包，
// crypto/tls 走不到 getCertificate 那一步，也就发不出 alert。
func sendUnrecognizedName(c net.Conn) {
	_ = tls.Server(c, &tls.Config{}).Handshake()
}

// readOnlyConn 是一个只能读的假连接。
//
// Write 返回 io.ErrClosedPipe，保证嗅探期间**没有任何字节**流向客户端；
// 地址与期限方法全部是空实现 —— crypto/tls 在握手路径上不需要它们。
type readOnlyConn struct{ reader io.Reader }

func (c readOnlyConn) Read(p []byte) (int, error)       { return c.reader.Read(p) }
func (readOnlyConn) Write([]byte) (int, error)          { return 0, io.ErrClosedPipe }
func (readOnlyConn) Close() error                       { return nil }
func (readOnlyConn) LocalAddr() net.Addr                { return nil }
func (readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (readOnlyConn) SetDeadline(time.Time) error        { return nil }
func (readOnlyConn) SetReadDeadline(time.Time) error    { return nil }
func (readOnlyConn) SetWriteDeadline(_ time.Time) error { return nil }
