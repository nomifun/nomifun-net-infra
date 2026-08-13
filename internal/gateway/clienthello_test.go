package gateway

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestPeekClientHelloExtractsSNIAndALPNWithoutDecrypting 证明 spec §7.2 的核心断言：
// **SNI 是明文，读它不需要解密一个字节。**
//
// 同时钉住「一次 peek 同时拿到 ServerName 与 SupportedProtos」——
// 判别顺序的第 3 步（ALPN）与第 4 步（SNI）共用这一次读取。
func TestPeekClientHelloExtractsSNIAndALPNWithoutDecrypting(t *testing.T) {
	cases := []struct {
		name     string
		cfg      *tls.Config
		wantSNI  string
		wantALPN []string
	}{
		{
			name:    "只有 SNI",
			cfg:     &tls.Config{ServerName: "api.example.com"},
			wantSNI: "api.example.com",
		},
		{
			name:     "SNI 加 h2 与 http/1.1",
			cfg:      &tls.Config{ServerName: "www.example.com", NextProtos: []string{"h2", "http/1.1"}},
			wantSNI:  "www.example.com",
			wantALPN: []string{"h2", "http/1.1"},
		},
		{
			name:     "ACME 的 TLS-ALPN-01 挑战",
			cfg:      &tls.Config{ServerName: "acme.example.com", NextProtos: []string{ACMETLSALPNProto}},
			wantSNI:  "acme.example.com",
			wantALPN: []string{ACMETLSALPNProto},
		},
		{
			name: "IP 字面量拨号：没有 SNI",
			// 直连 IP 的客户端不发 SNI —— 这条路只能落到端口默认绑定。
			// InsecureSkipVerify 只是为了让 tls.Client 在没有 ServerName 时肯发包，
			// 这里根本没有服务端证书要校验。
			cfg:     &tls.Config{InsecureSkipVerify: true},
			wantSNI: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hello := clientHelloBytes(t, tc.cfg)

			near, far := net.Pipe()
			defer near.Close()
			defer far.Close()

			// 客户端只写 ClientHello，然后闭嘴 —— 中继必须在此就能判别。
			go func() { _, _ = far.Write(hello) }()

			pc := NewPeekConn(near)
			info, err := peekClientHello(pc, 2*time.Second)
			if err != nil {
				t.Fatalf("解析 ClientHello 失败：%v", err)
			}
			if info.ServerName != tc.wantSNI {
				t.Errorf("ServerName = %q，期望 %q", info.ServerName, tc.wantSNI)
			}
			if !slices.Equal(info.SupportedProtos, tc.wantALPN) {
				t.Errorf("SupportedProtos = %v，期望 %v", info.SupportedProtos, tc.wantALPN)
			}

			// 嗅探期间**一个字节都不能**流向客户端：readOnlyConn 的 Write 恒失败。
			// far 端此时若有可读数据，说明我们回写了握手响应，那就等于在代握手。
			_ = far.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			one := make([]byte, 1)
			if n, err := far.Read(one); err == nil {
				t.Fatalf("嗅探期间向客户端写了 %d 字节（%#x）—— 绝不能代替后端握手", n, one[:n])
			}
		})
	}
}

// TestPeekedClientHelloIsReplayedByteIdentical 证明 peek 之后连接仍可原样重放。
//
// 透传模式下后端要用这份 ClientHello 做**真实**握手（私钥在它那边），
// 所以重放必须逐字节相同。
func TestPeekedClientHelloIsReplayedByteIdentical(t *testing.T) {
	hello := clientHelloBytes(t, &tls.Config{
		ServerName: "passthrough.example.com",
		NextProtos: []string{"h2", "http/1.1"},
	})

	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()

	go func() {
		_, _ = far.Write(hello)
		far.Close()
	}()

	pc := NewPeekConn(near)
	info, err := peekClientHello(pc, 2*time.Second)
	if err != nil {
		t.Fatalf("解析 ClientHello 失败：%v", err)
	}
	if info.ServerName != "passthrough.example.com" {
		t.Fatalf("ServerName = %q", info.ServerName)
	}

	replayed, err := io.ReadAll(pc)
	if err != nil {
		t.Fatalf("读重放字节失败：%v", err)
	}
	if !bytes.Equal(replayed, hello) {
		t.Fatalf("重放的 ClientHello 与原始不一致：%d vs %d 字节", len(replayed), len(hello))
	}
	t.Logf("逐字节重放 %d 字节 ClientHello", len(replayed))
}

// TestSendUnrecognizedNameEmitsRealAlert 证明拒绝走的是**真正的** TLS 告警
// （spec §7.3 第 6 步），而不是裸关闭。
//
// 裸关闭在浏览器里只会显示无信息的连接错误；unrecognized_name 让客户端与
// 运维都能立刻知道「这个域名没在中继上注册」。
func TestSendUnrecognizedNameEmitsRealAlert(t *testing.T) {
	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()

	errCh := make(chan error, 1)
	go func() {
		c := tls.Client(far, &tls.Config{ServerName: "unknown.example.com"})
		_ = far.SetDeadline(time.Now().Add(3 * time.Second))
		errCh <- c.Handshake()
	}()

	// 服务端侧：先把 ClientHello peek 出来（判别失败的真实路径），再回告警。
	pc := NewPeekConn(near)
	if _, err := peekClientHello(pc, 2*time.Second); err != nil {
		t.Fatalf("解析 ClientHello 失败：%v", err)
	}
	sendUnrecognizedName(pc)
	near.Close()

	err := <-errCh
	if err == nil {
		t.Fatal("客户端握手竟然成功了")
	}
	if !strings.Contains(err.Error(), "unrecognized name") {
		t.Fatalf("客户端错误 = %v，期望包含 unrecognized name（alert 112）", err)
	}
	t.Logf("客户端收到告警：%v", err)
}

// FuzzClientHello 对 ClientHello/SNI 解析路径做模糊测试。
//
// 这条路径的输入**完全由公网控制**且在任何鉴权之前执行，
// 所以它与 internal/proto 的帧解析器一样必须有 fuzz 目标：
// 不许 panic、不许无限等待、拿不到 hello 时必须干净报错。
func FuzzClientHello(f *testing.F) {
	// 种子：真实 ClientHello（带/不带 SNI 与 ALPN）+ 几个明显畸形的输入。
	f.Add(mustHello(f, &tls.Config{ServerName: "api.example.com"}))
	f.Add(mustHello(f, &tls.Config{ServerName: "a.b.c", NextProtos: []string{ACMETLSALPNProto}}))
	f.Add(mustHello(f, &tls.Config{InsecureSkipVerify: true}))
	f.Add([]byte{})
	f.Add([]byte{0x16})
	f.Add([]byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		info, err := readClientHello(bytes.NewReader(data))
		if err != nil {
			if info != nil {
				t.Fatalf("返回错误时不该同时返回 hello：%v", err)
			}
			return
		}
		if info == nil {
			t.Fatal("err 为 nil 时必须返回 hello")
		}
		// 解析成功时字段必须是可安全使用的：判别器会把 ServerName 当路由键，
		// 把 SupportedProtos 逐个比对。
		if strings.ContainsAny(info.ServerName, "\x00\r\n") {
			t.Fatalf("ServerName 含控制字符：%q", info.ServerName)
		}
		for _, p := range info.SupportedProtos {
			if p == "" {
				t.Error("SupportedProtos 含空串")
			}
		}
	})
}

func mustHello(f *testing.F, cfg *tls.Config) []byte {
	f.Helper()

	near, far := net.Pipe()
	defer near.Close()
	defer far.Close()

	go func() {
		c := tls.Client(near, cfg)
		_ = near.SetDeadline(time.Now().Add(2 * time.Second))
		_ = c.Handshake()
	}()

	_ = far.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16*1024)
	n, err := far.Read(buf)
	if err != nil {
		f.Fatalf("生成种子 ClientHello 失败：%v", err)
	}
	return bytes.Clone(buf[:n])
}
