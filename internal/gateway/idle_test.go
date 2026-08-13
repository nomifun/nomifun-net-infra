package gateway

import (
	"net"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// TestIdleKeepAliveConnectionsReleaseTheirSlot 钉住那道**必需**的空闲回收。
//
// # 不设 IdleTimeout 是一个远程可触发的拒绝服务
//
// 判别器在 Accept 之后、Decide 之前就占一个槽位（512），Handle 返回才还，
// 而网关分支的 Handle 要等**连接关闭**才返回。Go 的 Server.idleTimeout() 在
// IdleTimeout 为 0 时回落到 ReadTimeout —— 两个都没设时**压根没有空闲超时**。
//
// 实测（真实进程）：512 条「发完一个请求就挂着」的连接把整个共享端口占死，
// 无需鉴权、无需负载、也不需要配任何限速。之后新连接被 RST、
// **ACME 挑战在信号量那一步就被关掉**（证书续签静默失败）、L2 agent 连不上。
//
// 这条测试用一个很短的 IdleTimeout 验证机制：一条空闲的 keep-alive 连接
// 会被服务端主动关掉，槽位因此还回去。
//
// **它不证明那个洞被关上了**：攻击者每 55 秒发一个廉价请求就能一直占着，
// 而端口级信号量上没有任何每源 IP 记账。那一条仍在诚实清单里。
func TestIdleKeepAliveConnectionsReleaseTheirSlot(t *testing.T) {
	f := newGatewayFixtureWith(t, true, func(c *GatewayConfig) {
		c.IdleTimeout = 300 * time.Millisecond
	})
	limitedShared(t, f, "idle", "idle.example.com", nil)

	c, err := net.Dial("tcp", f.relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	// 一个完整请求，读完响应头就停 —— 之后这条连接进入空闲。
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: idle.example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	one := make([]byte, 1)
	var hdr []byte
	for {
		if _, err := c.Read(one); err != nil {
			t.Fatalf("读响应头失败：%v", err)
		}
		hdr = append(hdr, one[0])
		if len(hdr) >= 4 && string(hdr[len(hdr)-4:]) == "\r\n\r\n" {
			break
		}
	}

	// 空闲超过 IdleTimeout：服务端必须主动关掉它。
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			// EOF / RST 都算「服务端把它关了」。
			return
		}
		if n == 0 {
			return
		}
	}
}

// TestGatewaySetsAnIdleTimeout 钉住**取值本身**存在。
//
// 上面那条测试注入了一个短超时，所以它对「生产默认值是 0」这件事完全不敏感 ——
// 而 0 正是那个洞。这一条守住默认值。
func TestGatewaySetsAnIdleTimeout(t *testing.T) {
	g := NewGateway(GatewayConfig{Registry: NewRegistry()})
	srv := g.server()
	if srv.IdleTimeout <= 0 {
		t.Fatal("网关的 http.Server 没有 IdleTimeout —— " +
			"Go 会回落到 ReadTimeout（也是 0），于是一条空闲 keep-alive 连接" +
			"可以永远占着判别器的槽位。512 条就能把整个共享端口占死，" +
			"而 ACME 挑战会在信号量那一步被关掉：证书续签静默失败")
	}
	if srv.IdleTimeout != defaultIdleTimeout {
		t.Errorf("IdleTimeout = %v，期望默认值 %v", srv.IdleTimeout, defaultIdleTimeout)
	}
	// 刻意**不设** ReadTimeout：它会切断长命的流式响应（SSE 经隧道），
	// 而空闲回收只需要 IdleTimeout。
	if srv.ReadTimeout != 0 {
		t.Errorf("设了 ReadTimeout=%v —— 它会切断经隧道的 SSE 与长轮询", srv.ReadTimeout)
	}
	_ = tunnel.ExposureShared
}
