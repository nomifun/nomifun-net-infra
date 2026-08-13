package turnsrv

import (
	"errors"
	"net"

	"github.com/pion/turn/v5"
)

// countingGenerator 是一个会计量的 RelayAddressGenerator。
//
// # 为什么必须自己包一层
//
// pion/turn **不暴露任何带宽计数器**，也没有枚举分配的 API
// （研究文档 15 §A6 已核实：EventHandler 只有 OnAuth /
// OnAllocationCreated / OnPermissionCreated 这类事件，没有字节数）。
// 而「这个月 TURN 中继了多少流量」是运营这类服务的第一个问题 ——
// 它直接对应带宽账单。
//
// 唯一的挂钩点是这里：中继 socket 是**每分配一个**，由生成器创建，
// 所以把它包成一个计数的 net.PacketConn，字节数就能干净地归属。
//
// 委托给 RelayAddressGeneratorPortRange 而不是自己实现端口选择：
// 那里有重试逻辑与范围校验，重写一遍只会引入新 bug。
type countingGenerator struct {
	inner *turn.RelayAddressGeneratorPortRange
	stats *Stats
	reg   *registry
}

// newRelayGenerator 造一个新的计量生成器。
//
// 每个监听器配置都要一个**独立**实例：pion 的示例也是这样做的
// （examples 里 rag() 是个工厂函数），因为生成器内部持有状态。
func (s *Server) newRelayGenerator() turn.RelayAddressGenerator {
	return &countingGenerator{
		inner: &turn.RelayAddressGeneratorPortRange{
			// RelayAddress 是**告知客户端**的地址，原样写进
			// XOR-RELAYED-ADDRESS；Address 是实际绑定的地址。
			// 1:1 NAT 后面两者不同，这正是它们分开的理由。
			RelayAddress: net.IP(s.cfg.PublicIP.AsSlice()),
			Address:      "0.0.0.0",
			MinPort:      s.cfg.MinPort,
			MaxPort:      s.cfg.MaxPort,
			MaxRetries:   10,
		},
		stats: &s.stats,
		reg:   s.reg,
	}
}

func (g *countingGenerator) Validate() error { return g.inner.Validate() }

func (g *countingGenerator) AllocatePacketConn(
	cfg turn.AllocateListenerConfig,
) (net.PacketConn, net.Addr, error) {
	pc, addr, err := g.inner.AllocatePacketConn(cfg)
	if err != nil {
		return nil, nil, err
	}
	g.stats.AllocationsCreated.Add(1)
	// 中继地址是这个 socket 与「哪个分配」之间唯一的公共键：
	// 分配的身份来自 OnAllocationCreated，字节数只有这里知道。
	return &countingPacketConn{
		PacketConn: pc,
		stats:      g.stats,
		reg:        g.reg,
		relayKey:   pc.LocalAddr().String(),
	}, addr, nil
}

// ErrTCPAllocationRefused 表示我们不提供 RFC 6062 的 TCP 分配。
var ErrTCPAllocationRefused = errors.New(
	"turnsrv: 不支持 TCP 中继分配（RFC 6062）")

func (g *countingGenerator) AllocateListener(
	turn.AllocateListenerConfig,
) (net.Listener, net.Addr, error) {
	// RFC 6062 的 TCP 分配：**一律拒绝**。
	//
	// # 为什么不是「委托给 pion」
	//
	// 核实过 pion v5.0.12 的 relay_address_generator_static.go:87-91：
	// 它给 TCP 中继监听器加了 reuseport.Control（SO_REUSEADDR + SO_REUSEPORT），
	// 注释写得很清楚「let multiple connections bind to the same relay address」。
	// 而客户端能影响 RequestedPort（EVEN-PORT / RESERVATION-TOKEN 那条路径，
	// internal/server/turn.go 里 requestedPort = allocationPort + 1）。
	//
	// 于是两个不同客户端的 TCP 分配可以绑到**同一个**中继端口，两次 bind 都
	// 成功，入向连接被内核在两者之间负载均衡 —— 发给 A 的连接会被交给 B。
	// UDP 分配没有这个问题：AllocatePacketConn 用的是普通 ListenPacket，
	// 第二次 bind 会干净地失败。
	//
	// # 为什么拒绝是对的选择
	//
	// WebRTC 从不请求 TCP 分配（浏览器的 TURN-over-TCP 指的是**客户端腿**
	// 走 TCP，那与分配的传输协议无关，仍然是 UDP 分配）。所以拒绝它
	// 不减少任何真实能力，却去掉了一整个攻击面 —— 以及一条**不计量**的
	// 字节通路（原来那句「不计量」意味着 TCP 分配的流量在控制台上不存在）。
	//
	// 客户端会收到一个分配错误，而 OnAllocationError 会把它记进
	// AllocationErrors 与日志，所以不是静默失败。
	return nil, nil, ErrTCPAllocationRefused
}

func (g *countingGenerator) AllocateConn(turn.AllocateConnConfig) (net.Conn, error) {
	// 同上：不提供 TCP 分配，也就没有向 TCP 对端拨号这一步。
	return nil, ErrTCPAllocationRefused
}

// countingPacketConn 是一个会计量的中继 socket。
//
// 方向的定义以**中继端口**为视角：
//   - ReadFrom 是对端发来的媒体（下行，最终送给 TURN 客户端）
//   - WriteTo 是 TURN 客户端要送出去的媒体（上行）
//
// 两个方向分开计数而不是合成一个总数：带宽账单通常按出向计费，
// 而排查「为什么只有一方听得到」时也要看两边是否都在动。
type countingPacketConn struct {
	net.PacketConn
	stats *Stats

	// reg 与 relayKey 让字节数能归到**具体某个分配**上，
	// 而不只是加进一个全局总数 —— 「哪一路在刷流量」是运营要问的问题。
	reg      *registry
	relayKey string
}

// entry 按中继地址找到本 socket 所属的分配。
//
// 每包查一次哈希表在这条路径上是可接受的：TURN 中继本身就要做
// 权限查表与 STUN 封装，一次读锁哈希查找相比之下微不足道。
func (c *countingPacketConn) entry() *allocEntry {
	if c.reg == nil {
		return nil
	}
	return c.reg.lookupByRelay(c.relayKey)
}

func (c *countingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n > 0 {
		c.stats.RelayedBytesDown.Add(int64(n))
		if e := c.entry(); e != nil {
			e.bytesDown.Add(int64(n))
		}
	}
	return n, addr, err
}

func (c *countingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if n > 0 {
		c.stats.RelayedBytesUp.Add(int64(n))
		c.stats.RelayedPacketsUp.Add(1)
		if e := c.entry(); e != nil {
			e.bytesUp.Add(int64(n))
		}
	}
	return n, err
}

// 保证包装类型确实实现了接口 —— 少一个方法就会静默退化成
// 「pion 拿到的是 net.PacketConn 而计量方法从不被调用」。
var (
	_ turn.RelayAddressGenerator = (*countingGenerator)(nil)
	_ net.PacketConn             = (*countingPacketConn)(nil)
)
