package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// 共享入口上的每隧道限额。
//
// 这一组测试守的是 README 诚实清单里那条最容易咬人的缺口：
// max_conns / max_conns_per_ip / bytes_per_second 全链路可配、界面显示
// 「已设置」，而共享入口路径上零读取点 —— 用户给一条公网隧道配了 1 Mbps，
// 它照样跑满。「界面说生效而实际没有」是本仓最在意的缺陷类型。

// limitedShared 注册一条带限额的共享入口隧道并返回它。
func limitedShared(t *testing.T, f *gwFixture, slug, domain string, pol *tunnel.Policy) *tunnel.Tunnel {
	t.Helper()
	tn := sharedTunnel(slug, tunnel.TLSGateway, tunnel.RouterHTTP,
		f.backendAddr, []string{domain}, nil)
	tn.Policy = pol
	if err := f.reg.AddShared(f.relayPort, tn); err != nil {
		t.Fatal(err)
	}
	return tn
}

// TestSharedEntryHonoursBytesPerSecond 是这一组里最要紧的一条。
//
// 修之前：给共享入口的隧道配 bytes_per_second，界面显示「已设置」，
// 而 internal/gateway 里没有一处构造或查询限速器 —— 一个字节都没被限。
//
// # 为什么这条测试不 flaky
//
// 断言的是**耗时下界**而不是上界：机器慢只会让它更慢，不会假失败。
// 速率取得高于 minByteBurst（否则桶容量被抬到 64 KiB，载荷全落在初始突发里、
// 根本不会慢，测的就不是限速了），载荷取三倍速率（初始突发只够第一份）。
// 与 internal/limiter/limiter_test.go 的手法同源。
func TestSharedEntryHonoursBytesPerSecond(t *testing.T) {
	f := newGatewayFixture(t, true)

	const rate = 256 << 10 // 256 KiB/s
	const size = 3 * rate  // 768 KiB：初始突发只够第一份
	limitedShared(t, f, "slow", "slow.example.com", &tunnel.Policy{
		BytesPerSecond: rate,
	})

	// 先用一条**不限速**的隧道量个基线，确认这个尺寸本身很快 ——
	// 否则「慢」可能只是后端或测试机的问题，而不是限速起了作用。
	fast := time.Now()
	doSized(t, f, "api.example.com", size)
	baseline := time.Since(fast)

	start := time.Now()
	got := doSized(t, f, "slow.example.com", size)
	elapsed := time.Since(start)

	if got != size {
		t.Fatalf("响应体少了：读到 %d / %d —— 限速必须**等**而不是丢，"+
			"在一条 TCP 流中间挖洞比慢得多糟糕", got, size)
	}
	// 768 KiB 过 256 KiB/s：桶初始满（256 KiB），剩下 512 KiB 要按 256 KiB/s 补，
	// 所以至少 ~2 秒。取 1 秒作下界，留足余量。
	if elapsed < time.Second {
		t.Fatalf("%d 字节过 %d B/s 只花了 %s（不限速的基线是 %s）—— 限速没生效",
			size, rate, elapsed.Round(time.Millisecond), baseline.Round(time.Millisecond))
	}
	t.Logf("限速生效：%s（不限速基线 %s）",
		elapsed.Round(time.Millisecond), baseline.Round(time.Millisecond))
}

// TestSharedEntryHonoursMaxConns 钉住并发上限。
//
// 语义与独立监听器有意不同（那边一条连接一个额度，这边一个**在飞请求**一个额度），
// 理由写在 ServeHTTP 的注释里：共享入口上一条连接可以服务任意多个请求、
// 还可以中途换隧道，所以按连接算的归属必然是错的。
func TestSharedEntryHonoursMaxConns(t *testing.T) {
	f := newGatewayFixture(t, true)
	limitedShared(t, f, "cap", "cap.example.com", &tunnel.Policy{MaxConns: 2})

	// /api/slow 的后端会分三块、每块间隔 10ms 地吐 —— 足够让请求重叠。
	// 用一个更长的路径不行（后端没实现），所以靠并发数量制造重叠。
	const n = 8
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := f.client(false).Get("http://cap.example.com/api/slow")
			if err != nil {
				codes[i] = -1
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
			codes[i] = resp.StatusCode
		}()
	}
	wg.Wait()

	var ok, full int
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusServiceUnavailable:
			full++
		}
	}
	if full == 0 {
		t.Fatalf("并发 %d 个请求、上限 2，一个都没被拒（状态分布 %v）—— "+
			"max_conns 在共享入口上没生效", n, codes)
	}
	if ok == 0 {
		t.Fatalf("全被拒了（%v）—— 闸门把正常请求也挡了", codes)
	}
	if got := f.gw.Stats().DeniedMaxConns.Load(); got == 0 {
		t.Error("DeniedMaxConns 计数器没动 —— 运维看不出是哪一道闸拒的")
	}
	t.Logf("放行 %d、拒 %d（上限 2）", ok, full)
}

// TestSharedEntryHonoursPerIPQuota 钉住每源 IP 配额。
//
// 只有全局上限时，一个源 IP 就能占满它并把别人挤出去 ——「最多 N 路」保护的是
// 中继不被压垮，不是保护其他用户。测试里所有请求都来自 127.0.0.1，
// 所以配额比全局上限更小时应当是**配额**先触发。
func TestSharedEntryHonoursPerIPQuota(t *testing.T) {
	f := newGatewayFixture(t, true)
	limitedShared(t, f, "perip", "perip.example.com", &tunnel.Policy{
		MaxConns: 64, MaxConnsPerIP: 1,
	})

	const n = 6
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := f.client(false).Get("http://perip.example.com/api/slow")
			if err != nil {
				codes[i] = -1
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
			codes[i] = resp.StatusCode
		}()
	}
	wg.Wait()

	if f.gw.Stats().DeniedPerIP.Load() == 0 {
		t.Fatalf("配额 1、并发 %d 个同源请求，DeniedPerIP 一次都没动（%v）—— "+
			"每源配额在共享入口上没生效", n, codes)
	}
	// 全局上限是 64，远没满，所以不该是它触发的。
	if got := f.gw.Stats().DeniedMaxConns.Load(); got != 0 {
		t.Errorf("被全局上限拒了 %d 次，而上限是 64 —— 两道闸的归属搞混了", got)
	}
}

// TestLimitsSurviveARouteTableRebuild 是这一组里**最容易被写错**的一条。
//
// # 为什么它必须存在
//
// applyShared 每次都造一张新注册表再 ReplaceWith 整体替换，并对每条隧道调
// Invalidate。而它由 ApplyTunnels **与 refreshStates** 两处触发 ——
// 后者在**每次 agent 上下线**时都跑。
//
// 把限额状态放进路由表、或跟着 Invalidate 回收，会有两个后果：
//
//   - 令牌桶被清零。桶初始是满的，所以每次清零都送出一份完整的突发额度 ——
//     一个能让 agent 反复重连的人（拔网线就够）由此拿到不受限的带宽。
//     限速变成了一个可被外部驱动关掉的开关。
//   - 在飞计数被清零而连接还开着，释放路径把一个已归零的计数器再减，
//     闸门从此恒开或恒关。
//
// 所以这条测试直接验「重建之后拿到的还是同一个状态对象」。
func TestLimitsSurviveARouteTableRebuild(t *testing.T) {
	reg := NewRegistry()
	tn := sharedTunnel("keep", tunnel.TLSGateway, tunnel.RouterHTTP,
		"127.0.0.1:9", []string{"keep.example.com"}, nil)
	tn.Policy = &tunnel.Policy{MaxConns: 4, BytesPerSecond: 1 << 20}

	before := reg.limitsFor(tn)
	if before == nil {
		t.Fatal("配了限额却没建出状态")
	}
	// 占一个额度，模拟一条在飞的请求。
	release, denied := before.admit(netip.MustParseAddr("203.0.113.7"))
	if denied != denyNone {
		t.Fatalf("第一个额度就被拒了：%v", denied)
	}
	defer release()

	// 模拟 applyShared：整张路由表换掉，并对这条隧道 Invalidate。
	fresh := NewRegistry()
	if err := fresh.AddShared(443, tn); err != nil {
		t.Fatal(err)
	}
	reg.ReplaceWith(fresh)
	reg.RetainLimits(map[string]bool{tn.ID: true})

	after := reg.limitsFor(tn)
	if after != before {
		t.Fatalf("路由表重建之后拿到了**另一个**限额状态 —— " +
			"令牌桶被清零（桶初始满 → 每次 agent 抖动白送一份突发额度），" +
			"在飞计数也与还开着的连接脱节")
	}
	// 在飞计数必须还在：上限 4、已占 1，所以还能再占 3、第 5 个被拒。
	var got int
	for range 4 {
		rel, d := after.admit(netip.MustParseAddr("203.0.113.7"))
		defer rel()
		if d == denyNone {
			got++
		}
	}
	if got != 3 {
		t.Errorf("重建之后还能再占 %d 个额度，期望 3（上限 4、已占 1）—— "+
			"在飞计数被重置了", got)
	}
}

// TestChangingThePolicyDoesRebuildTheBucket 是上一条的**反面**。
//
// 「只在策略变了时才重建」很容易退化成「永不重建」——那时用户把 1 Mbps 改成
// 10 Mbps 之后毫无变化，而界面显示新值。这一条守住那个方向。
func TestChangingThePolicyDoesRebuildTheBucket(t *testing.T) {
	reg := NewRegistry()
	tn := sharedTunnel("chg", tunnel.TLSGateway, tunnel.RouterHTTP,
		"127.0.0.1:9", []string{"chg.example.com"}, nil)
	tn.Policy = &tunnel.Policy{BytesPerSecond: 1 << 20}

	first := reg.limitsFor(tn)
	if first == nil {
		t.Fatal("没建出状态")
	}
	bucket0 := first.bucket()
	if same := reg.limitsFor(tn); same != first {
		t.Fatal("策略没变却重建了 —— 每次 apply 都会白送一份突发额度")
	}
	// **桶也不能换。** 只断言对象身份不够：变异验证抓出来的 ——
	// 把「spec 相同就直接复用」那一支去掉之后，控制流会落到「只有带宽变了」
	// 那一支，于是对象保住了而桶被换掉。桶初始是满的，所以那等于
	// 每次 applyShared（每次 agent 上下线都会跑）白送一份完整的突发额度。
	if first.bucket() != bucket0 {
		t.Fatal("策略没变却换了桶 —— 桶初始是满的，每次 agent 抖动都会" +
			"白送一份完整的突发额度，限速变成一个可被外部驱动关掉的开关")
	}

	// 改速率：**对象要保住**（已建立的连接持有它，桶现取所以立刻生效），
	// 而**桶必须换掉**。
	//
	// 这条断言在这一轮被改过方向。第一版要求「换对象」，那样已经建立的连接
	// 会一直持着旧对象、跑旧桶 —— 而把 10 Mbps 调成 1 Mbps 的典型动机
	// 恰恰是压住**正在进行**的滥用。评审指出了这一点。
	bucketBefore := first.bucket()
	tn.Policy = &tunnel.Policy{BytesPerSecond: 8 << 20}
	second := reg.limitsFor(tn)
	if second != first {
		t.Fatal("只改了带宽却换了限额对象 —— 已经建立的连接会一直跑旧桶，" +
			"而调低带宽的典型动机正是压住正在进行的滥用")
	}
	if second.bucket() == bucketBefore {
		t.Fatal("改了 bytes_per_second 却没换桶 —— 新配置永远不生效，" +
			"而界面显示的是新值")
	}

	// 改成完全不限：状态应当被丢掉。
	tn.Policy = &tunnel.Policy{}
	if third := reg.limitsFor(tn); third != nil {
		t.Error("限额被改成全不限，却还留着状态对象")
	}
	if n := reg.trackedLimits(); n != 0 {
		t.Errorf("还跟踪着 %d 条 —— 全不限的隧道不该占状态", n)
	}
}

// TestDeletedTunnelsStopBeingTracked 钉住回收。
//
// 键是隧道 ID，而中继是长期运行的进程。不回收的话反复增删隧道会让这张表
// 只增不减 —— 一个慢速内存泄漏。
func TestDeletedTunnelsStopBeingTracked(t *testing.T) {
	reg := NewRegistry()
	for _, slug := range []string{"a", "b", "c"} {
		tn := sharedTunnel(slug, tunnel.TLSGateway, tunnel.RouterHTTP,
			"127.0.0.1:9", []string{slug + ".example.com"}, nil)
		tn.Policy = &tunnel.Policy{MaxConns: 2}
		reg.limitsFor(tn)
	}
	if n := reg.trackedLimits(); n != 3 {
		t.Fatalf("前置不成立：跟踪了 %d 条，期望 3", n)
	}
	reg.RetainLimits(map[string]bool{"t-b": true})
	if n := reg.trackedLimits(); n != 1 {
		t.Errorf("回收之后还跟踪着 %d 条，期望 1 —— 已删隧道的状态没被丢掉", n)
	}
}

// TestPerIPTableDropsEntriesAtZero 钉住每源表的归零删除。
//
// 键是源 IP，由任何能连上来的人指定。不删的话这张表只增不减 ——
// 那是一个可被外部驱动的内存耗尽面。与独立监听器、loginguard、
// 学习模式同一条纪律。
func TestPerIPTableDropsEntriesAtZero(t *testing.T) {
	tl := newTunnelLimits(limitSpec{maxConns: 100, maxPerIP: 2})

	var rels []func()
	for i := range 50 {
		a := netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", i+1))
		rel, d := tl.admit(a)
		if d != denyNone {
			t.Fatalf("第 %d 个源被拒了：%v", i, d)
		}
		rels = append(rels, rel)
	}
	tl.perIPMu.Lock()
	peak := len(tl.perIP)
	tl.perIPMu.Unlock()
	if peak != 50 {
		t.Fatalf("前置不成立：表里有 %d 条，期望 50", peak)
	}

	for _, rel := range rels {
		rel()
	}
	tl.perIPMu.Lock()
	left := len(tl.perIP)
	tl.perIPMu.Unlock()
	if left != 0 {
		t.Errorf("全部释放之后表里还剩 %d 条 —— 键由外部指定，"+
			"只增不减就是一个可被驱动的内存耗尽面", left)
	}
}

// TestReleaseIsIdempotent 钉住重复释放。
//
// 多释放一次会把额度**凭空造出来**，闸门静默失效；
// 而漏释放最终耗尽额度、是可见的。两者不对称，所以防的是前者。
func TestReleaseIsIdempotent(t *testing.T) {
	tl := newTunnelLimits(limitSpec{maxConns: 1, maxPerIP: 1})
	src := netip.MustParseAddr("203.0.113.9")

	rel, d := tl.admit(src)
	if d != denyNone {
		t.Fatal("第一个就被拒了")
	}
	rel()
	rel() // 第二次必须是空操作
	rel()

	// 上限是 1：如果重复释放造出了额度，下面这两个都会被放行。
	r1, d1 := tl.admit(src)
	defer r1()
	r2, d2 := tl.admit(src)
	defer r2()
	if d1 != denyNone {
		t.Fatalf("释放之后第一个额度拿不到：%v", d1)
	}
	if d2 == denyNone {
		t.Error("上限 1 却同时放行了两个 —— 重复释放把额度凭空造出来了")
	}
}

// TestUnlimitedTunnelsAllocateNothing 钉住零成本路径。
//
// 绝大多数隧道不配限额。为它们分配一个状态对象、走一遍信号量，
// 是给「不用这个功能的人」加税。
func TestUnlimitedTunnelsAllocateNothing(t *testing.T) {
	reg := NewRegistry()
	tn := sharedTunnel("free", tunnel.TLSGateway, tunnel.RouterHTTP,
		"127.0.0.1:9", []string{"free.example.com"}, nil)

	if tl := reg.limitsFor(tn); tl != nil {
		t.Error("没配限额的隧道也建了状态对象")
	}
	if n := reg.trackedLimits(); n != 0 {
		t.Errorf("跟踪了 %d 条没配限额的隧道", n)
	}
	// nil 上调用必须安全（调用方无条件 defer release()）。
	var nilTL *tunnelLimits
	rel, d := nilTL.admit(netip.MustParseAddr("203.0.113.1"))
	if d != denyNone {
		t.Errorf("nil 限额却拒了请求：%v", d)
	}
	rel()
	if nilTL.bucket() != nil {
		t.Error("nil 限额却给出了一个限速器")
	}
	// nil 上的包装必须原样返回连接（不分配、不改变行为）。
	var c net.Conn
	if got := nilTL.throttle(context.Background(), c); got != c {
		t.Error("nil 限额却把连接包了一层")
	}
}

// doSized 打一个请求要 n 字节响应体，返回实际读到的字节数。
func doSized(t *testing.T, f *gwFixture, host string, n int) int {
	t.Helper()
	resp, err := f.client(false).Get(fmt.Sprintf("http://%s/api/bulk?n=%d", host, n))
	if err != nil {
		t.Fatalf("请求 %s 失败：%v", host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		t.Fatalf("请求 %s 回了 %d：%s", host, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	got, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatalf("读响应体失败：%v", err)
	}
	return int(got)
}

// TestSharedEntryLimitsTheUploadDirectionToo 补上一个变异验证抓出来的**盲区**。
//
// TestSharedEntryHonoursBytesPerSecond 只量下行（响应体）。把
// limitedConn 的写侧包装去掉之后那条测试**照样绿** —— 也就是说
// 「一个客户端把大文件 POST 进内网」这条路上限速可以静默失效，
// 而那正是最需要限的形态之一（上行打满家宽的上传带宽）。
//
// 两个方向必须各有一条测试。限速器本身是共享的（同一条隧道一个桶），
// 但**挂点**是两个：limitedConn.Read 与 limitedConn.Write。
func TestSharedEntryLimitsTheUploadDirectionToo(t *testing.T) {
	f := newGatewayFixture(t, true)

	const rate = 256 << 10
	const size = 3 * rate
	limitedShared(t, f, "up", "up.example.com", &tunnel.Policy{BytesPerSecond: rate})

	body := strings.NewReader(strings.Repeat("u", size))
	baseStart := time.Now()
	postSized(t, f, "api.example.com", strings.NewReader(strings.Repeat("u", size)))
	baseline := time.Since(baseStart)

	start := time.Now()
	postSized(t, f, "up.example.com", body)
	elapsed := time.Since(start)

	if elapsed < time.Second {
		t.Fatalf("上行 %d 字节过 %d B/s 只花了 %s（不限速基线 %s）—— "+
			"上行没被限速：只包了读侧",
			size, rate, elapsed.Round(time.Millisecond), baseline.Round(time.Millisecond))
	}
	t.Logf("上行限速生效：%s（不限速基线 %s）",
		elapsed.Round(time.Millisecond), baseline.Round(time.Millisecond))
}

// postSized 把一段内容 POST 过去，只关心它花了多久与有没有报错。
func postSized(t *testing.T, f *gwFixture, host string, body io.Reader) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+host+"/api/sink", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	resp, err := f.client(false).Do(req)
	if err != nil {
		t.Fatalf("POST %s 失败：%v", host, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s 回了 %d", host, resp.StatusCode)
	}
}

// TestSplicePathHonoursTunnelLimits 补上第二个盲区：**splice 路径压根没有测试**。
//
// 变异验证时我把 splice 里的并发闸门整个拿掉，测试**全绿** —— 因为
// `-run Splice` 一个测试都没匹配到，而 go test 匹配不到任何测试时退出码是 0。
// 那是一次「测试套件说没问题，其实那条路一行都没被跑过」。
//
// splice 路径（SNI 直通、明文/默认分支）与网关路径是**两套**挂点：
// 网关按请求算，splice 按连接算。只测一边等于只接了一半。
func TestSplicePathHonoursTunnelLimits(t *testing.T) {
	// 后端：接受连接后什么都不做，只挂着 —— 这样连接会一直占着额度。
	bln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bln.Close()
	held := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := bln.Accept()
			if err != nil {
				return
			}
			held <- c
		}
	}()

	agent := startFakeAgent(t, func(proto.StreamOpen) (net.Conn, error) {
		return net.Dial("tcp", bln.Addr().String())
	})
	sessions := sessionMap{"agent-1": agent.session("agent-1")}
	f := newDiscFixture(t, sessions, nil, nil)

	pt := sharedTunnel("ptlim", tunnel.TLSPassthrough, tunnel.RouterTLSSNI,
		bln.Addr().String(), []string{"ptlim.example.com"}, nil)
	pt.Policy = &tunnel.Policy{MaxConns: 1}
	if err := f.reg.AddShared(443, pt); err != nil {
		t.Fatal(err)
	}

	hello := clientHelloBytes(t, &tls.Config{
		ServerName: "ptlim.example.com", NextProtos: []string{"h2", "http/1.1"}})

	// 开两条连接。上限是 1，所以第二条必须被限额拒掉。
	for i := range 2 {
		near, far := net.Pipe()
		defer near.Close()
		defer far.Close()
		go func() { _, _ = far.Write(hello) }()
		go f.disc.Handle(t.Context(), near,
			netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), 443))
		_ = i
		time.Sleep(300 * time.Millisecond)
	}

	if got := f.disc.Stats().SpliceDeniedMaxConns.Load(); got == 0 {
		t.Fatalf("上限 1、开了两条 splice 连接，SpliceDeniedMaxConns 一次都没动 —— "+
			"splice 路径上 max_conns 没生效（拿到的后端连接数：%d）", len(held))
	}
	t.Logf("splice 路径的隧道限额生效：拒了 %d 次", f.disc.Stats().SpliceDeniedMaxConns.Load())
}

// spliceRig 起一条带限额的 SNI 直通隧道，并返回「开一条连接并收发字节」的工具。
//
// 直通路径上中继一个字节都不解析，所以这里的后端不是 HTTP 服务，
// 而是一段裸 TCP 逻辑：读掉 ClientHello，然后按测试的要求收发。
func spliceRig(t *testing.T, pol *tunnel.Policy, backend func(net.Conn)) func() net.Conn {
	t.Helper()

	bln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bln.Close() })
	go func() {
		for {
			c, err := bln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				backend(c)
			}()
		}
	}()

	agent := startFakeAgent(t, func(proto.StreamOpen) (net.Conn, error) {
		return net.Dial("tcp", bln.Addr().String())
	})
	f := newDiscFixture(t, sessionMap{"agent-1": agent.session("agent-1")}, nil, nil)

	pt := sharedTunnel("ptbw", tunnel.TLSPassthrough, tunnel.RouterTLSSNI,
		bln.Addr().String(), []string{"ptbw.example.com"}, nil)
	pt.Policy = pol
	if err := f.reg.AddShared(443, pt); err != nil {
		t.Fatal(err)
	}
	hello := clientHelloBytes(t, &tls.Config{
		ServerName: "ptbw.example.com", NextProtos: []string{"h2", "http/1.1"}})

	return func() net.Conn {
		near, far := net.Pipe()
		t.Cleanup(func() { _ = near.Close() })
		t.Cleanup(func() { _ = far.Close() })
		go f.disc.Handle(t.Context(), near,
			netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), 443))
		if _, err := far.Write(hello); err != nil {
			t.Fatalf("写 ClientHello 失败：%v", err)
		}
		return far
	}
}

// helloBudget 是 ClientHello 的长度上界，用来算「还要再收多少字节」。
//
// 取一个宽上界而不是精确长度：精确长度依赖 crypto/tls 的版本与扩展集，
// 钉住它会让这条测试在升级 Go 之后无端变红。
const helloBudget = 2048

// TestSpliceLimitsTheDownstreamDirection 钉住直通路径上**后端→客户端**的限速。
//
// 两个方向必须各有一条测试。变异验证抓出来的：只包一个方向时，
// 「总耗时超过下界」这个断言照样成立（另一向还在限），于是漏掉的那一向
// 完全不受限而测试全绿。
func TestSpliceLimitsTheDownstreamDirection(t *testing.T) {
	const rate = 256 << 10
	const size = 3 * rate

	dial := spliceRig(t, &tunnel.Policy{BytesPerSecond: rate}, func(c net.Conn) {
		// 读掉 ClientHello（内容不关心），然后往回灌 size 字节。
		buf := make([]byte, 16<<10)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Read(buf)
		_ = c.SetReadDeadline(time.Time{})
		payload := make([]byte, 32<<10)
		for left := size; left > 0; {
			k := min(left, len(payload))
			if _, err := c.Write(payload[:k]); err != nil {
				return
			}
			left -= k
		}
	})

	far := dial()
	_ = far.SetDeadline(time.Now().Add(60 * time.Second))
	start := time.Now()
	n, err := io.CopyN(io.Discard, far, size)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("读下行失败（读到 %d / %d）：%v", n, size, err)
	}
	if elapsed < time.Second {
		t.Fatalf("下行 %d 字节过 %d B/s 只花了 %s —— 直通路径的下行没被限速",
			size, rate, elapsed.Round(time.Millisecond))
	}
	t.Logf("直通下行限速生效：%s", elapsed.Round(time.Millisecond))
}

// TestSpliceLimitsTheUpstreamDirection 钉住直通路径上**客户端→后端**的限速。
//
// 这一向是「有人把大文件推进内网」，与下行是两个独立的挂点。
func TestSpliceLimitsTheUpstreamDirection(t *testing.T) {
	const rate = 256 << 10
	const size = 3 * rate

	got := make(chan int, 1)
	dial := spliceRig(t, &tunnel.Policy{BytesPerSecond: rate}, func(c net.Conn) {
		// 读掉 ClientHello，然后把后面的读完。
		//
		// **第一次 Read 会连载荷一起吞。** 它拿到的是「ClientHello + 恰好一起
		// 到达的那部分载荷」——一次 TCP 读最多能返回整个缓冲区。所以不能
		// 之后再要 size 个字节：那等于把已经收到的那一截又等一遍，
		// 于是测试卡到超时并报「字节少了」，看起来像限速在丢数据。
		//
		// 这条 1/3 概率的假失败是真的发生过的（786432 期望、771574 实收，
		// 差 14858 ≈ 16 KiB 缓冲减去 hello）。按**总量**收才对。
		buf := make([]byte, 16<<10)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n0, _ := c.Read(buf)
		_ = c.SetDeadline(time.Now().Add(60 * time.Second))
		n, _ := io.CopyN(io.Discard, c, int64(size+helloBudget-n0))
		got <- int(n) + n0
	})

	far := dial()
	_ = far.SetDeadline(time.Now().Add(60 * time.Second))
	payload := make([]byte, 32<<10)
	start := time.Now()
	for left := size; left > 0; {
		k := min(left, len(payload))
		if _, err := far.Write(payload[:k]); err != nil {
			t.Fatalf("写上行失败：%v", err)
		}
		left -= k
	}
	select {
	case n := <-got:
		elapsed := time.Since(start)
		// 收到的应当是 hello + size。只比 size 会把 hello 算成「多收」，
		// 只比总量又要知道 hello 的确切长度 —— 所以判「不少于 size」，
		// 那已经足够证明「一个载荷字节都没丢」。
		if n < size {
			t.Fatalf("后端只收到 %d 字节，少于载荷 %d —— 限速必须等而不是丢", n, size)
		}
		if elapsed < time.Second {
			t.Fatalf("上行 %d 字节过 %d B/s 只花了 %s —— 直通路径的上行没被限速",
				size, rate, elapsed.Round(time.Millisecond))
		}
		t.Logf("直通上行限速生效：%s", elapsed.Round(time.Millisecond))
	case <-time.After(60 * time.Second):
		t.Fatal("后端没收完上行字节")
	}
}

// TestEveryByteIsChargedExactlyOnce 钉住**双重计费**。
//
// # 为什么这条测试必须是确定性的，不能靠挂钟
//
// 双重计费与正确实现只差一个倍数：正确是 (3R−R)/R ≈ 2 秒，双扣是
// (6R−R)/R ≈ 5 秒。要靠挂钟区分就得设**上界**，而上界在 -race + 真 TCP
// 下不可靠 —— 本仓的限速测试通篇只用下界，理由写在 limiter_test.go 里。
//
// 所以改成数「结账了多少字节」：它必须**逐字节等于**载荷大小。
// 这条断言对倍数敏感、对机器速度完全不敏感。
//
// 这个失效形态不是假想的：我在这一轮真的写出过它 —— 把 splice 管道的两端
// 都包成受限连接，于是同一批字节先过一端的 Read 再过另一端的 Write，
// 被同一个桶算两次，有效带宽减半。「配了 1 Mbps 只跑 500 kbps」也是谎。
func TestEveryByteIsChargedExactlyOnce(t *testing.T) {
	const rate = 8 << 20 // 取高速率：这条测的是计费次数，不该顺带等两秒
	const size = 256 << 10

	t.Run("splice 双向", func(t *testing.T) {
		var tl *tunnelLimits
		got := make(chan int, 1)
		dial := spliceRigWith(t, &tunnel.Policy{BytesPerSecond: rate},
			func(_ *Registry, l *tunnelLimits) { tl = l },
			func(c net.Conn) {
				buf := make([]byte, 16<<10)
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				n0, _ := c.Read(buf) // ClientHello
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				n, _ := io.CopyN(io.Discard, c, size)
				got <- int(n) + n0
			})

		far := dial()
		_ = far.SetDeadline(time.Now().Add(30 * time.Second))
		payload := make([]byte, 32<<10)
		for left := size; left > 0; {
			k := min(left, len(payload))
			if _, err := far.Write(payload[:k]); err != nil {
				t.Fatalf("写上行失败：%v", err)
			}
			left -= k
		}
		select {
		case n := <-got:
			// 后端收到的 = ClientHello + size。结账的字节数必须与它一致。
			time.Sleep(300 * time.Millisecond) // 让最后一次结账落地
			charged := tl.metered.Load()
			if charged != int64(n) {
				t.Errorf("结账 %d 字节，实际搬了 %d 字节 —— 比值 %.2f。"+
					"大于 1 就是双重计费（有效带宽被减半），小于 1 就是有字节没过桶",
					charged, n, float64(charged)/float64(n))
			}
		case <-time.After(30 * time.Second):
			t.Fatal("后端没收完")
		}
	})
}

// spliceRigWith 与 spliceRig 相同，外加一个回调交出限额对象（供计费断言用）。
func spliceRigWith(t *testing.T, pol *tunnel.Policy,
	expose func(*Registry, *tunnelLimits), backend func(net.Conn),
) func() net.Conn {
	t.Helper()

	bln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bln.Close() })
	go func() {
		for {
			c, err := bln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); backend(c) }()
		}
	}()

	agent := startFakeAgent(t, func(proto.StreamOpen) (net.Conn, error) {
		return net.Dial("tcp", bln.Addr().String())
	})
	f := newDiscFixture(t, sessionMap{"agent-1": agent.session("agent-1")}, nil, nil)

	pt := sharedTunnel("ptonce", tunnel.TLSPassthrough, tunnel.RouterTLSSNI,
		bln.Addr().String(), []string{"ptonce.example.com"}, nil)
	pt.Policy = pol
	if err := f.reg.AddShared(443, pt); err != nil {
		t.Fatal(err)
	}
	expose(f.reg, f.reg.limitsFor(pt))

	hello := clientHelloBytes(t, &tls.Config{
		ServerName: "ptonce.example.com", NextProtos: []string{"h2", "http/1.1"}})

	return func() net.Conn {
		near, far := net.Pipe()
		t.Cleanup(func() { _ = near.Close() })
		t.Cleanup(func() { _ = far.Close() })
		go f.disc.Handle(t.Context(), near,
			netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), 443))
		if _, err := far.Write(hello); err != nil {
			t.Fatalf("写 ClientHello 失败：%v", err)
		}
		return far
	}
}

// TestALiveConnectionPicksUpANewRate 钉住评审指出的那个缺陷。
//
// # 缺陷是什么
//
// 第一版把桶捕获在连接包装里（`lim := tl.limiterOf()` 之后一直用它）。
// 于是一条长命连接 —— WebSocket、splice 出去的裸 TCP，都可以活几天 ——
// 会永远跑建立那一刻的速率。
//
// 而把 10 Mbps 调成 1 Mbps 的**典型动机恰恰是压住正在进行的滥用**。
// 那条连接不受影响，而详情页显示的是新值「已设置」——
// 正是这一整轮要消灭的那类谎的残留。
//
// 修法：包装持有每隧道那个**稳定对象**，桶每次读写现取。
//
// # 这条测试怎么做到不 flaky
//
// 断言的方向是「**还没**传完」而不是「传完了要多久」——那是一个下界，
// 机器慢只会让它更成立。
//
// 手法：先用一个高速率建连（第一块字节瞬间过去），中途把速率压到 1 KiB/s，
// 然后断言剩下的字节在 2 秒内**没有**送达。桶若被捕获在包装里，
// 那些字节会以旧的高速率瞬间送完 —— 于是断言失败。
func TestALiveConnectionPicksUpANewRate(t *testing.T) {
	const chunk = 16 << 10
	const total = 128 << 10

	var (
		tl  *tunnelLimits
		reg *Registry
	)
	got := make(chan int, 4)

	dial := spliceRigWith(t,
		// 先给一个很高的速率：对象因此存在，而第一块字节实际不受阻。
		&tunnel.Policy{BytesPerSecond: 64 << 20},
		func(r *Registry, l *tunnelLimits) { reg, tl = r, l },
		func(c net.Conn) {
			buf := make([]byte, chunk)
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, _ = c.Read(buf) // ClientHello
			_ = c.SetDeadline(time.Now().Add(60 * time.Second))
			n := 0
			for n < total {
				k, err := c.Read(buf)
				if k > 0 {
					n += k
					got <- n
				}
				if err != nil {
					return
				}
			}
		})

	far := dial()
	_ = far.SetDeadline(time.Now().Add(60 * time.Second))
	payload := make([]byte, chunk)

	// 第一块：高速率下应当很快到。
	if _, err := far.Write(payload); err != nil {
		t.Fatalf("写第一块失败：%v", err)
	}
	select {
	case n := <-got:
		t.Logf("高速率下第一块已送达（累计 %d 字节）", n)
	case <-time.After(5 * time.Second):
		t.Fatal("高速率下第一块都没送达，前置不成立")
	}

	// ── 中途把速率压到 1 KiB/s ──
	//
	// 走的是 applyShared 那条路：同一个隧道 ID、只改带宽 → 对象保住、桶换掉。
	pt := sharedTunnel("ptonce", tunnel.TLSPassthrough, tunnel.RouterTLSSNI,
		"127.0.0.1:9", []string{"ptonce.example.com"}, nil)
	pt.Policy = &tunnel.Policy{BytesPerSecond: 1 << 10}
	if same := reg.limitsFor(pt); same != tl {
		t.Fatal("只改带宽却换了限额对象 —— 那条已经建立的连接会继续跑旧桶")
	}

	// 继续推剩下的字节。
	go func() {
		for left := total - chunk; left > 0; {
			k := min(left, chunk)
			if _, err := far.Write(payload[:k]); err != nil {
				return
			}
			left -= k
		}
	}()

	// 1 KiB/s 下，剩下的 112 KiB 要一百多秒。所以两秒内**绝不**该传完。
	//
	// 桶被捕获时它会以 64 MiB/s 瞬间传完 —— 那时下面这个 select 会拿到
	// n >= total，断言失败。
	deadline := time.After(2 * time.Second)
	for {
		select {
		case n := <-got:
			if n >= total {
				t.Fatalf("中途压到 1 KiB/s 之后，剩下的字节仍然在两秒内全部送达"+
					"（累计 %d）—— 那条已经建立的连接还在跑旧桶。"+
					"而调低带宽的典型动机正是压住正在进行的滥用", n)
			}
		case <-deadline:
			t.Logf("新速率对已建立的连接生效了：两秒内没有传完（结账 %d 字节）",
				tl.metered.Load())
			return
		}
	}
}
