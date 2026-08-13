package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/carrier"
	"github.com/nomifun/nomifun-net-infra/internal/console"
	"github.com/nomifun/nomifun-net-infra/internal/gateway"
	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/relay"
	"github.com/nomifun/nomifun-net-infra/internal/store"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
	"github.com/nomifun/nomifun-net-infra/internal/udpflow"
)

// newTestRuntime 造一个带真实（临时）库的 runtime。
//
// 用真库而不是打桩：这里要断言的正是「事件到底有没有落进去」，
// 打桩会把被测的那一步替换掉。
func newTestRuntime(t *testing.T) *runtime {
	t.Helper()

	quiet := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	db, err := store.Open(store.Options{
		Path: filepath.Join(t.TempDir(), "rt.db"),
		Log:  quiet,
	})
	if err != nil {
		t.Fatalf("打开库失败：%v", err)
	}
	t.Cleanup(func() { db.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	return newRuntime(ctx, db, quiet, "test", "127.0.0.1:0", "pin")
}

func TestDesktopTunnelURL(t *testing.T) {
	if got := desktopTunnelURL("relay.example.com", 19090); got != "http://relay.example.com:19090" {
		t.Fatalf("desktopTunnelURL = %q", got)
	}
	if got := desktopTunnelURL("2001:db8::1", 19090); got != "http://[2001:db8::1]:19090" {
		t.Fatalf("IPv6 desktopTunnelURL = %q", got)
	}
	if got := desktopTunnelURL("", 19090); got != "" {
		t.Fatalf("empty host should produce empty URL, got %q", got)
	}
}

// countDenied 数一下库里有几条拨号期否决事件。
func countDenied(t *testing.T, rt *runtime) int {
	t.Helper()

	events, err := rt.db.ListEvents(rt.ctx, 200, 0)
	if err != nil {
		t.Fatalf("读事件失败：%v", err)
	}
	n := 0
	for _, e := range events {
		if e.Kind == store.KindStreamDenied {
			n++
		}
	}
	return n
}

func TestStreamDeniedEventsAreDedupedPerTunnelAndCode(t *testing.T) {
	// 一条配置错了的隧道会让**每一条**用户连接都被拒一次。一个刷新不停的
	// 页面几秒钟就能写进上千条一模一样的事件，把真正有用的事件挤出可视范围。
	// 事件流的价值在信噪比，所以这里必须去重。
	rt := newTestRuntime(t)

	for range 50 {
		rt.noteStreamDenied("t-1", "target_denied", "目标被本地策略否决")
	}
	if n := countDenied(t, rt); n != 1 {
		t.Fatalf("同隧道同码的 50 次否决应当只写 1 条事件，实际 %d 条", n)
	}

	// 不同错误码是**不同的**问题，不能被彼此的去重窗口吞掉 ——
	// 否则用户改完策略后遇到的新问题（比如本地服务没起）就看不见了。
	rt.noteStreamDenied("t-1", "internal", "拨本地目标失败")
	if n := countDenied(t, rt); n != 2 {
		t.Fatalf("不同错误码应当各自成条，实际 %d 条", n)
	}

	// 不同隧道同理。
	rt.noteStreamDenied("t-2", "target_denied", "另一条隧道")
	if n := countDenied(t, rt); n != 3 {
		t.Fatalf("不同隧道应当各自成条，实际 %d 条", n)
	}
}

func TestStreamDeniedEventsResumeAfterTheDedupWindow(t *testing.T) {
	// 去重不能变成永久静音：用户改了策略再试一次，必须能看到新事件，
	// 否则他无法判断「我改的有没有生效」。
	rt := newTestRuntime(t)

	rt.noteStreamDenied("t-1", "target_denied", "第一次")
	if n := countDenied(t, rt); n != 1 {
		t.Fatalf("首次应当写 1 条，实际 %d 条", n)
	}

	// 把上次时间往回拨到窗口之外，模拟时间流逝而不真的等一分钟。
	rt.mu.Lock()
	rt.deniedSeen["t-1|target_denied"] = time.Now().Add(-2 * streamDeniedDedupWindow)
	rt.mu.Unlock()

	rt.noteStreamDenied("t-1", "target_denied", "改完策略又试了一次")
	if n := countDenied(t, rt); n != 2 {
		t.Fatalf("超出去重窗口后应当再写一条，实际 %d 条", n)
	}
}

func TestStreamDeniedDedupTableDoesNotGrowWithoutBound(t *testing.T) {
	// 这张表的键是 tunnelID|code 的组合，随隧道增删会不断产生新键。
	// 没有清理的话它就是一个慢速内存泄漏 —— 中继是长期运行的进程。
	rt := newTestRuntime(t)

	// 灌一批已经很旧的条目。
	rt.mu.Lock()
	for i := range 100 {
		rt.deniedSeen[string(rune('a'+i%26))+"|old"+string(rune('0'+i%10))] =
			time.Now().Add(-100 * streamDeniedDedupWindow)
	}
	before := len(rt.deniedSeen)
	rt.mu.Unlock()
	if before < 50 {
		t.Fatalf("测试前置条件不成立：只灌进去 %d 条", before)
	}

	// 任意一次调用都会顺手清掉过期条目。
	rt.noteStreamDenied("t-new", "target_denied", "触发一次清理")

	rt.mu.RLock()
	after := len(rt.deniedSeen)
	rt.mu.RUnlock()
	// 只剩刚写进去的那一条。
	if after != 1 {
		t.Fatalf("过期条目应当被清掉，只留新写的 1 条，实际剩 %d 条", after)
	}
}

func TestSessionForRejectsTheEmptyAgentID(t *testing.T) {
	// 空 agent_id **只**表示「中继自己拨号」，不再被解释为「任意在线 agent」。
	//
	// 第一版把空值当作单 agent 部署的便利，于是同一个值有了两种含义：
	// 库里存空值，控制台按规格渲染成「中继直拨」，运行时却悄悄派给了
	// 某个 agent —— 界面与实际行为对不上。这是看浏览器截图发现的。
	rt := newTestRuntime(t)

	if _, ok := rt.SessionFor(""); ok {
		t.Fatal("空 agent_id 不该匹配到任何会话 —— 那个二义性是已修的缺陷")
	}
}

func TestRefreshStatesTellsTheTruthWhenNoAgentIsOnline(t *testing.T) {
	// 状态谎报比报错更糟：控制台显示 active，而实际连接会被干净拒掉，
	// 用户会先去查网络而不是查 agent。
	rt := newTestRuntime(t)

	tn := &tunnel.Tunnel{
		ID:         "t-1",
		TenantID:   tunnel.DefaultTenantID,
		Slug:       "phone-api",
		AgentID:    "agent-1", // 已绑定，但没有任何会话在线
		ListenPort: 19099,
		Backend:    tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
	}
	tn.Complete()
	if err := rt.db.PutTunnel(rt.ctx, tn); err != nil {
		t.Fatalf("建隧道失败：%v", err)
	}

	rt.RefreshStates()

	got, err := rt.db.GetTunnel(rt.ctx, "t-1")
	if err != nil {
		t.Fatalf("读隧道失败：%v", err)
	}
	if got.State != tunnel.StateDegraded {
		t.Fatalf("绑定的 agent 不在线时状态应为 %s，实际 %s（原因：%s）",
			tunnel.StateDegraded, got.State, got.StateReason)
	}
	if got.StateReason == "" {
		t.Error("降级必须带原因 —— 只给一个状态词等于让用户自己猜")
	}
}

func TestRepeatedApplyDoesNotRebuildLiveEntries(t *testing.T) {
	// ApplyTunnels 会被反复调用（控制台改配置、每次 agent 上线各一次）。
	// 若它把已有入口关掉重建，活跃的音视频流就会断、计数器归零、
	// 端口还有一个未绑定的窗口在丢包。
	//
	// 这个缺陷真实存在过：addrPort 只认 *net.TCPAddr，对 UDP 返回 0，
	// 于是「端口变了吗」的判据恒为真。真实进程验证时靠「UDP 入口已就绪」
	// 打了两遍才发现 —— 单看功能是通的，8/8 往返成功。
	rt := newTestRuntime(t)

	udp := &tunnel.Tunnel{
		ID: "t-udp", TenantID: tunnel.DefaultTenantID, Slug: "udp-media",
		L4: tunnel.L4UDP, ListenPort: 0, // 0 让系统分配，避免测试间端口冲突
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:5004"},
	}
	udp.Complete()
	tcp := &tunnel.Tunnel{
		ID: "t-tcp", TenantID: tunnel.DefaultTenantID, Slug: "phone-api",
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
	}
	tcp.Complete()

	// ListenPort 为 0 的隧道不会被绑定（那是「未分配端口」的意思），
	// 所以这里先各自占一个真实端口。
	udpPort, tcpPort := freePort(t, "udp"), freePort(t, "tcp")
	udp.ListenPort = udpPort
	tcp.ListenPort = tcpPort

	for _, tn := range []*tunnel.Tunnel{udp, tcp} {
		if err := rt.db.PutTunnel(rt.ctx, tn); err != nil {
			t.Fatalf("建隧道 %s 失败：%v", tn.Slug, err)
		}
	}

	applyTunnelsWithRetry(t, rt, "t-udp", "t-tcp")

	rt.mu.RLock()
	firstUDP := rt.dgrams["t-udp"]
	firstTCP := rt.entries["t-tcp"]
	rt.mu.RUnlock()
	if firstUDP == nil {
		t.Fatal("UDP 入口没有被建起来")
	}
	if firstTCP == nil {
		t.Fatal("TCP 入口没有被建起来")
	}

	// 再应用两次，什么都没改。
	for i := range 2 {
		if err := rt.ApplyTunnels(); err != nil {
			t.Fatalf("第 %d 次重复应用失败：%v —— 端口已经绑住了，这次不该失败", i+2, err)
		}
	}

	rt.mu.RLock()
	againUDP := rt.dgrams["t-udp"]
	againTCP := rt.entries["t-tcp"]
	rt.mu.RUnlock()

	// 必须是**同一个对象**：新建一个就意味着旧的被关掉了。
	if againUDP != firstUDP {
		t.Error("UDP 入口被重建了 —— 活跃的媒体流会因此中断")
	}
	if againTCP != firstTCP {
		t.Error("TCP 入口被重建了")
	}

	// 解复用器里也必须只有一份。
	frame, err := udpflow.Header{
		Tunnel: udp.ShortID, FlowID: 1, DstPort: udpPort,
	}.AppendTo(nil, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	rt.DatagramRouter().Dispatch("agent-1", frame)
	if _, unrouted := rt.DatagramRouter().Stats(); unrouted != 0 {
		t.Errorf("入口应当仍在解复用器里注册着，unrouted=%d", unrouted)
	}
}

func TestUDPTunnelReachesActiveWithoutTheOldNotWiredError(t *testing.T) {
	// 曾经的行为是把每条 UDP 隧道直接标成 error「UDP 入口尚未接线」。
	// 接线之后必须真的变成可用状态，否则控制台还在劝用户别用。
	rt := newTestRuntime(t)

	udp := &tunnel.Tunnel{
		ID: "t-udp", TenantID: tunnel.DefaultTenantID, Slug: "udp-media",
		L4: tunnel.L4UDP, ListenPort: freePort(t, "udp"),
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:5004"},
	}
	udp.Complete()
	if err := rt.db.PutTunnel(rt.ctx, udp); err != nil {
		t.Fatal(err)
	}
	applyTunnelsWithRetry(t, rt, "t-udp")

	got, err := rt.db.GetTunnel(rt.ctx, "t-udp")
	if err != nil {
		t.Fatal(err)
	}
	if got.State == tunnel.StateError {
		t.Fatalf("UDP 隧道不该再是 error 状态：%s", got.StateReason)
	}
	if got.ShortID == 0 {
		t.Fatal("UDP 隧道必须有短标识，否则解复用会错位")
	}
}

// freePort 取一个当前空闲的端口。
//
// 让内核挑而不是写死数字：写死的端口会让并行测试互相抢。
//
// 注意这里有个**无法消除**的 TOCTOU：探到端口、关掉探测 socket、
// 真正去绑，这三步之间别的进程（或 go test 并行跑的其他包）可能抢走它。
// 所以凡是要真的绑上去的地方都必须用 applyTunnelsWithRetry，
// 不能假设探到的端口一定还能绑 —— 我就是靠一次无法复现的 make check
// 失败才想到这一点，而「跑不出来」不是结论。
func freePort(t *testing.T, network string) uint16 {
	t.Helper()
	if network == "udp" {
		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		return uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// applyTunnelsWithRetry 应用隧道，遇到端口被抢就换一个端口重试。
//
// 存在的理由见 freePort 的说明：端口是共享资源，探到不等于绑得上。
// 重试而不是放宽断言 —— 我们要测的行为一点都不能少测，
// 只是不该因为环境里另一个进程抢了端口就报失败。
func applyTunnelsWithRetry(t *testing.T, rt *runtime, ids ...string) {
	t.Helper()

	for attempt := range 5 {
		err := rt.ApplyTunnels()
		if err == nil {
			return
		}
		if attempt == 4 {
			t.Fatalf("应用隧道连续 5 次失败，最后一次：%v", err)
		}
		t.Logf("应用隧道失败（可能是端口被抢），换端口重试：%v", err)
		for _, id := range ids {
			tn, gErr := rt.db.GetTunnel(rt.ctx, id)
			if gErr != nil {
				t.Fatalf("重试时读隧道 %s 失败：%v", id, gErr)
			}
			network := "tcp"
			if tn.L4 == tunnel.L4UDP {
				network = "udp"
			}
			tn.ListenPort = freePort(t, network)
			if pErr := rt.db.PutTunnel(rt.ctx, tn); pErr != nil {
				t.Fatalf("重试时写隧道 %s 失败：%v", id, pErr)
			}
		}
	}
}

func TestSnapshotReportsUDPEntryCountersNotZeroes(t *testing.T) {
	// 漏读 UDP 入口的计数器是**静默错误**：隧道明明在传数据，控制台上流量
	// 却永远是 0。而 README 自己写着「0 会被读成『测过，是零』」——
	// 用户会去查客户端，而问题根本不在那里。
	//
	// 这条缺陷真实存在过：Snapshot 只读 rt.entries（TCP），从不读 rt.dgrams。
	rt := newTestRuntime(t)

	udp := &tunnel.Tunnel{
		ID: "t-udp", TenantID: tunnel.DefaultTenantID, Slug: "udp-media",
		L4: tunnel.L4UDP, ListenPort: freePort(t, "udp"),
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:5004"},
	}
	udp.Complete()
	if err := rt.db.PutTunnel(rt.ctx, udp); err != nil {
		t.Fatal(err)
	}
	applyTunnelsWithRetry(t, rt, "t-udp")

	rt.mu.RLock()
	de := rt.dgrams["t-udp"]
	rt.mu.RUnlock()
	if de == nil {
		t.Fatal("UDP 入口没建起来")
	}

	// 手动把计数器推到非零，模拟已经跑过流量。
	//
	// 直接改计数器而不是真发包：这条测试要证的是「快照读了这些字段」，
	// 而「发包会让计数器动」已由 internal/relay 的测试覆盖。
	// 每个字段给一个**不同**的值，才能抓出「读错字段」这种错误 ——
	// 全填 1 的话把 BytesIn 读成 BytesOut 也测不出来。
	de.Stats().Flows.Store(3)
	de.Stats().BytesIn.Store(1000)
	de.Stats().BytesOut.Store(2000)
	de.Stats().PacketsIn.Store(11)
	de.Stats().PacketsOut.Store(22)
	de.Stats().DeniedCIDR.Store(4)
	de.Stats().NoSession.Store(5)
	de.Stats().NoDatagram.Store(6)
	de.Stats().RateLimited.Store(7)
	de.Stats().TableFull.Store(8)
	de.Stats().PerIPQuota.Store(9)
	de.Stats().UnknownFlow.Store(10)

	snap := rt.Snapshot()
	var got *console.TunnelStatus
	for i := range snap.Tunnels {
		if snap.Tunnels[i].ID == "t-udp" {
			got = &snap.Tunnels[i]
		}
	}
	if got == nil {
		t.Fatal("快照里没有这条隧道")
	}

	checks := []struct {
		name string
		got  int64
		want int64
	}{
		{"Sessions（活跃流数）", got.Sessions, 3},
		{"BytesIn", got.BytesIn, 1000},
		{"BytesOut", got.BytesOut, 2000},
		{"PacketsIn", got.PacketsIn, 11},
		{"PacketsOut", got.PacketsOut, 22},
		{"DeniedCIDR", got.DeniedCIDR, 4},
		{"NoSession", got.NoSession, 5},
		{"OpenFailed（UDP 上是「承载不支持数据报」）", got.OpenFailed, 6},
		{"RateLimited", got.RateLimited, 7},
		{"DroppedTableFull", got.DroppedTableFull, 8},
		{"DroppedPerIPQuota", got.DroppedPerIPQuota, 9},
		{"DroppedUnknownFlow", got.DroppedUnknownFlow, 10},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s 应为 %d，实际 %d", c.name, c.want, c.got)
		}
	}

	// 总计也要把 UDP 算进去，否则概览页的吞吐磁贴会漏掉 UDP 流量。
	if snap.Totals.BytesIn < 1000 || snap.Totals.BytesOut < 2000 {
		t.Errorf("总计应当包含 UDP 流量，实际 in=%d out=%d",
			snap.Totals.BytesIn, snap.Totals.BytesOut)
	}
}

func TestCloseEntriesReleasesUDPPortsToo(t *testing.T) {
	// 漏关 UDP 入口的后果：优雅关闭时端口仍在监听、仍在收包，而这些包会被
	// 送给一个正在断开的会话；且端口不释放会让紧接着的重启绑定失败。
	rt := newTestRuntime(t)

	port := freePort(t, "udp")
	udp := &tunnel.Tunnel{
		ID: "t-udp", TenantID: tunnel.DefaultTenantID, Slug: "udp-media",
		L4: tunnel.L4UDP, ListenPort: port,
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:5004"},
	}
	udp.Complete()
	if err := rt.db.PutTunnel(rt.ctx, udp); err != nil {
		t.Fatal(err)
	}
	applyTunnelsWithRetry(t, rt, "t-udp")

	// 重试可能换过端口，从库里取当前值。
	cur, err := rt.db.GetTunnel(rt.ctx, "t-udp")
	if err != nil {
		t.Fatal(err)
	}
	port = cur.ListenPort

	// 端口现在应当被占着。
	if pc, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)}); err == nil {
		pc.Close()
		t.Fatal("测试前置条件不成立：入口应当已经绑住这个端口")
	}

	rt.closeEntries()

	// 关闭后必须能重新绑上 —— 这就是「端口真的释放了」的判据。
	waitForPortFree(t, port)
}

// waitForPortFree 等一个 UDP 端口变为可绑。
func waitForPortFree(t *testing.T, port uint16) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		pc, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
		if err == nil {
			pc.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("端口 %d 在关闭后仍未释放 —— 重启会绑定失败", port)
}

func TestSharedEntryRoutesByHostAndRebuildsRoutesOnReload(t *testing.T) {
	// internal/gateway 有 14 个文件与全套测试，但在这次改动之前
	// **生产路径上一个调用点都没有** —— 与 internal/udpflow 之前的处境
	// 完全一样。这条测试钉住「它真的被接上了」。
	rt := newTestRuntime(t)

	// 共享入口用 :0 让内核挑端口。
	if err := rt.startShared("127.0.0.1:0", nil, nil, nil, false); err != nil {
		t.Fatalf("起共享入口失败：%v", err)
	}
	defer rt.closeShared()

	rt.mu.RLock()
	sh := rt.shared
	rt.mu.RUnlock()
	if sh == nil {
		t.Fatal("共享入口没有被记录到 runtime 上")
	}
	if sh.port == 0 {
		t.Fatal("共享入口没拿到端口")
	}

	// 一条共享隧道，按 Host 路由。
	shared := &tunnel.Tunnel{
		ID: "t-shared", TenantID: tunnel.DefaultTenantID, Slug: "web",
		Exposure: tunnel.ExposureShared,
		TLS:      tunnel.TLSGateway,
		Router: &tunnel.Router{
			Kind:    tunnel.RouterHTTP,
			Domains: []string{"web.example.com"},
		},
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
	}
	shared.Complete()
	if err := rt.db.PutTunnel(rt.ctx, shared); err != nil {
		t.Fatal(err)
	}
	if err := rt.ApplyTunnels(); err != nil {
		t.Fatalf("应用失败：%v", err)
	}

	// 路由表里应当能查到这个域名。
	view, ok := sh.reg.View(sh.port)
	if !ok {
		t.Fatal("路由表里没有这个端口的绑定")
	}
	if got, ok := view.Hosts.MatchHost("web.example.com"); !ok {
		t.Fatal("按 Host 查不到刚建的共享隧道 —— 路由表没被同步")
	} else if got.Tunnel.ID != "t-shared" {
		t.Fatalf("匹配到了错误的隧道：%s", got.Tunnel.ID)
	}

	// 删掉隧道后路由必须消失。
	//
	// 全量重建的关键判据就在这里：增量 diff 最容易漏的正是删除路径，
	// 表现为「隧道删了但流量还在往旧后端走」。
	if err := rt.db.DeleteTunnel(rt.ctx, "t-shared"); err != nil {
		t.Fatal(err)
	}
	if err := rt.ApplyTunnels(); err != nil {
		t.Fatal(err)
	}
	view2, ok := sh.reg.View(sh.port)
	if ok {
		if _, still := view2.Hosts.MatchHost("web.example.com"); still {
			t.Fatal("隧道已删除，路由却还在 —— 流量会继续走向旧后端")
		}
	}

	// 共享入口本身必须还活着：一个监听器服务任意多条隧道，
	// 删掉最后一条隧道不该关掉端口。
	rt.mu.RLock()
	stillThere := rt.shared
	rt.mu.RUnlock()
	if stillThere == nil {
		t.Fatal("删掉最后一条共享隧道不该关掉共享入口")
	}
	c, err := net.DialTimeout("tcp", sh.ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("共享端口应当仍在监听：%v", err)
	}
	c.Close()
}

func TestSharedEntryIsNotStartedWithoutTheFlag(t *testing.T) {
	// 默认不启用：共享入口要占 443，而那是个需要用户明确同意的决定。
	rt := newTestRuntime(t)
	if err := rt.startShared("", nil, nil, nil, false); err != nil {
		t.Fatalf("不启用时不该报错：%v", err)
	}
	rt.mu.RLock()
	sh := rt.shared
	rt.mu.RUnlock()
	if sh != nil {
		t.Fatal("没给地址时不该起监听器")
	}
	// 未启用时 applyShared 必须是无害的空操作，而不是 panic。
	rt.applyShared(nil)
	rt.closeShared()
}

func TestSharedTunnelWithoutDomainsBecomesThePortDefault(t *testing.T) {
	// 场景二在共享端口上的路径：ESP32 只填「中继 IP + 端口」，不发 SNI，
	// Host 是 IP 字面量甚至缺失 —— 没有任何域名可匹配。
	//
	// gateway.resolve 早就有 Fallback 分支，但在这次改动之前**没有任何方式
	// 能设置它**：AddShared 遇到空域名列表时循环一次都不执行，
	// 于是返回 nil 而注册了零条路由 —— 用户建了隧道什么都没发生，
	// 界面还显示 active。这是「只被测试引用的导出标识符」扫描抓出来的：
	// BindDefault 从未被生产代码调用过。
	rt := newTestRuntime(t)
	if err := rt.startShared("127.0.0.1:0", nil, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	defer rt.closeShared()

	rt.mu.RLock()
	sh := rt.shared
	rt.mu.RUnlock()

	catchAll := &tunnel.Tunnel{
		ID: "t-catch", TenantID: tunnel.DefaultTenantID, Slug: "robot",
		Exposure: tunnel.ExposureShared,
		// 明文 HTTP 路由要读 Host，所以必须是 gateway 模式 —— 校验会强制这一条。
		// 场景二的 ESP32 正是发明文 HTTP。
		TLS: tunnel.TLSGateway,
		// 显式 catch_all，而不是靠「域名列表为空」暗示。
		Router:  &tunnel.Router{Kind: tunnel.RouterHTTP, CatchAll: true},
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
	}
	catchAll.Complete()
	if err := rt.db.PutTunnel(rt.ctx, catchAll); err != nil {
		t.Fatal(err)
	}
	if err := rt.ApplyTunnels(); err != nil {
		t.Fatal(err)
	}

	view, ok := sh.reg.View(sh.port)
	if !ok {
		t.Fatal("路由表里没有这个端口的绑定")
	}
	if view.Fallback == nil {
		t.Fatal("无域名的共享隧道应当成为端口默认落点 —— 否则场景二在共享端口上无路可走")
	}
	if view.Fallback.ID != "t-catch" {
		t.Fatalf("默认落点应当是 t-catch，实际 %s", view.Fallback.ID)
	}

	// 状态不该是 error（它是合法配置，不是坏配置）。
	got, err := rt.db.GetTunnel(rt.ctx, "t-catch")
	if err != nil {
		t.Fatal(err)
	}
	if got.State == tunnel.StateError {
		t.Fatalf("无域名的共享隧道是合法配置，不该是 error：%s", got.StateReason)
	}

	// 两条默认落点必须冲突并如实报错，而不是后一条静默覆盖前一条。
	second := &tunnel.Tunnel{
		ID: "t-catch2", TenantID: tunnel.DefaultTenantID, Slug: "robot2",
		Exposure: tunnel.ExposureShared,
		TLS:      tunnel.TLSGateway,
		Router:   &tunnel.Router{Kind: tunnel.RouterHTTP, CatchAll: true},
		Backend:  tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8081"},
	}
	second.Complete()
	if err := rt.db.PutTunnel(rt.ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := rt.ApplyTunnels(); err != nil {
		t.Fatal(err)
	}

	// 其中一条必须被标成 error 并说明原因。
	var errored int
	for _, id := range []string{"t-catch", "t-catch2"} {
		g, err := rt.db.GetTunnel(rt.ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if g.State == tunnel.StateError {
			errored++
			if g.StateReason == "" {
				t.Errorf("%s 被标成 error 但没有原因", id)
			}
		}
	}
	if errored == 0 {
		t.Fatal("两条默认落点应当冲突并有一条被标成 error —— 静默覆盖会让用户以为两条都生效了")
	}
}

func TestAddSharedRefusesEmptyDomainListLoudly(t *testing.T) {
	// AddShared 遇到空域名列表时那个双层循环一次都不执行，
	// 于是它会返回 nil 而注册了零条路由 —— 调用方以为成功了。
	// 这类「静默无操作」是本仓库认定最坏的一类缺陷。
	reg := gateway.NewRegistry()
	tn := &tunnel.Tunnel{
		ID: "t", Slug: "x", Exposure: tunnel.ExposureShared, TLS: tunnel.TLSGateway,
		Router:  &tunnel.Router{Kind: tunnel.RouterHTTP}, // 无域名
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:1"},
	}
	tn.Complete()

	if err := reg.AddShared(443, tn); err == nil {
		t.Fatal("空域名列表应当报错，而不是静默注册零条路由")
	}
}

// stateOf 读一条隧道当前的状态与原因。
func stateOf(t *testing.T, rt *runtime, id string) (tunnel.State, string) {
	t.Helper()
	tn, err := rt.db.GetTunnel(rt.ctx, id)
	if err != nil {
		t.Fatalf("读隧道 %s 失败：%v", id, err)
	}
	return tn.State, tn.StateReason
}

func TestChangingL4FromTCPToUDPClosesTheOldTCPListener(t *testing.T) {
	// 把一条已上线的端口型隧道从 tcp 改成 udp 之后，绑定循环会去建 UDP 入口，
	// 而**旧的 TCP 监听器一直留着并继续把连接代理到后端**。
	// 用户以为自己换了协议，实际是同一个端口上多了一条没人知道的 TCP 通路。
	rt := newTestRuntime(t)

	port := freePort(t, "tcp")
	tn := &tunnel.Tunnel{
		ID: "t-1", TenantID: tunnel.DefaultTenantID, Slug: "switch-l4",
		ListenPort: port,
		Backend:    tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
	}
	tn.Complete()
	if err := rt.db.PutTunnel(rt.ctx, tn); err != nil {
		t.Fatal(err)
	}
	applyTunnelsWithRetry(t, rt, "t-1")

	rt.mu.RLock()
	el := rt.entries["t-1"]
	rt.mu.RUnlock()
	if el == nil {
		t.Fatal("TCP 入口没建起来，测试前置条件不成立")
	}

	// 控制台把它改成 UDP（端口不变，这是最自然的操作）。
	tn.L4 = tunnel.L4UDP
	if err := rt.db.PutTunnel(rt.ctx, tn); err != nil {
		t.Fatal(err)
	}
	_ = rt.ApplyTunnels()

	rt.mu.RLock()
	stillTCP := rt.entries["t-1"]
	rt.mu.RUnlock()
	if stillTCP != nil {
		t.Fatal("改成 UDP 之后旧的 TCP 监听器还在 —— " +
			"同一个端口上多了一条没人知道的 TCP 通路，还在往后端代理")
	}
	// 端口应当已经被释放（或被新的 UDP 入口占用），总之不该还有人在听 TCP。
	if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)),
		300*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("旧 TCP 端口仍然可连")
	}
}

func TestEntryBindFailureReasonSurvivesRefreshStates(t *testing.T) {
	// refreshStates 从零重算状态、不知道谁绑失败过，于是它会把
	// 「端口被占，error」覆盖成「端口已监听，等待代理端上线」——
	// 那句话本身是假的，端口根本没有监听。
	rt := newTestRuntime(t)

	// 先自己占住一个端口，让中继绑不上。
	squat, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer squat.Close()
	port := uint16(squat.Addr().(*net.TCPAddr).Port)

	tn := &tunnel.Tunnel{
		ID: "t-1", TenantID: tunnel.DefaultTenantID, Slug: "occupied",
		ListenPort: port,
		Backend:    tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
	}
	tn.Complete()
	if err := rt.db.PutTunnel(rt.ctx, tn); err != nil {
		t.Fatal(err)
	}
	_ = rt.ApplyTunnels() // 预期失败

	state, reason := stateOf(t, rt, "t-1")
	if state != tunnel.StateError {
		t.Fatalf("端口被占时状态应当是 error，实际 %s（原因：%q）—— "+
			"报 pending/active 等于告诉用户「端口已监听」，而它没有", state, reason)
	}
	if reason == "" {
		t.Fatal("必须带上绑定失败的原因，否则用户只看到「不通」")
	}

	// 再刷一次状态（agent 上下线会走这条路）——原因不能被冲掉。
	rt.RefreshStates()
	state, reason2 := stateOf(t, rt, "t-1")
	if state != tunnel.StateError || reason2 != reason {
		t.Fatalf("刷新状态把绑定失败的原因冲掉了：%s / %q", state, reason2)
	}

	// 快照里也要看得到。
	snap := rt.Snapshot()
	for _, ts := range snap.Tunnels {
		if ts.ID == "t-1" && (ts.State != string(tunnel.StateError) || ts.Reason == "") {
			t.Fatalf("快照里状态不对：%s / %q", ts.State, ts.Reason)
		}
	}
}

func TestSharedTunnelWithoutSharedEntryIsNotReportedActive(t *testing.T) {
	// exposure=shared 但中继没启用 -shared：**一个监听器都没有**，
	// 而它原本会被报成 active —— curl 过去直接连不上。
	//
	// 必须断言 error 而不只是「不是 active」：不加这条判定时它会落到
	// 「pending / 端口已监听，等待代理端上线」——那句话本身是假的，
	// 而 pending 还会让用户以为「再等等就好了」。
	// 我第一版的断言正是只查 active，于是变异测试是绿的。
	rt := newTestRuntime(t)

	shared := &tunnel.Tunnel{
		ID: "t-shared", TenantID: tunnel.DefaultTenantID, Slug: "no-shared",
		Kind: tunnel.KindService, TLS: tunnel.TLSGateway,
		Exposure: tunnel.ExposureShared, L4: tunnel.L4TCP,
		Router:  &tunnel.Router{Kind: tunnel.RouterHTTP, Domains: []string{"a.example.com"}},
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
	}
	shared.Complete()
	if err := rt.db.PutTunnel(rt.ctx, shared); err != nil {
		t.Fatal(err)
	}

	// 注意：**没有**调用 startShared。
	_ = rt.ApplyTunnels()

	state, reason := stateOf(t, rt, "t-shared")
	if state != tunnel.StateError {
		t.Errorf("状态是 %s（原因 %q）—— 中继一个监听器都没为它开，"+
			"只有 error 是诚实的", state, reason)
	}
	if strings.Contains(reason, "端口已监听") {
		t.Errorf("原因说「端口已监听」，而它没有：%q", reason)
	}
}

func TestRelayAssignsAndPersistsAPortWhenListenPortIsZero(t *testing.T) {
	// `ListenPort` 的注释一直写着「0 表示由中继分配」——而那件事**没有实现**：
	// 绑定循环直接跳过 listen_port=0 的隧道，于是一个监听器都没有。
	// 注释承诺了一个不存在的行为，那比没有这个功能更糟。
	//
	// 分配之后**必须回写库**：不回写的话重启会换一个端口，
	// 而 exposure=port 的客户端是拿端口号硬配的（场景二的设备写在固件里）——
	// 换端口等于让所有客户端同时失联。「由中继分配」的意思是
	// 「你不用挑，但挑定了就不再变」。
	rt := newTestRuntime(t)

	for _, tn := range []*tunnel.Tunnel{
		{
			ID: "t-tcp", TenantID: tunnel.DefaultTenantID, Slug: "auto-tcp",
			ListenPort: 0,
			Backend:    tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
		},
		{
			ID: "t-udp", TenantID: tunnel.DefaultTenantID, Slug: "auto-udp",
			L4: tunnel.L4UDP, ListenPort: 0,
			Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:5004"},
		},
	} {
		tn.Complete()
		if err := rt.db.PutTunnel(rt.ctx, tn); err != nil {
			t.Fatal(err)
		}
	}

	_ = rt.ApplyTunnels()

	assigned := map[string]uint16{}
	for _, id := range []string{"t-tcp", "t-udp"} {
		cur, err := rt.db.GetTunnel(rt.ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if cur.ListenPort == 0 {
			t.Fatalf("%s 的端口没有被分配 —— 「0 表示由中继分配」那句注释仍然是假的", id)
		}
		assigned[id] = cur.ListenPort

		// 入口必须真的在监听那个端口。
		rt.mu.RLock()
		el, de := rt.entries[id], rt.dgrams[id]
		rt.mu.RUnlock()
		switch {
		case el != nil:
			if got := addrPort(el.Addr()); got != cur.ListenPort {
				t.Errorf("%s 库里记的是 %d，实际监听 %d", id, cur.ListenPort, got)
			}
		case de != nil:
			if got := addrPort(de.Addr()); got != cur.ListenPort {
				t.Errorf("%s 库里记的是 %d，实际监听 %d", id, cur.ListenPort, got)
			}
		default:
			t.Errorf("%s 分配了端口却没有入口在监听", id)
		}

		// 状态不该再是「分配失败」。
		if state, reason := stateOf(t, rt, id); state == tunnel.StateError {
			t.Errorf("%s 分配成功后不该是 error：%s", id, reason)
		}
	}

	// 再应用两次：端口**不能变**。这是「回写」真正要保证的东西 ——
	// 只断言「分配到了一个端口」的测试对「每次都换一个」是绿的。
	for i := range 2 {
		if err := rt.ApplyTunnels(); err != nil {
			t.Fatalf("第 %d 次重复应用失败：%v", i+2, err)
		}
	}
	for id, want := range assigned {
		cur, err := rt.db.GetTunnel(rt.ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if cur.ListenPort != want {
			t.Fatalf("%s 的端口从 %d 变成了 %d —— "+
				"每次重启换端口等于让所有客户端同时失联", id, want, cur.ListenPort)
		}
	}
}

func TestUnregisterEntryDoesNotRemoveAReplacementWithTheSameShortID(t *testing.T) {
	// 一次「改入口端口」会先关旧入口再建新入口，而两者短标识相同。
	// 并发的另一次 ApplyTunnels 手上还拿着旧入口，若按短标识注销，
	// 就会把新入口的注册删掉 —— 这条隧道从此**单向**：
	// 上行照常（入口自己的读循环还在跑），回向全被 Dispatch 当 unrouted 丢掉。
	// 保存请求返回成功，控制台显示正常，用户看到「发得出去收不回来」。
	rt := newTestRuntime(t)

	tn := &tunnel.Tunnel{
		ID: "t-udp", TenantID: tunnel.DefaultTenantID, Slug: "udp-media",
		L4: tunnel.L4UDP, ListenPort: freePort(t, "udp"),
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:5004"},
	}
	tn.Complete()
	if err := rt.db.PutTunnel(rt.ctx, tn); err != nil {
		t.Fatal(err)
	}
	applyTunnelsWithRetry(t, rt, "t-udp")

	rt.mu.RLock()
	oldEntry := rt.dgrams["t-udp"]
	rt.mu.RUnlock()
	if oldEntry == nil {
		t.Fatal("UDP 入口没建起来")
	}

	// 改端口 → 重建。新入口用同一个短标识注册。
	tn.ListenPort = freePort(t, "udp")
	if err := rt.db.PutTunnel(rt.ctx, tn); err != nil {
		t.Fatal(err)
	}
	applyTunnelsWithRetry(t, rt, "t-udp")

	rt.mu.RLock()
	newEntry := rt.dgrams["t-udp"]
	rt.mu.RUnlock()
	if newEntry == nil || newEntry == oldEntry {
		t.Fatal("改端口之后应当有一个**新**入口")
	}

	// 现在模拟那个落后的并发调用：拿着旧入口去注销。
	rt.DatagramRouter().UnregisterEntry(oldEntry)

	// 新入口的注册必须还在，否则回向数据报全丢。
	frame, err := udpflow.Header{
		Tunnel: tn.ShortID, FlowID: 12345, DstPort: tn.ListenPort,
	}.AppendTo(nil, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	rt.DatagramRouter().Dispatch("agent-1", frame)
	if _, unrouted := rt.DatagramRouter().Stats(); unrouted != 0 {
		t.Fatalf("拿旧入口注销把新入口的注册删掉了（unrouted=%d）—— "+
			"这条隧道从此只能发不能收", unrouted)
	}
}

func TestSharedEntryStatsReachTheSnapshot(t *testing.T) {
	// sharedStats 原本存在但**没有任何调用点**，于是共享入口的所有数字在
	// 控制台上恒为 0 —— 而共享入口是一个监听器服务多条隧道，
	// 按隧道的计数器回答不了「443 上到底发生了什么」。
	rt := newTestRuntime(t)

	if snap := rt.Snapshot(); snap.Shared != nil {
		t.Fatal("未启用 -shared 时应当缺席，而不是给一堆 0")
	}

	if err := rt.startShared("127.0.0.1:0", nil, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	defer rt.closeShared()

	snap := rt.Snapshot()
	if snap.Shared == nil {
		t.Fatal("启用 -shared 之后快照必须带上它的计量")
	}
	if snap.Shared.Addr == "" {
		t.Error("必须报出监听地址")
	}
	if snap.Shared.TLSTermination {
		t.Error("没给 TLS 配置时不该说自己能终止 TLS")
	}

	// 打一个明文连接过去：它会被拒（端口上没有路由），Rejected 应当动。
	addr := snap.Shared.Addr
	if c, err := net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
		_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: nope.example.com\r\n\r\n"))
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Read(make([]byte, 64))
		c.Close()
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s := rt.Snapshot().Shared; s != nil && (s.Rejected > 0 || s.Cleartext > 0) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("共享入口的判别计数没有出现在快照里 —— " +
		"用户只能看到「不通」，而这正是本产品声称要解决的问题")
}

// idleCarrier 是一个什么都不做但「活着」的承载。
//
// 只为了让 rt.sessions 里有一个 Alive 的会话 —— bindUnassigned 只在
// **恰好一个** agent 在线时才写 t.AgentID，而那次写正是要测的 race。
// 没有它的话测试是绿的，而 bug 还在（我第一版就是这样）。
type idleCarrier struct {
	ctx  context.Context
	stop context.CancelFunc
}

func newIdleCarrier(t *testing.T) *idleCarrier {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &idleCarrier{ctx: ctx, stop: cancel}
}

func (c *idleCarrier) OpenStream(context.Context) (carrier.Stream, error) {
	return nil, carrier.ErrClosed
}
func (c *idleCarrier) AcceptStream(ctx context.Context) (carrier.Stream, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *idleCarrier) SendDatagram([]byte) error { return nil }
func (c *idleCarrier) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *idleCarrier) SupportsDatagrams() bool { return true }
func (c *idleCarrier) MaxDatagramPayload() int { return 1200 }
func (c *idleCarrier) Rung() carrier.Rung      { return carrier.RungQUIC }

// ChannelBinding 返回空材料：这个假承载没有 TLS。
// 两端在同一条连接上都拿到空值，所以 MAC 仍然一致。
func (c *idleCarrier) ChannelBinding() ([]byte, error) { return nil, nil }
func (c *idleCarrier) Context() context.Context        { return c.ctx }
func (c *idleCarrier) RTT() time.Duration              { return 0 }
func (c *idleCarrier) LocalAddr() net.Addr             { return &net.UDPAddr{} }
func (c *idleCarrier) RemoteAddr() net.Addr            { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *idleCarrier) CloseWithError(uint64, string) error {
	c.stop()
	return nil
}

func TestConcurrentApplyTunnelsDoesNotRaceOnAgentID(t *testing.T) {
	// bindUnassigned 写 t.AgentID，而 rt.tunnels = byID 一旦发布，数据面就
	// 通过 TunnelByID 拿到同一批指针并每包读 t.AgentID —— 真实的 data race。
	//
	// -race 下会在任何「入口打流 + agent 上线」重叠的场景里报出来，
	// 而发布构建是 CGO_ENABLED=0、没有 race 检测器：表现会是偶发的错误路由。
	//
	// 修法是把 bindUnassigned 挪到发布**之前**（那时这些对象只有一个协程
	// 看得到），而不是加锁 —— 独占是最便宜也最不容易写错的方式。
	rt := newTestRuntime(t)

	// **必须有恰好一个在线 agent**：bindUnassigned 只在那种情况下才写
	// t.AgentID，而那次写就是要测的 race。
	rt.sessions.Add(&relay.Session{
		AgentID: "agent-1", Carrier: newIdleCarrier(t), ConnectedAt: time.Now(),
	})

	for i := range 6 {
		tn := &tunnel.Tunnel{
			ID:         fmt.Sprintf("t-%d", i),
			TenantID:   tunnel.DefaultTenantID,
			Slug:       fmt.Sprintf("svc-%d", i),
			ListenPort: freePort(t, "tcp"),
			Backend:    tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
		}
		tn.Complete()
		if err := rt.db.PutTunnel(rt.ctx, tn); err != nil {
			t.Fatal(err)
		}
	}

	// 一边反复 ApplyTunnels（控制台改配置 / agent 上线各走一次），
	// 一边反复走数据面的查询路径（每个入站连接都会做）。
	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			for i := range 6 {
				if tn, ok := rt.TunnelByID(fmt.Sprintf("t-%d", i)); ok {
					_ = tn.AgentID // 数据面每包都读它
					_, _ = rt.SessionFor(tn.AgentID)
				}
			}
		}
	}()

	for range 8 {
		_ = rt.ApplyTunnels()
	}
	close(stop)
	wg.Wait()
}

func TestUDPProbeReportsUnverifiedHopsInsteadOfFakeGreenTicks(t *testing.T) {
	// 旧版本给 UDP 隧道的 target_dialable 报 ok=true，detail 里写着
	// 「UDP 无连接语义，无法探测」—— 于是整条探测恒报「全链路通」并在那一跳
	// 画一个绿勾。那与 ProbeTunnel 自己的注释直接相反，
	// 而后果是用户在真正的故障点上白找半天：本地服务没起、被 agent 策略否决、
	// 端口写错，全都显示成「通过」。
	rt := newTestRuntime(t)
	rt.sessions.Add(&relay.Session{
		AgentID: "agent-1", Carrier: newIdleCarrier(t), ConnectedAt: time.Now(),
	})

	tn := &tunnel.Tunnel{
		ID: "t-udp", TenantID: tunnel.DefaultTenantID, Slug: "udp-media",
		AgentID: "agent-1",
		L4:      tunnel.L4UDP, ListenPort: freePort(t, "udp"),
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:5004"},
	}
	tn.Complete()
	if err := rt.db.PutTunnel(rt.ctx, tn); err != nil {
		t.Fatal(err)
	}
	applyTunnelsWithRetry(t, rt, "t-udp")

	cur, err := rt.db.GetTunnel(rt.ctx, "t-udp")
	if err != nil {
		t.Fatal(err)
	}
	res := rt.ProbeTunnel(rt.ctx, cur)

	for _, st := range res.Steps {
		if st.Hop == console.HopTargetDialable && st.OK {
			t.Fatalf("UDP 隧道不该给 target_dialable 画绿勾：%+v", st)
		}
		if st.Hop == console.HopFirstByte && st.OK {
			t.Fatalf("没发过业务字节就不该说 first_byte 通过：%+v", st)
		}
	}

	// 那三跳必须**如实**出现在 unverified 里 —— 只是省略掉的话，
	// 界面无从区分「没测」与「没走到」。
	want := map[console.ProbeHop]bool{
		console.HopCarrierRTT:     false,
		console.HopTargetDialable: false,
		console.HopFirstByte:      false,
	}
	for _, u := range res.Unverified {
		if _, ok := want[u.Hop]; ok {
			want[u.Hop] = true
			if u.Why == "" {
				t.Errorf("%s 必须说清为什么没测", u.Hop)
			}
		}
	}
	for hop, got := range want {
		if !got {
			t.Errorf("%s 应当出现在 unverified 里（测不到就如实说测不到）", hop)
		}
	}
}

func TestAgentReportedMetricsReachTheSnapshot(t *testing.T) {
	// 中继只看得见自己那一侧。agent 侧有一整类丢弃它完全不知道：
	// 拨本地目标失败、被本地策略否决、回向发送队列满、回向超限、回向重组失败。
	// 症状是「下行统计都对，就是收不到回包」，而在这条上报之前
	// **没有任何数字**能告诉运维为什么 —— TypeMetrics 这个帧类型在协议里
	// 早就定义了（frame.go:98，注释写着「agent → relay：周期性计数器」），
	// 但从来没有人发过它，也没有人读过它。
	rt := newTestRuntime(t)

	// 走真实的入网路径拿一个 agent —— 那是唯一能建出 agent 的口子。
	token, err := rt.db.CreateEnrolToken(rt.ctx, tunnel.DefaultTenantID, time.Hour, "test")
	if err != nil {
		t.Fatal(err)
	}
	agentID, _, err := rt.db.RedeemEnrolToken(rt.ctx, token,
		&store.Agent{Hostname: "home-nas", OS: "linux"})
	if err != nil {
		t.Fatal(err)
	}
	sess := &relay.Session{
		AgentID: agentID, Carrier: newIdleCarrier(t), ConnectedAt: time.Now(),
	}
	rt.sessions.Add(sess)

	// 没收到上报时必须**缺席**而不是一堆 0 —— 0 会被读成「测过，是零」。
	for _, a := range rt.Snapshot().Agents {
		if a.ID == agentID && a.Reported != nil {
			t.Fatal("还没收到上报就不该有 reported 字段")
		}
	}

	// 用一对内存流模拟控制流：agent 那头写，中继这头读。
	agentSide, relaySide := net.Pipe()
	t.Cleanup(func() { agentSide.Close(); relaySide.Close() })
	go rt.readAgentMetrics(pipeStream{relaySide}, sess)

	want := proto.AgentMetrics{
		UptimeSeconds: 42,
		UDP: proto.AgentUDPMetrics{
			DialFailed: 7, Denied: 3, SendQueueFull: 11,
			ReasmOverlapping: 2, PendingDial: 5,
		},
	}
	w := proto.NewWriter(pipeStream{agentSide})
	if err := w.WriteMessage(proto.TypeMetrics, 0, 0, want); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, a := range rt.Snapshot().Agents {
			if a.ID != agentID || a.Reported == nil {
				continue
			}
			if a.Reported.UptimeSeconds != want.UptimeSeconds {
				t.Fatalf("uptime 不对：%d", a.Reported.UptimeSeconds)
			}
			if a.Reported.AtUnix == 0 {
				t.Error("必须记下到达时刻 —— 否则一份十分钟前的数会被当成现在的")
			}
			udp, ok := a.Reported.UDP.(proto.AgentUDPMetrics)
			if !ok {
				t.Fatalf("UDP 字段类型不对：%T", a.Reported.UDP)
			}
			if udp.DialFailed != 7 || udp.Denied != 3 || udp.SendQueueFull != 11 ||
				udp.ReasmOverlapping != 2 || udp.PendingDial != 5 {
				t.Fatalf("计数器没对上：%+v", udp)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("agent 上报的计数器没有出现在快照里 —— " +
		"那意味着 agent 侧的丢弃在控制台上完全不可见")
}

// pipeStream 把 net.Pipe 的一端当成 carrier.Stream。
type pipeStream struct{ net.Conn }

func TestTrustProxyProtocolSurvivesRouteTableRebuilds(t *testing.T) {
	// applyShared 每次都造一张新注册表再整体替换，而「这个端口信任 PROXY 头」
	// 不由任何一条隧道产生 —— 不重新设置的话，第一次隧道变更就会把它悄悄关掉。
	//
	// 关掉的方向是**安全**的（不再解析不可信的头），但它是一次静默的行为改变：
	// 前置 LB 后面的部署会突然把所有客户端的源地址看成 LB 的地址，
	// 于是白名单开始误拒，而配置一个字都没改。
	// 这与 EnsurePort 是同一个坑，只是方向相反。
	rt := newTestRuntime(t)
	if err := rt.startShared("127.0.0.1:0", nil, nil, nil, true); err != nil {
		t.Fatal(err)
	}
	defer rt.closeShared()

	trusted := func() bool {
		rt.mu.RLock()
		sh := rt.shared
		rt.mu.RUnlock()
		view, ok := sh.reg.View(sh.port)
		return ok && view.TrustProxyProtocol
	}
	if !trusted() {
		t.Fatal("启用后应当立刻生效")
	}

	// 一次隧道变更（哪怕一条隧道都没有）。
	rt.applyShared(nil)
	if !trusted() {
		t.Fatal("路由表重建把 PROXY 信任标记冲掉了 —— " +
			"前置 LB 后面的部署会突然把所有客户端看成 LB 的地址，" +
			"白名单开始误拒，而配置一个字都没改")
	}

	// 默认必须是 false：对不可信来源解析 PROXY 头等于把源 IP 伪造能力
	// 送给公网。
	rt2 := newTestRuntime(t)
	if err := rt2.startShared("127.0.0.1:0", nil, nil, nil, false); err != nil {
		t.Fatal(err)
	}
	defer rt2.closeShared()
	rt2.mu.RLock()
	sh2 := rt2.shared
	rt2.mu.RUnlock()
	if view, ok := sh2.reg.View(sh2.port); ok && view.TrustProxyProtocol {
		t.Fatal("默认必须不信任 PROXY 头")
	}
}

// TestSnapshotCarriesTheLearnedDatagramMTU 钉住这条**接线**。
//
// # 为什么它此前是一个「缺口」而其实不是
//
// 数据报 MTU 不是测不到：quic-go 在一次 SendDatagram 超限时回
// *quic.DatagramTooLargeError，里面带着真实上限；承载层把它存下来，
// 分片器拿它决定分不分片 —— 也就是说这个值**早就在影响转发行为**。
//
// 缺的只是出口：控制台的 rich metric 帧里有个 dgram_mtu 字段，
// 而中继发的是快照、从不发那种帧。于是界面上那一格恒为「—」，
// README 的诚实清单把它与「丢包率没有测量点」并列 —— 而两者根本不同质。
//
// 这条测试守的正是「快照里带着它」这一步。它测不到反应式学习本身
// （那需要真的发一个超限报文，由真实进程验证覆盖，实测 0 → 1404）。
func TestSnapshotCarriesTheLearnedDatagramMTU(t *testing.T) {
	rt := newTestRuntime(t)

	tn := &tunnel.Tunnel{
		ID: "t-udp-mtu", Slug: "udp-mtu", Kind: tunnel.KindService,
		AgentID: "agent-mtu010203ff", Exposure: tunnel.ExposurePort,
		L4: tunnel.L4UDP, ListenPort: 0, ShortID: 7,
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:9"},
	}
	tn.Complete()
	if err := rt.db.PutTunnel(rt.ctx, tn); err != nil {
		t.Fatal(err)
	}

	// 一个在线 agent，其承载报告一个已学到的上限。
	rt.sessions.Add(&relay.Session{
		AgentID: tn.AgentID, Carrier: newIdleCarrier(t), ConnectedAt: time.Now(),
	})

	// UDP 入口必须真的存在：快照的 UDP 分支挂在 rt.dgrams 上。
	de, err := relay.NewDatagramEntry("127.0.0.1:0", tn, rt, relay.DatagramOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = de.Close() })

	rt.mu.Lock()
	rt.tunnels[tn.ID] = tn
	rt.dgrams[tn.ID] = de
	rt.mu.Unlock()

	var got *console.TunnelStatus
	for i := range rt.Snapshot().Tunnels {
		if ts := &rt.Snapshot().Tunnels[i]; ts.ID == tn.ID {
			got = ts
			break
		}
	}
	if got == nil {
		t.Fatal("快照里没有这条隧道")
	}
	if got.DgramMTU != 1200 {
		t.Errorf("dgram_mtu = %d，期望 1200（承载报告的值）—— "+
			"没接上的话界面那一格恒为「—」，而这个值其实早就在影响分片决策了",
			got.DgramMTU)
	}
}

// TestChangingBandwidthOnALiveTunnelTakesEffectWithoutARestart 钉住一条
// **此前是假话**的注释。
//
// # 修之前的行为
//
// entry.go 的注释写着「改限速值走重建入口（隧道定义变了本来就要重建）」，
// 而 ApplyTunnels 的绑定循环对已存在的入口直接 `continue` —— policy 的四个
// 数字变了**不在**重建判据里。于是在一条已上线隧道上把 1 Mbps 改成 100 Kbps，
// 进程重启前一个字节都不会变，而详情页照常显示「已设置」。
//
// 这与共享入口那边刚做的实现还会**互相矛盾**：同一个界面上的同一个字段，
// exposure=shared 立刻生效、exposure=port 要重启。
//
// # 为什么带宽原地改而并发上限重建
//
// 信号量容量是固定的，改并发上限只能重建 —— 而重建会掐断这条隧道上所有在飞
// 连接。调一次带宽不该让所有用户掉线，所以两类参数刻意分开处理。
func TestChangingBandwidthOnALiveTunnelTakesEffectWithoutARestart(t *testing.T) {
	rt := newTestRuntime(t)
	tn := mkTunnel("bw", tunnel.KindService, "agent-bw01020304")
	tn.Policy = &tunnel.Policy{BytesPerSecond: 1 << 20}
	if err := rt.db.PutTunnel(rt.ctx, tn); err != nil {
		t.Fatal(err)
	}
	rt.sessions.Add(&relay.Session{
		AgentID: tn.AgentID, Carrier: newIdleCarrier(t), ConnectedAt: time.Now(),
	})
	if err := rt.ApplyTunnels(); err != nil {
		t.Fatalf("首次应用失败：%v", err)
	}

	rt.mu.RLock()
	el := rt.entries[tn.ID]
	rt.mu.RUnlock()
	if el == nil {
		t.Fatal("入口没建起来")
	}
	conns0, perIP0 := el.LimitsSpec()

	// ── 只改带宽：入口**不该**被重建（否则在飞连接会被掐断）──
	fresh, err := rt.db.GetTunnel(rt.ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	fresh.Policy = &tunnel.Policy{BytesPerSecond: 100 << 10}
	if err := rt.db.PutTunnel(rt.ctx, fresh); err != nil {
		t.Fatal(err)
	}
	if err := rt.ApplyTunnels(); err != nil {
		t.Fatalf("改带宽后应用失败：%v", err)
	}
	rt.mu.RLock()
	same := rt.entries[tn.ID]
	rt.mu.RUnlock()
	if same != el {
		t.Error("只改了带宽却重建了入口 —— 这条隧道上所有在飞连接被无谓掐断")
	}
	if c, p := same.LimitsSpec(); c != conns0 || p != perIP0 {
		t.Errorf("并发参数被改动了（%d/%d → %d/%d），而只改了带宽", conns0, perIP0, c, p)
	}

	// ── 改并发上限：入口**必须**被重建，否则新值永远不生效 ──
	fresh2, err := rt.db.GetTunnel(rt.ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	fresh2.Policy = &tunnel.Policy{BytesPerSecond: 100 << 10, MaxConns: 7}
	if err := rt.db.PutTunnel(rt.ctx, fresh2); err != nil {
		t.Fatal(err)
	}
	if err := rt.ApplyTunnels(); err != nil {
		t.Fatalf("改并发上限后应用失败：%v", err)
	}
	rt.mu.RLock()
	rebuilt := rt.entries[tn.ID]
	rt.mu.RUnlock()
	if rebuilt == nil {
		t.Fatal("改并发上限之后入口没了")
	}
	if c, _ := rebuilt.LimitsSpec(); c != 7 {
		t.Errorf("改 max_conns=7 之后入口的容量还是 %d —— "+
			"新值永远不生效，而界面显示「已设置」", c)
	}

	// ── 再 apply 一次：什么都没改，绝不能重建 ──
	//
	// 少了这一条，「并发上限变了吗」的判据只要与 NewEntryListener 的算法
	// 有一丝不一致，就会**每秒重建一次入口**（ApplyTunnels 由 refreshStates
	// 触发），所有连接被反复掐断，而配置一个字都没改。
	if err := rt.ApplyTunnels(); err != nil {
		t.Fatal(err)
	}
	rt.mu.RLock()
	stable := rt.entries[tn.ID]
	rt.mu.RUnlock()
	if stable != rebuilt {
		t.Error("配置没变却又重建了一次入口 —— " +
			"判据与 NewEntryListener 的算法不一致，会每次 apply 都掐断所有连接")
	}
}
