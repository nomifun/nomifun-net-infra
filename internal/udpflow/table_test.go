package udpflow

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func key(src string, dstPort, tunnel uint16) Key {
	return Key{Src: netip.MustParseAddrPort(src), DstPort: dstPort, Tunnel: tunnel}
}

// fakeConn 代表一个被会话表持有的资源（真实实现里是 *net.UDPConn）。
type fakeConn struct {
	id     int
	closed atomic.Bool
}

func newTableWithClock[V any](cfg Config, now func() time.Time) *Table[V] {
	t := New[V](cfg)
	t.now = now
	return t
}

// TestSourcePortSprayCannotExhaustResources 是本包最重要的测试。
//
// 它复现 frp 的 fd 耗尽攻击：从随机源端口向中继喷包。在 frp 里每个新源地址
// 都会 net.DialUDP 一个新 socket 且**表无上限**（pkg/proto/udp/udp.go:75,117-124），
// 30 秒回收窗口内即可耗尽文件描述符。这里必须被容量与配额挡住。
func TestSourcePortSprayCannotExhaustResources(t *testing.T) {
	const capacity = 64
	// 把速率上限放得很高，以便单独检验容量与配额这两道闸。
	cfg := Config{Capacity: capacity, PerSourceIP: 1024, NewFlowsPerSecond: 1_000_000}

	var created, closed atomic.Int64
	tbl := New[*fakeConn](cfg)

	// 同一个源 IP，10000 个不同源端口 —— 典型的喷射形态。
	for port := 1; port <= 10000; port++ {
		k := key(fmt.Sprintf("203.0.113.9:%d", port), 8443, 1)
		_, _, err := tbl.Admit(k,
			func() (*fakeConn, error) {
				created.Add(1)
				return &fakeConn{id: port}, nil
			},
			func(c *fakeConn) {
				if c.closed.Swap(true) {
					t.Error("同一个资源被 discard 了两次")
				}
				closed.Add(1)
			},
		)
		if err != nil {
			t.Fatalf("port=%d: Admit 意外失败：%v", port, err)
		}
	}

	if got := tbl.Len(); got > capacity {
		t.Fatalf("表长 %d 超过容量 %d —— 无界表就是 fd 耗尽攻击面", got, capacity)
	}
	// 被淘汰的资源必须都被释放，否则 fd 仍然泄漏。
	if c, cl := created.Load(), closed.Load(); c-cl > int64(capacity) {
		t.Fatalf("创建 %d 个、释放 %d 个，泄漏 %d 个（应当 ≤ 容量 %d）", c, cl, c-cl, capacity)
	}
}

// TestPerSourceIPQuotaIsKeyedByIPNotIPPort 验证配额按源 IP 计而非按 IP:端口。
//
// 这是关键区别：若按 IP:端口计额，攻击者换个源端口就绕过去了，配额形同虚设。
func TestPerSourceIPQuotaIsKeyedByIPNotIPPort(t *testing.T) {
	const perIP = 8
	tbl := New[*fakeConn](Config{Capacity: 10000, PerSourceIP: perIP, NewFlowsPerSecond: 1_000_000})

	mk := func(port int) error {
		_, _, err := tbl.Admit(key(fmt.Sprintf("198.51.100.7:%d", port), 8443, 1),
			func() (*fakeConn, error) { return &fakeConn{id: port}, nil }, nil)
		return err
	}

	for i := 1; i <= perIP; i++ {
		if err := mk(i); err != nil {
			t.Fatalf("第 %d 条（配额内）应当通过：%v", i, err)
		}
	}
	// 第 perIP+1 条：**同一 IP、不同源端口**，必须被拒。
	if err := mk(perIP + 1); !errors.Is(err, ErrPerIPQuota) {
		t.Fatalf("换源端口不该绕过每源 IP 配额，得到 %v", err)
	}

	// 换一个 IP 则应当放行 —— 配额是按 IP 隔离的，不是全局。
	_, _, err := tbl.Admit(key("198.51.100.8:1", 8443, 1),
		func() (*fakeConn, error) { return &fakeConn{}, nil }, nil)
	if err != nil {
		t.Fatalf("不同源 IP 应当有独立配额：%v", err)
	}
}

// TestPerIPQuotaIsReleasedOnEviction 确认配额计数在条目被回收后归还，
// 否则一个源 IP 用满配额后即使流早已结束也永久无法再建流。
func TestPerIPQuotaIsReleasedOnEviction(t *testing.T) {
	const perIP = 4
	base := time.Now()
	cur := base
	tbl := newTableWithClock[*fakeConn](
		Config{Capacity: 100, PerSourceIP: perIP, NewFlowsPerSecond: 1_000_000, IdleTimeout: time.Minute},
		func() time.Time { return cur },
	)

	for i := 1; i <= perIP; i++ {
		if _, _, err := tbl.Admit(key(fmt.Sprintf("192.0.2.5:%d", i), 80, 1),
			func() (*fakeConn, error) { return &fakeConn{id: i}, nil }, nil); err != nil {
			t.Fatalf("第 %d 条应当通过：%v", i, err)
		}
	}
	if _, _, err := tbl.Admit(key("192.0.2.5:99", 80, 1),
		func() (*fakeConn, error) { return &fakeConn{}, nil }, nil); !errors.Is(err, ErrPerIPQuota) {
		t.Fatalf("配额应当已满，得到 %v", err)
	}

	// 全部空闲超时。
	cur = base.Add(2 * time.Minute)
	if n := tbl.EvictIdle(nil); n != perIP {
		t.Fatalf("回收了 %d 条，期望 %d", n, perIP)
	}

	// 配额必须已归还。
	if _, _, err := tbl.Admit(key("192.0.2.5:100", 80, 1),
		func() (*fakeConn, error) { return &fakeConn{}, nil }, nil); err != nil {
		t.Fatalf("回收后配额应当归还，却仍被拒：%v", err)
	}
}

// TestRateLimitBlocksBurstThenRecovers 验证建表限速。
func TestRateLimitBlocksBurstThenRecovers(t *testing.T) {
	const perSec = 10
	base := time.Now()
	cur := base
	tbl := newTableWithClock[*fakeConn](
		Config{Capacity: 10000, PerSourceIP: 10000, NewFlowsPerSecond: perSec},
		func() time.Time { return cur },
	)

	mk := func(port int) error {
		_, _, err := tbl.Admit(key(fmt.Sprintf("192.0.2.1:%d", port), 80, 1),
			func() (*fakeConn, error) { return &fakeConn{id: port}, nil }, nil)
		return err
	}

	// 桶初始为满，前 perSec 条应当通过。
	for i := 1; i <= perSec; i++ {
		if err := mk(i); err != nil {
			t.Fatalf("突发第 %d 条应当通过：%v", i, err)
		}
	}
	if err := mk(perSec + 1); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("桶应当已空，得到 %v", err)
	}

	// 时间推进一秒，桶补满。
	cur = base.Add(time.Second)
	if err := mk(perSec + 2); err != nil {
		t.Fatalf("一秒后应当恢复：%v", err)
	}
}

// TestLookupRefreshesLRUOrder 确认活跃流不会被当作最旧淘汰。
func TestLookupRefreshesLRUOrder(t *testing.T) {
	base := time.Now()
	cur := base
	tbl := newTableWithClock[*fakeConn](
		Config{Capacity: 100, PerSourceIP: 100, NewFlowsPerSecond: 1_000_000, IdleTimeout: 30 * time.Second},
		func() time.Time { return cur },
	)

	hot := key("192.0.2.1:1000", 80, 1)
	cold := key("192.0.2.1:1001", 80, 1)

	for _, k := range []Key{hot, cold} {
		if _, _, err := tbl.Admit(k, func() (*fakeConn, error) { return &fakeConn{}, nil }, nil); err != nil {
			t.Fatal(err)
		}
	}

	// 20 秒后只碰 hot。
	cur = base.Add(20 * time.Second)
	if _, ok := tbl.Lookup(hot); !ok {
		t.Fatal("hot 应当还在")
	}

	// 再过 20 秒：cold 已空闲 40s（超时），hot 只空闲 20s（未超时）。
	cur = base.Add(40 * time.Second)
	tbl.EvictIdle(nil)

	if _, ok := tbl.Lookup(hot); !ok {
		t.Error("活跃流被误回收 —— Lookup 没有刷新 LRU 顺序")
	}
	if _, ok := tbl.Lookup(cold); ok {
		t.Error("空闲流应当已被回收")
	}
}

// TestAdmitDoesNotHoldLockAcrossCreate 验证 create 是在锁外调用的。
//
// frp 把 net.DialUDP 放在全局锁内（pkg/proto/udp/udp.go:116-126），
// 使所有新会话建立被串行化。这里用「create 内部再调表的其他方法」来检测：
// 若 create 在锁内被调用，这个测试会死锁（由 go test 超时暴露）。
func TestAdmitDoesNotHoldLockAcrossCreate(t *testing.T) {
	tbl := New[*fakeConn](Config{Capacity: 100, PerSourceIP: 100, NewFlowsPerSecond: 1_000_000})

	// 先放一条别的流，让 create 里的 Lookup 有东西可查。
	other := key("192.0.2.9:1", 80, 1)
	if _, _, err := tbl.Admit(other, func() (*fakeConn, error) { return &fakeConn{id: 1}, nil }, nil); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = tbl.Admit(key("192.0.2.9:2", 80, 1), func() (*fakeConn, error) {
			// 若 Admit 在此期间持有分片锁，这次 Lookup 就会自锁。
			// 注意两个 key 的源 IP 相同，必然落在同一分片。
			tbl.Lookup(other)
			tbl.Len()
			return &fakeConn{id: 2}, nil
		}, nil)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Admit 在 create 期间持有了锁 —— 会把所有新会话建立串行化")
	}
}

// TestConcurrentAdmitSameKeyKeepsOneAndDiscardsOther 验证并发竞争下
// 只有一个值被登记，另一个通过 discard 交还调用方释放，不泄漏。
func TestConcurrentAdmitSameKeyKeepsOneAndDiscardsOther(t *testing.T) {
	tbl := New[*fakeConn](Config{Capacity: 100, PerSourceIP: 100, NewFlowsPerSecond: 1_000_000})
	k := key("192.0.2.3:5000", 443, 7)

	const racers = 16
	var created, discarded atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			_, _, err := tbl.Admit(k,
				func() (*fakeConn, error) { created.Add(1); return &fakeConn{id: id}, nil },
				func(*fakeConn) { discarded.Add(1) },
			)
			if err != nil {
				t.Errorf("Admit: %v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if got := tbl.Len(); got != 1 {
		t.Fatalf("表长 %d，期望 1（同一 key 只应登记一条）", got)
	}
	// 创建了 N 个，只有 1 个被留下，其余 N-1 必须都被 discard。
	if c, d := created.Load(), discarded.Load(); c-d != 1 {
		t.Fatalf("创建 %d 个、discard %d 个 —— 泄漏 %d 个资源", c, d, c-d-1)
	}
}

func TestDeleteReleasesQuotaAndResource(t *testing.T) {
	tbl := New[*fakeConn](Config{Capacity: 10, PerSourceIP: 1, NewFlowsPerSecond: 1_000_000})
	k := key("192.0.2.4:1", 80, 1)

	var closed bool
	if _, _, err := tbl.Admit(k, func() (*fakeConn, error) { return &fakeConn{}, nil }, nil); err != nil {
		t.Fatal(err)
	}
	if !tbl.Delete(k, func(*fakeConn) { closed = true }) {
		t.Fatal("Delete 应当返回 true")
	}
	if !closed {
		t.Error("Delete 应当调用 discard 释放资源")
	}
	if tbl.Delete(k, nil) {
		t.Error("重复 Delete 应当返回 false")
	}
	// 配额已归还，可以再建。
	if _, _, err := tbl.Admit(k, func() (*fakeConn, error) { return &fakeConn{}, nil }, nil); err != nil {
		t.Fatalf("Delete 后配额应当归还：%v", err)
	}
}

// TestPerIPMapDoesNotLeakZeroEntries 确认配额 map 不留零值条目 ——
// 否则 map 本身就是一个随源 IP 数量无界增长的泄漏。
func TestPerIPMapDoesNotLeakZeroEntries(t *testing.T) {
	tbl := New[*fakeConn](Config{Capacity: 10000, PerSourceIP: 100, NewFlowsPerSecond: 1_000_000})

	for i := 1; i <= 500; i++ {
		k := key(fmt.Sprintf("192.0.2.%d:1", i%250+1), 80, uint16(i))
		if _, _, err := tbl.Admit(k, func() (*fakeConn, error) { return &fakeConn{}, nil }, nil); err != nil {
			t.Fatal(err)
		}
		tbl.Delete(k, nil)
	}

	tbl.ipMu.Lock()
	n := len(tbl.perIP)
	tbl.ipMu.Unlock()
	if n != 0 {
		t.Fatalf("配额 map 残留 %d 个零值条目 —— 这是一个随源 IP 数无界增长的泄漏", n)
	}
}

func TestCloseReleasesEverything(t *testing.T) {
	tbl := New[*fakeConn](Config{Capacity: 100, PerSourceIP: 100, NewFlowsPerSecond: 1_000_000})
	const n = 30
	for i := 0; i < n; i++ {
		if _, _, err := tbl.Admit(key(fmt.Sprintf("192.0.2.1:%d", 1000+i), 80, 1),
			func() (*fakeConn, error) { return &fakeConn{id: i}, nil }, nil); err != nil {
			t.Fatal(err)
		}
	}

	var closed atomic.Int64
	tbl.Close(func(*fakeConn) { closed.Add(1) })

	if tbl.Len() != 0 {
		t.Errorf("Close 后表长应为 0，实际 %d", tbl.Len())
	}
	if got := closed.Load(); got != n {
		t.Errorf("Close 释放了 %d 个资源，期望 %d", got, n)
	}
}

// TestKeyDistinguishesDstPortAndTunnel 确认键包含目的端口与隧道标识。
//
// frp 在服务端把原始目的地址丢了（pkg/proto/udp/udp.go:64 传 nil），
// 导致一条隧道无法承载多个 UDP 服务。这里必须能区分。
func TestKeyDistinguishesDstPortAndTunnel(t *testing.T) {
	tbl := New[int](Config{Capacity: 100, PerSourceIP: 100, NewFlowsPerSecond: 1_000_000})

	same := "192.0.2.10:5000"
	variants := []Key{
		key(same, 8080, 1),
		key(same, 8081, 1), // 同源、不同目的端口
		key(same, 8080, 2), // 同源同目的端口、不同隧道
	}
	for i, k := range variants {
		v := i + 1
		got, _, err := tbl.Admit(k, func() (int, error) { return v, nil }, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got != v {
			t.Fatalf("变体 %d 与既有条目撞键了 —— 键必须包含目的端口与隧道标识", i)
		}
	}
	if tbl.Len() != len(variants) {
		t.Fatalf("表长 %d，期望 %d", tbl.Len(), len(variants))
	}
}

func TestCreateErrorReleasesQuota(t *testing.T) {
	tbl := New[*fakeConn](Config{Capacity: 10, PerSourceIP: 1, NewFlowsPerSecond: 1_000_000})
	k := key("192.0.2.6:1", 80, 1)

	wantErr := errors.New("dial 失败")
	if _, _, err := tbl.Admit(k, func() (*fakeConn, error) { return nil, wantErr }, nil); !errors.Is(err, wantErr) {
		t.Fatalf("应当透传 create 的错误，得到 %v", err)
	}
	// 配额必须已归还，否则一次 dial 失败就永久占用一个额度。
	if _, _, err := tbl.Admit(k, func() (*fakeConn, error) { return &fakeConn{}, nil }, nil); err != nil {
		t.Fatalf("create 失败后配额应当归还：%v", err)
	}
}

func TestAdmitReportsWhoActuallyCreatedTheValue(t *testing.T) {
	// 调用方常常要为「新流」做一次性副作用：起一个读回包的协程、活跃数 +1。
	// 抢输的那一次拿到的是**别人的**值，对它再做一遍就是两个协程读同一个
	// socket —— 其中一个退出时 close 掉，另一个跟着死，而表项还活着。
	// agent 侧真实发生过这个形状。
	tbl := New[*fakeConn](Config{Capacity: 64})
	k := key("192.0.2.20:1", 80, 1)

	_, created, err := tbl.Admit(k, func() (*fakeConn, error) { return &fakeConn{id: 1}, nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("第一次 Admit 必须报 created=true")
	}

	// 同一个键再来一次：拿到的是既有值，created 必须为 false。
	var discarded atomic.Int64
	got, created, err := tbl.Admit(k,
		func() (*fakeConn, error) { return &fakeConn{id: 2}, nil },
		func(*fakeConn) { discarded.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("同键重复 Admit 必须报 created=false，" +
			"否则调用方会为别人的值再起一个读协程")
	}
	if got.id != 1 {
		t.Fatalf("应当返回既有值（id=1），实际 id=%d", got.id)
	}
	if discarded.Load() != 1 {
		t.Fatalf("我建的那个应当被交还给 discard，实际交还 %d 次", discarded.Load())
	}
}

func TestCapacityEvictionsAreCountedBecauseTableFullNeverReturnsAnError(t *testing.T) {
	// 本表满了不会拒绝新流，而是淘汰最旧的那条（对实时流量是正确取舍）。
	// 后果是「表满」这件事**一个错误都不返回** —— grep 全仓，
	// ErrTableFull 没有任何生产者，于是控制台上 dropped_table_full 恒为 0，
	// 而真实情况是有人的流正在被静默挤掉。
	//
	// 那个 0 比没有数字更糟：README 自己写着「0 会被读成『测过，是零』」。
	tbl := New[*fakeConn](Config{Capacity: 4, PerSourceIP: 100})

	for i := range 10 {
		k := key(fmt.Sprintf("192.0.2.30:%d", 1000+i), 80, 1)
		_, _, err := tbl.Admit(k,
			func() (*fakeConn, error) { return &fakeConn{id: i}, nil }, nil)
		if err != nil {
			t.Fatalf("第 %d 条不该被拒 —— 本表的语义是淘汰最旧而不是拒绝新流：%v", i, err)
		}
	}

	if got := tbl.Len(); got != 4 {
		t.Fatalf("表长应当收敛到容量 4，实际 %d", got)
	}
	if got := tbl.CapacityEvictions(); got != 6 {
		t.Fatalf("应当记下 6 次容量淘汰，实际 %d —— "+
			"没有这个数字的话「表满」在界面上完全看不见", got)
	}
}
