package relay

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/limiter"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// TestSetLimitsReallyReplacesTheBucket 钉住原地改带宽**真的换了桶**。
//
// # 为什么 cmd/nfrelay 那条测试不够
//
// 那条测的是「入口对象没被重建」与「并发参数没变」，而这两点在
// SetLimits 什么都不做时**照样成立** —— 变异验证抓出来的：把 SetLimits 改成
// 空操作，那条测试全绿。
//
// 也就是说「改带宽立刻生效」这个承诺当时并没有被任何测试守着。
// 这条测试在包内做，直接看那个原子指针换了没有、以及换上来的桶真的会限速。
func TestSetLimitsReallyReplacesTheBucket(t *testing.T) {
	tn := &tunnel.Tunnel{
		ID: "t-setlim", Slug: "setlim", Kind: tunnel.KindService,
		AgentID: "agent-x", Exposure: tunnel.ExposurePort, ListenPort: 0,
		L4: tunnel.L4TCP, Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:9"},
	}
	tn.Complete()

	el, err := NewEntryListener("127.0.0.1:0", tn, newStubLookup(), EntryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = el.Close() })

	// 一开始不限速：limiter.New 对零值返回 nil。
	if got := el.limiter.Load(); got != nil {
		t.Fatalf("没配限速却有一个桶：%v", got)
	}

	const rate = 128 << 10
	el.SetLimits(limiter.Limits{BytesPerSecond: rate})
	lim := el.limiter.Load()
	if lim == nil {
		t.Fatal("SetLimits 之后还是没有桶 —— 改带宽是个空操作，" +
			"而界面显示「已设置」")
	}

	// 换上来的桶必须**真的会限**。三倍速率的载荷：初始突发只够第一份。
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	src := strings.NewReader(strings.Repeat("z", 3*rate))
	start := time.Now()
	n, err := io.Copy(io.Discard, lim.WaitReader(ctx, src))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("限速不该让复制失败：%v", err)
	}
	if n != int64(3*rate) {
		t.Fatalf("一个字节都不能少：读到 %d / %d", n, 3*rate)
	}
	if elapsed < time.Second {
		t.Fatalf("%d 字节过 %d B/s 只花了 %s —— 换上来的桶不限速",
			3*rate, rate, elapsed.Round(time.Millisecond))
	}

	// 再改一次：必须又换一个桶（否则第二次调整不生效）。
	el.SetLimits(limiter.Limits{BytesPerSecond: 4 * rate})
	if el.limiter.Load() == lim {
		t.Error("第二次 SetLimits 没换桶 —— 只有第一次调整生效")
	}

	// 改回不限速：桶必须变回 nil，否则「取消限速」做不到。
	el.SetLimits(limiter.Limits{})
	if el.limiter.Load() != nil {
		t.Error("把限速改成 0 之后桶还在 —— 取消限速做不到")
	}
	t.Logf("原地换桶生效：%s", elapsed.Round(time.Millisecond))
}
