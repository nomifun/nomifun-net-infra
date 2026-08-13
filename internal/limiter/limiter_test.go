package limiter

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestZeroLimitsProduceNoLimiterAtAll(t *testing.T) {
	// 绝大多数隧道不限速。为它们造一个限速器意味着每个字节都要过一次
	// 令牌桶（一次 CAS + 一次时间读），而收益是零。
	if l := New(Limits{}); l != nil {
		t.Fatal("完全不限速时应当返回 nil，让调用方彻底跳过限速路径")
	}
	// nil 上的所有方法都必须安全 —— 调用方不该到处判空。
	var nilLim *Limiter
	if !nilLim.AllowN(1 << 20) {
		t.Error("nil 限速器必须一律放行")
	}
	if got := nilLim.WaitReader(context.Background(), strings.NewReader("x")); got == nil {
		t.Error("nil 限速器应当原样返回 reader")
	}
}

func TestBurstNeverFallsBelowAMaximumDatagram(t *testing.T) {
	// 桶容量小于单次申请量时，x/time/rate 的 AllowN/WaitN **直接失败**
	// 而不是等 —— 于是一个满尺寸 UDP 数据报会**永久**通不过，
	// 现象是「大包不通小包正常」，而那看起来像 MTU 问题，不像限速。
	l := New(Limits{BytesPerSecond: 1000}) // 远小于 64 KiB
	if got := l.bytes.Burst(); got < minByteBurst {
		t.Fatalf("突发额度 %d 小于一个满尺寸数据报（%d）—— "+
			"那个尺寸的包会永久失败而不是被限速", got, minByteBurst)
	}
	// 一个 64 KiB 的包必须**能**通过（可能要等，但不是永久失败）。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := l.Wait(ctx, minByteBurst); err != nil {
		t.Fatalf("满尺寸数据报应当能拿到额度（哪怕要等）：%v", err)
	}
}

func TestPacketRateLimitCatchesSmallPacketFloods(t *testing.T) {
	// 10 万 pps 的 64 字节小包是现实攻击形态：每秒 6.4 MB，
	// 任何按字节的限速器都会放行它，而它足以打满一台家用路由器的 pps 能力。
	// 规格里 BytesPerSecond 与 PacketsPerSecond 同时存在正是这个理由。
	l := New(Limits{PacketsPerSecond: 10}) // 只限包，不限字节

	var allowed int
	for range 100 {
		if l.AllowN(64) {
			allowed++
		}
	}
	if allowed > 20 {
		t.Fatalf("只限包速率 10/s，一百个小包放行了 %d 个 —— "+
			"小包洪水那条攻击面根本没被覆盖（包桶的突发额度被套上了字节桶的下限？）",
			allowed)
	}
	if allowed == 0 {
		t.Fatal("桶初始应当是满的，头几个必须能过")
	}
}

func TestByteRateLimitDropsOversizeBursts(t *testing.T) {
	l := New(Limits{BytesPerSecond: 100 << 10}) // 100 KiB/s

	// 桶初始是满的（容量 100 KiB），所以头一批能过。
	var allowed int
	for range 40 {
		if l.AllowN(8 << 10) { // 8 KiB 一个
			allowed++
		}
	}
	if allowed == 40 {
		t.Fatal("40 × 8 KiB = 320 KiB 远超 100 KiB/s 的桶容量，不该全部放行")
	}
	if allowed == 0 {
		t.Fatal("桶初始应当是满的，头几个必须能过 —— " +
			"从空桶开始会让每条新连接的第一批数据都被丢")
	}
}

func TestWaitReaderThrottlesInsteadOfDroppingBytes(t *testing.T) {
	// TCP 是字节流：丢掉中间一段就是把连接搞坏。所以 TCP 路径必须**等**。
	// 这条测的是「一个字节都不能少」，顺带确认它真的慢下来了。
	// 速率必须 >= minByteBurst，否则桶容量被抬到 64 KiB，
	// 而那时 40 KiB 全落在初始突发里、根本不会慢 —— 测的就不是限速了。
	const rate = 128 << 10 // 128 KiB/s
	const total = 3 * rate // 三倍：初始突发只够第一份
	l := New(Limits{BytesPerSecond: rate})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	src := strings.NewReader(strings.Repeat("a", total))
	start := time.Now()
	n, err := io.Copy(io.Discard, l.WaitReader(ctx, src))
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("限速不该让复制失败：%v", err)
	}
	if n != total {
		t.Fatalf("一个字节都不能少：读到 %d / %d —— "+
			"在一条 TCP 流中间挖洞比慢得多糟糕", n, total)
	}
	// 桶初始满（128 KiB），剩下 256 KiB 要按 128 KiB/s 补，所以至少 ~2 秒。
	if elapsed < time.Second {
		t.Fatalf("%d 字节过 %d B/s 的限速只花了 %s —— 限速没生效",
			total, rate, elapsed)
	}
}

func TestWaitReaderSurrendersBytesAlreadyReadWhenContextEnds(t *testing.T) {
	// ctx 结束时**不能**把已经从底层读出来的字节丢掉：
	// 那些字节已经离开 socket 缓冲了，丢了就是在 TCP 流里挖一个洞。
	l := New(Limits{BytesPerSecond: 1 << 10})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立刻结束

	r := l.WaitReader(ctx, strings.NewReader("hello"))
	buf := make([]byte, 5)
	n, _ := r.Read(buf)
	if n != 5 {
		t.Fatalf("已经读出来的字节必须交出去，实际 %d", n)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("内容不对：%q", buf[:n])
	}
}

func TestWaitHandlesRequestsLargerThanTheBucket(t *testing.T) {
	// 一次读到 1 MiB 而限速只有 64 KiB/s：x/time/rate 对 n > burst
	// **直接返回错误**而不是等 —— 不分批的话这条流会永久失败。
	l := New(Limits{BytesPerSecond: 1 << 20}) // 1 MiB/s，桶容量 1 MiB
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 要 3 MiB，是桶容量的三倍。
	if err := l.Wait(ctx, 3<<20); err != nil {
		t.Fatalf("超过桶容量的请求应当分批而不是失败：%v", err)
	}
}
