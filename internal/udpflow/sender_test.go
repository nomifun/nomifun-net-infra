package udpflow

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingCarrier 是一个「永远发不出去」的承载，用来证明调用方不会被拖住。
//
// 这正是 quic-go 的真实行为边界：连接内已排队 32 条未发出的数据报时
// SendDatagram 会阻塞（datagram_queue.go:44-46）。若不隔离它，
// 一个拥塞的对端就能冻结整个 UDP 读循环。
type blockingCarrier struct {
	release chan struct{}
	calls   atomic.Int64
	maxPay  atomic.Int64
}

func newBlockingCarrier() *blockingCarrier {
	return &blockingCarrier{release: make(chan struct{})}
}

func (c *blockingCarrier) SendDatagram(b []byte) error {
	c.calls.Add(1)
	<-c.release // 挂住不放
	return nil
}

func (c *blockingCarrier) MaxDatagramPayload() int { return int(c.maxPay.Load()) }

// countingCarrier 正常收下数据报并记账。
type countingCarrier struct {
	// got 由 Sender 的发送协程写、由测试协程读，所以要**加锁**。
	//
	// 只靠 n 这个原子计数同步是不够的：n 到 3 之后发送协程可能还在追加
	// 第 4 片，此时测试正在遍历 got —— 竞态检测器抓的就是这个。
	// 这类「假件自己不并发安全」的 bug 会以随机失败的形式出现在别的测试上，
	// 比测的东西本身更难查。
	mu     sync.Mutex
	got    [][]byte
	maxPay atomic.Int64
	fail   error
	n      atomic.Int64
}

func (c *countingCarrier) SendDatagram(b []byte) error {
	if c.fail != nil {
		return c.fail
	}
	c.mu.Lock()
	// 必须拷贝：Sender 会把缓冲还回池里复用，留着切片就会读到后来的内容。
	c.got = append(c.got, append([]byte(nil), b...))
	c.mu.Unlock()
	c.n.Add(1)
	return nil
}

// frames 返回当前已发出的帧的快照。
func (c *countingCarrier) frames() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.got...)
}

func (c *countingCarrier) MaxDatagramPayload() int { return int(c.maxPay.Load()) }

func TestSenderNeverBlocksTheCallerEvenWhenTheCarrierIsWedged(t *testing.T) {
	// 这是本部件存在的唯一理由。若 Send 会阻塞，一个卡住的对端就会让
	// 同一入口上**所有**流的包一起停，而且没有计数、界面上看不出异常 ——
	// 那正是 frp 下行 UDP 队列满时阻塞的错误（server/proxy/udp.go:140）。
	car := newBlockingCarrier()
	s := NewSender(car, 4, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	defer s.Close()

	// 第一条会被 Run 取走并卡在 SendDatagram 里；队列还能收 4 条。
	// 之后的每一条都必须**立刻**被丢弃而不是等待。
	done := make(chan int, 1)
	go func() {
		accepted := 0
		for range 200 {
			if s.Send(Header{Tunnel: 1, FlowID: 7, DstPort: 5000}, []byte("媒体包")) {
				accepted++
			}
		}
		done <- accepted
	}()

	select {
	case accepted := <-done:
		// 队列 4 + 正在发的 1，其余全丢。
		if accepted > 8 {
			t.Errorf("承载卡死时收下了 %d 条，队列深度只有 4 —— 说明它在等", accepted)
		}
		if dropped := s.Stats().QueueFull.Load(); dropped < 190 {
			t.Errorf("丢弃数 %d 太少，200 条里绝大多数应当被丢", dropped)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Send 被卡住了 —— 它必须绝不阻塞调用方")
	}

	close(car.release)
}

func TestSenderFramesWhatItIsGiven(t *testing.T) {
	car := &countingCarrier{}
	s := NewSender(car, 8, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	defer s.Close()

	want := []byte("你好，这是一条 UDP 载荷")
	h := Header{Tunnel: 3, FlowID: 0xDEADBEEF, DstPort: 5004}
	if !s.Send(h, want) {
		t.Fatal("正常承载上不该丢包")
	}
	waitFor(t, func() bool { return car.n.Load() == 1 }, "数据报应当被发出")

	gotHdr, gotPayload, err := ParseFrame(car.frames()[0])
	if err != nil {
		t.Fatalf("发出的帧解析失败：%v", err)
	}
	if gotHdr.Tunnel != h.Tunnel || gotHdr.FlowID != h.FlowID || gotHdr.DstPort != h.DstPort {
		t.Fatalf("帧头被改动：%+v", gotHdr)
	}
	if string(gotPayload) != string(want) {
		t.Fatalf("载荷被改动：%q", gotPayload)
	}
	// 未分片帧的长度字段必须自洽，否则接收侧会拒收。
	if gotHdr.Fragmented() || gotHdr.TotalLen != gotHdr.FragLen {
		t.Fatalf("单包不该被标成分片：%+v", gotHdr)
	}
}

func TestSenderTreatsUnknownMaxPayloadAsNoLimit(t *testing.T) {
	// PMTUD 完成前上限是未知的（返回 0）。把「未知」当成「上限为 0」
	// 会让第一批包全被丢掉 —— 而那恰好是连接刚建立、最需要通的时候。
	car := &countingCarrier{} // maxPay 为 0，即未知
	s := NewSender(car, 8, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	defer s.Close()

	if !s.Send(Header{Tunnel: 1}, make([]byte, 1200)) {
		t.Fatal("上限未知时不该丢包 —— 那会让连接建立初期全军覆没")
	}
	waitFor(t, func() bool { return car.n.Load() == 1 }, "数据报应当被发出")
	if got := s.Stats().TooLarge.Load(); got != 0 {
		t.Fatalf("上限未知时不该记 TooLarge，实际 %d", got)
	}
}

func TestSenderCountsCarrierFailuresSeparatelyFromTooLarge(t *testing.T) {
	car := &countingCarrier{fail: errors.New("承载断了")}
	s := NewSender(car, 8, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	defer s.Close()

	s.Send(Header{Tunnel: 1}, []byte("x"))
	waitFor(t, func() bool { return s.Stats().Failed.Load() == 1 }, "承载失败应当计入 Failed")
	if got := s.Stats().TooLarge.Load(); got != 0 {
		t.Fatalf("普通失败不该记成超限，实际 %d", got)
	}
}

// tooLargeErr 模拟承载返回的结构化超限错误。
type tooLargeErr struct{ max int }

func (e *tooLargeErr) Error() string           { return "载荷过大" }
func (e *tooLargeErr) DatagramMaxPayload() int { return e.max }

func TestSenderRecognisesStructuredTooLargeFromTheCarrier(t *testing.T) {
	// 发送时才发现超限（上限刚刚缩小）要归到 TooLarge 而不是 Failed，
	// 否则看板上会显示「承载在坏」，而实际只是包大了。
	car := &countingCarrier{fail: &tooLargeErr{max: 900}}
	s := NewSender(car, 8, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	defer s.Close()

	s.Send(Header{Tunnel: 1}, []byte("x"))
	waitFor(t, func() bool { return s.Stats().TooLarge.Load() == 1 },
		"结构化超限错误应当计入 TooLarge")
	if got := s.Stats().Failed.Load(); got != 0 {
		t.Fatalf("超限不该同时记成 Failed，实际 %d", got)
	}
}

func TestSenderRefusesToQueueAfterClose(t *testing.T) {
	// 关闭后入队的包永远不会被消费，缓冲也就永远回不了池。
	car := &countingCarrier{}
	s := NewSender(car, 8, nil)
	s.Close()
	s.Close() // 可重复调用

	if s.Send(Header{Tunnel: 1}, []byte("x")) {
		t.Fatal("关闭后不该再收包")
	}
}

// waitFor 轮询等一个条件成立，避免用 sleep 猜时间。
//
// 期限取 20 秒而不是 3 秒：它是「只有真挂死才该触发」的上界，不是被测量的
// 东西 —— 条件一满足就立刻返回，放宽不会让套件慢一毫秒。而 3 秒在
// `go test ./...`（跨包并行）加 -race 的负载下会偶发超时，
// 于是断言本身变成了一个偶发失败的门禁 —— 那比没有断言更糟，
// 因为它会让人开始习惯性重跑，直到有一天把真缺陷也重跑掉。
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待超时：%s", what)
}

func TestSenderFragmentsOversizePayloadsWhenReassemblyIsAllowed(t *testing.T) {
	// 默认（不置 FlagNoReassemble）走分片路径。默认要错向安全的一侧：
	// 一条本该丢弃的媒体流被分片只是多点延迟，而一条本该分片的批量流
	// 被丢弃是**静默数据丢失**。
	car := &countingCarrier{}
	car.maxPay.Store(500)
	s := NewSender(car, 32, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	defer s.Close()

	want := make([]byte, 2000)
	for i := range want {
		want[i] = byte(i % 251) // 非重复图案，拼错位置就能看出来
	}

	if !s.Send(Header{Tunnel: 3, FlowID: 9, DstPort: 5004}, want) {
		t.Fatal("允许重组时超限数据报应当被分片而不是丢弃")
	}
	// 屏障等的是「**最后一片**已经发出」，不是一个片数魔数。
	//
	// 这里原本写的是 `car.n.Load() >= 4`，而 2000 字节在 500 上限下实际要
	// **5** 片 —— 于是这条测试是偶发失败的：多数时候第 5 片与第 4 片几乎同时
	// 到达所以看不出来，但在 -race 下调度一变就会拿到 4 片去拼、拼不全。
	// 一个偶发失败的门禁比没有门禁更糟：它教人养成「重跑一次」的习惯。
	//
	// 按「最后一片」判而不是按数量判，是因为片数是实现细节（改一次头部大小
	// 或 MTU 就变），而「有没有发完」是这条测试真正关心的事。
	waitFor(t, func() bool {
		for _, raw := range car.frames() {
			if h, _, err := ParseFrame(raw); err == nil && h.LastFragment() {
				return true
			}
		}
		return false
	}, "应当发出完整的一组分片（含最后一片）")

	if got := s.Stats().Fragmented.Load(); got != 1 {
		t.Errorf("Fragmented 应当按「数据报」计 1，实际 %d", got)
	}
	if got := s.Stats().TooLarge.Load(); got != 0 {
		t.Errorf("分片成功不该记 TooLarge，实际 %d", got)
	}

	// 用重组器把它拼回来 —— 这是「发的和收的是同一份」的唯一硬证明。
	r := NewReassembler(ReassemblerConfig{})
	var got []byte
	for _, raw := range car.frames() {
		h, payload, err := ParseFrame(raw)
		if err != nil {
			t.Fatalf("发出的分片解析失败：%v", err)
		}
		if !h.Fragmented() {
			t.Fatalf("超限数据报的每一片都该置分片位：%+v", h)
		}
		if len(raw) > 500 {
			t.Fatalf("分片帧 %d 字节，超过上限 500 —— 分片没起作用", len(raw))
		}
		if h.DgramID == 0 {
			t.Fatal("分片必须带 DgramID，否则并发数据报会被拼混")
		}
		d, complete, err := r.Push(h, payload)
		if err != nil {
			t.Fatalf("重组自己发出的分片失败：%v", err)
		}
		if complete {
			got = bytes.Clone(d)
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatal("分片再重组后与原文不符")
	}
}

func TestSenderDropsOversizeOnRealtimePathInsteadOfFragmenting(t *testing.T) {
	// 实时路径必须丢：分片放大丢包影响（任一片丢失整个数据报作废），
	// 而一帧迟到的音频等于丢了还白占带宽。
	car := &countingCarrier{}
	car.maxPay.Store(500)
	s := NewSender(car, 32, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	defer s.Close()

	if s.Send(Header{Tunnel: 1, Flags: FlagNoReassemble}, make([]byte, 2000)) {
		t.Fatal("实时路径上超限数据报应当被丢弃")
	}
	if got := s.Stats().TooLarge.Load(); got != 1 {
		t.Errorf("TooLarge 应为 1，实际 %d", got)
	}
	if got := s.Stats().Fragmented.Load(); got != 0 {
		t.Errorf("实时路径不该分片，实际分了 %d 个", got)
	}
	// 超限不该被误记成队列满 —— 两者对应的运维动作完全不同
	// （等 PMTUD / 降包长 vs 加带宽 / 降码率）。
	if got := s.Stats().QueueFull.Load(); got != 0 {
		t.Errorf("超限不该被记成队列满，实际 %d", got)
	}
	// 上限之内的照常发。
	if !s.Send(Header{Tunnel: 1, Flags: FlagNoReassemble}, make([]byte, 100)) {
		t.Fatal("上限之内的数据报不该被丢")
	}
}

func TestSenderClearsNoReassembleOnFragmentsItProduces(t *testing.T) {
	// FlagNoReassemble 与分片位同时置上会让对端无从判断该不该重组。
	// 这个组合必须在发出前就消除，而不是指望对端猜。
	car := &countingCarrier{}
	car.maxPay.Store(400)
	s := NewSender(car, 32, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	defer s.Close()

	// 刻意同时给一个「无关的」标志位与分片需求。
	if !s.Send(Header{Tunnel: 1, Flags: 0}, make([]byte, 1200)) {
		t.Fatal("应当分片成功")
	}
	waitFor(t, func() bool { return car.n.Load() >= 3 }, "应当发出多片")

	for i, raw := range car.frames() {
		h, _, err := ParseFrame(raw)
		if err != nil {
			t.Fatal(err)
		}
		if h.NoReassemble() {
			t.Fatalf("第 %d 片同时置了分片位与 FlagNoReassemble —— 对端无从判断", i)
		}
	}
}

func TestSenderRefusesDatagramsBeyondTheLengthFieldCapacity(t *testing.T) {
	// TotalLen 是 uint16，装不下更大的数据报。必须当场拒绝并计数，
	// 而不是让 uint16 回绕产生一个「长度看起来很小」的分片头。
	car := &countingCarrier{}
	car.maxPay.Store(1200)
	s := NewSender(car, 32, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	defer s.Close()

	if s.Send(Header{Tunnel: 1}, make([]byte, MaxPayload+1)) {
		t.Fatal("超过 TotalLen 表示上限的数据报应当被拒")
	}
	if got := s.Stats().TooLarge.Load(); got == 0 {
		t.Error("应当被计数")
	}
}

func TestSenderReprobesTheMTUSoARaisedPathLimitIsSeen(t *testing.T) {
	// 承载学到的上限**只会变小**：唯一来源是 SendDatagram 返回
	// DatagramTooLargeError，而 Send 的前置检查会让更大的包永远到不了
	// SendDatagram。于是一次瞬时的小 MTU 会让实时隧道对某一段包长
	// **永久 100% 丢包**（例如 1228~1399 字节的音视频包），直到承载重建 ——
	// 而 QUIC 自己的 DPLPMTUD 明明会把真实上限探上去。
	//
	// 重探在实时路径上是**免费**的：这个包本来就要被丢掉。
	car := &countingCarrier{}
	car.maxPay.Store(400)
	s := NewSender(car, 32, nil)

	now := time.Now()
	s.now = func() time.Time { return now }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	defer s.Close()

	big := make([]byte, 1000)
	rt := Header{Tunnel: 1, Flags: FlagNoReassemble}

	// 刚建好：不该立刻探（那时的上限是准确的，白丢一个包）。
	if s.Send(rt, big) {
		t.Fatal("刚建好的发送器不该立刻拿超限包去探")
	}
	if got := s.Stats().MTUProbes.Load(); got != 0 {
		t.Fatalf("刚建好时不该有重探，实际 %d", got)
	}

	// 时间过去一个间隔：路径变宽了（承载现在允许 2000）。
	now = now.Add(MTUProbeInterval + time.Second)
	car.maxPay.Store(2000)
	// 但 Send 里读到的是承载**当前**的值，所以这一包直接走正常路径。
	// 真正要测的是「上限没变大时也会去探一次」——把它调回小值。
	car.maxPay.Store(400)

	if !s.Send(rt, big) {
		t.Fatal("到了重探时机，超限包应当被放出去试一次（这个包本来就要被丢）")
	}
	if got := s.Stats().MTUProbes.Load(); got != 1 {
		t.Fatalf("MTUProbes 应为 1，实际 %d", got)
	}

	// 紧接着的超限包不该再探 —— 一场突发里每包都去撞承载等于没有前置检查。
	if s.Send(rt, big) {
		t.Fatal("同一个间隔内只该探一次")
	}
	if got := s.Stats().MTUProbes.Load(); got != 1 {
		t.Fatalf("MTUProbes 仍应为 1，实际 %d", got)
	}
	if got := s.Stats().TooLarge.Load(); got != 2 {
		t.Fatalf("没探的那两包应当计入 TooLarge，实际 %d", got)
	}
}

func TestSenderDoesNotProbeOnTheBulkPath(t *testing.T) {
	// 批量路径**不**重探：上限偏小只会让分片多一些（效率问题），
	// 而拿一个必然失败的整包去试会让这个数据报从「分片后能到」
	// 变成「丢了」——那是功能问题。
	car := &countingCarrier{}
	car.maxPay.Store(400)
	s := NewSender(car, 64, nil)

	now := time.Now().Add(24 * time.Hour) // 早就该重探了
	s.now = func() time.Time { return now }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	defer s.Close()

	if !s.Send(Header{Tunnel: 1}, make([]byte, 1000)) {
		t.Fatal("批量路径应当分片成功")
	}
	if got := s.Stats().MTUProbes.Load(); got != 0 {
		t.Errorf("批量路径不该重探，实际 %d", got)
	}
	if got := s.Stats().Fragmented.Load(); got != 1 {
		t.Errorf("批量路径应当分片，实际 Fragmented=%d", got)
	}
}
