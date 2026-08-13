package udpflow

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// fragmentAll 把一个完整数据报按 mtu 切片，返回分片帧序列。
//
// 这是测试自己的切片器，与 Sender 的实现独立 —— 用被测代码去生成
// 测试输入，会让「切片和重组用同一个错误假设」的缺陷双双隐身。
func fragmentAll(t *testing.T, h Header, payload []byte, chunk int) [][]byte {
	t.Helper()

	var out [][]byte
	total := len(payload)
	for off := 0; off < total; off += chunk {
		end := min(off+chunk, total)
		fh := h
		fh.Flags |= FlagFragmented
		if end == total {
			fh.Flags |= FlagLastFrag
		}
		fh.FragOff = uint16(off)
		fh.FragLen = uint16(end - off)
		fh.TotalLen = uint16(total)
		frame, err := fh.AppendTo(nil, payload[off:end])
		if err != nil {
			t.Fatalf("组分片帧失败（off=%d）：%v", off, err)
		}
		out = append(out, frame)
	}
	return out
}

// pushFrames 把一批分片帧交进重组器，返回最后一次的结果。
func pushFrames(t *testing.T, r *Reassembler, frames [][]byte) ([]byte, bool) {
	t.Helper()

	var done []byte
	var ok bool
	for i, f := range frames {
		h, payload, err := ParseFrame(f)
		if err != nil {
			t.Fatalf("第 %d 片解析失败：%v", i, err)
		}
		d, complete, err := r.Push(h, payload)
		if err != nil {
			t.Fatalf("第 %d 片重组失败：%v", i, err)
		}
		if complete {
			done, ok = bytes.Clone(d), true
		}
	}
	return done, ok
}

func TestReassemblesInOrderFragments(t *testing.T) {
	r := NewReassembler(ReassemblerConfig{})
	want := bytes.Repeat([]byte("一帧较大的 IoT 报文"), 200) // 约 5.4 KiB

	frames := fragmentAll(t, Header{Tunnel: 7, FlowID: 42, DstPort: 5000, DgramID: 1},
		want, 1100)
	if len(frames) < 4 {
		t.Fatalf("测试前置条件不成立：只切了 %d 片", len(frames))
	}

	got, ok := pushFrames(t, r, frames)
	if !ok {
		t.Fatal("所有分片都交进去了，应当重组完成")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("重组结果与原文不符（长度 %d vs %d）", len(got), len(want))
	}
	if n := r.Stats().Completed.Load(); n != 1 {
		t.Errorf("Completed 应为 1，实际 %d", n)
	}
	if n := r.Stats().Fragments.Load(); int(n) != len(frames) {
		t.Errorf("Fragments 应为 %d，实际 %d", len(frames), n)
	}
	// 重组完必须把状态清掉，否则就是内存泄漏。
	if c, b := r.Pending(); c != 0 || b != 0 {
		t.Errorf("重组完成后不该还留着状态，实际 %d 条 / %d 字节", c, b)
	}
}

func TestReassemblesOutOfOrderFragments(t *testing.T) {
	// UDP 无序。分片乱序到达是常态，不是异常。
	r := NewReassembler(ReassemblerConfig{})
	want := bytes.Repeat([]byte("乱序"), 900)

	frames := fragmentAll(t, Header{Tunnel: 1, FlowID: 1, DgramID: 9}, want, 500)
	if len(frames) < 3 {
		t.Fatalf("片数太少：%d", len(frames))
	}
	// 倒序交进去。
	reversed := make([][]byte, len(frames))
	for i := range frames {
		reversed[i] = frames[len(frames)-1-i]
	}

	got, ok := pushFrames(t, r, reversed)
	if !ok {
		t.Fatal("倒序交付也应当能重组完成")
	}
	if !bytes.Equal(got, want) {
		t.Fatal("倒序重组的结果与原文不符")
	}
}

func TestConcurrentDatagramsOnOneFlowDoNotCorruptEachOther(t *testing.T) {
	// 这条钉住那个**没有 dgramID 就必然发生**的静默数据损坏。
	//
	// 两个**长度相同**的数据报在同一条流上交错到达。只靠
	// (fragOff, totalLen) 分不开它们 —— 重组器会把甲的一半和乙的一半
	// 拼在一起交付。所以帧格式必须带数据报标识。
	r := NewReassembler(ReassemblerConfig{})

	a := bytes.Repeat([]byte("A"), 3000)
	b := bytes.Repeat([]byte("B"), 3000) // 刻意同长度

	base := Header{Tunnel: 3, FlowID: 77, DstPort: 5004}
	ha, hb := base, base
	ha.DgramID = 100
	hb.DgramID = 101

	fa := fragmentAll(t, ha, a, 1000)
	fb := fragmentAll(t, hb, b, 1000)
	if len(fa) != len(fb) || len(fa) < 3 {
		t.Fatalf("测试前置条件不成立：%d vs %d 片", len(fa), len(fb))
	}

	// 交错交付：a0 b0 a1 b1 a2 b2 …
	var gotA, gotB []byte
	for i := range fa {
		for _, f := range [][]byte{fa[i], fb[i]} {
			h, payload, err := ParseFrame(f)
			if err != nil {
				t.Fatal(err)
			}
			d, complete, err := r.Push(h, payload)
			if err != nil {
				t.Fatalf("重组报错：%v", err)
			}
			if complete {
				if h.DgramID == 100 {
					gotA = bytes.Clone(d)
				} else {
					gotB = bytes.Clone(d)
				}
			}
		}
	}

	if !bytes.Equal(gotA, a) {
		t.Errorf("甲的重组结果被污染了：前 20 字节 %q", firstN(gotA, 20))
	}
	if !bytes.Equal(gotB, b) {
		t.Errorf("乙的重组结果被污染了：前 20 字节 %q", firstN(gotB, 20))
	}
	if n := r.Stats().Completed.Load(); n != 2 {
		t.Errorf("应当重组出 2 个数据报，实际 %d", n)
	}
}

func firstN(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

func TestOverlappingFragmentsAreRejectedAndCounted(t *testing.T) {
	// 重叠分片是 IP 分片时代的经典攻击手法（teardrop / rose）：
	// 让检查设备与终端看到不同的内容。正常发送方按固定步长切片，
	// 绝不会重叠 —— 所以 Overlapping 非零本身就是安全信号。
	r := NewReassembler(ReassemblerConfig{})

	h := Header{Tunnel: 1, FlowID: 1, DgramID: 5, Flags: FlagFragmented}

	// 第一片：[0, 100)
	f1 := h
	f1.FragOff, f1.FragLen, f1.TotalLen = 0, 100, 300
	frame1, err := f1.AppendTo(nil, bytes.Repeat([]byte("x"), 100))
	if err != nil {
		t.Fatal(err)
	}
	hh, pp, err := ParseFrame(frame1)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Push(hh, pp); err != nil {
		t.Fatalf("第一片不该被拒：%v", err)
	}

	// 第二片：[50, 150) —— 与第一片重叠。
	f2 := h
	f2.FragOff, f2.FragLen, f2.TotalLen = 50, 100, 300
	frame2, err := f2.AppendTo(nil, bytes.Repeat([]byte("y"), 100))
	if err != nil {
		t.Fatal(err)
	}
	hh2, pp2, err := ParseFrame(frame2)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Push(hh2, pp2); err == nil {
		t.Fatal("重叠分片必须被拒")
	}
	if n := r.Stats().Overlapping.Load(); n != 1 {
		t.Errorf("Overlapping 应为 1，实际 %d —— 这是安全信号，不能漏计", n)
	}
	// 整个数据报必须作废：留着一个已被污染的缓冲比丢掉危险。
	if c, _ := r.Pending(); c != 0 {
		t.Errorf("遇到重叠后该数据报应当整体作废，实际还留着 %d 条", c)
	}
}

func TestDuplicateFragmentsAreToleratedNotTreatedAsOverlap(t *testing.T) {
	// 网络会重复包。把完全相同的重复片当成攻击会让正常流量在丢包重传的
	// 链路上大面积失败。
	r := NewReassembler(ReassemblerConfig{})
	want := bytes.Repeat([]byte("z"), 400)
	frames := fragmentAll(t, Header{Tunnel: 1, FlowID: 1, DgramID: 7}, want, 200)

	// 把每一片交两遍。
	doubled := make([][]byte, 0, len(frames)*2)
	for _, f := range frames {
		doubled = append(doubled, f, f)
	}

	got, ok := pushFrames(t, r, doubled)
	if !ok {
		t.Fatal("重复片不该妨碍重组完成")
	}
	if !bytes.Equal(got, want) {
		t.Fatal("重组结果不对")
	}
	if n := r.Stats().Overlapping.Load(); n != 0 {
		t.Errorf("完全重复的片不该被记成重叠，实际 %d", n)
	}
	if n := r.Stats().Duplicated.Load(); n == 0 {
		t.Error("重复片应当被计数 —— 它是链路质量信号")
	}
}

func TestIncompleteDatagramsExpireAndReleaseTheirBuffers(t *testing.T) {
	// 重组器是数据面上唯一有状态的部件。攻击者只要不停发「某个大数据报的
	// 第一片」就能让接收方无限攒内存，而每一片都是合法帧。
	r := NewReassembler(ReassemblerConfig{Timeout: 50 * time.Millisecond})

	now := time.Now()
	r.now = func() time.Time { return now }

	h := Header{Tunnel: 1, FlowID: 1, DgramID: 1, Flags: FlagFragmented}
	h.FragOff, h.FragLen, h.TotalLen = 0, 100, 60000
	frame, err := h.AppendTo(nil, bytes.Repeat([]byte("x"), 100))
	if err != nil {
		t.Fatal(err)
	}
	hh, pp, err := ParseFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Push(hh, pp); err != nil {
		t.Fatal(err)
	}

	c, b := r.Pending()
	if c != 1 || b != 60000 {
		t.Fatalf("应当留着 1 条 / 60000 字节，实际 %d / %d", c, b)
	}

	// 时间前进到超时之后，再来一片（任何一片都会触发清理）。
	now = now.Add(time.Second)
	h2 := h
	h2.DgramID = 2
	h2.TotalLen = 100
	h2.Flags |= FlagLastFrag
	frame2, err := h2.AppendTo(nil, bytes.Repeat([]byte("y"), 100))
	if err != nil {
		t.Fatal(err)
	}
	hh2, pp2, err := ParseFrame(frame2)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Push(hh2, pp2); err != nil {
		t.Fatal(err)
	}

	if n := r.Stats().TimedOut.Load(); n != 1 {
		t.Errorf("超时的数据报应当被计数，实际 %d", n)
	}
	// 缓冲必须真的还回去了 —— 只删 map 不减字节数就是账目泄漏，
	// 表现为「明明没积压却报缓冲已满」。
	if _, b := r.Pending(); b != 0 {
		t.Errorf("超时后字节账应当归零，实际 %d", b)
	}
}

func TestReassemblerRefusesBeyondItsPendingCeiling(t *testing.T) {
	r := NewReassembler(ReassemblerConfig{MaxPending: 2, MaxBytes: 1 << 20})

	push := func(dgramID uint32) error {
		h := Header{Tunnel: 1, FlowID: 1, DgramID: dgramID, Flags: FlagFragmented}
		h.FragOff, h.FragLen, h.TotalLen = 0, 10, 1000
		frame, err := h.AppendTo(nil, bytes.Repeat([]byte("x"), 10))
		if err != nil {
			t.Fatal(err)
		}
		hh, pp, err := ParseFrame(frame)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = r.Push(hh, pp)
		return err
	}

	if err := push(1); err != nil {
		t.Fatalf("第 1 条不该被拒：%v", err)
	}
	if err := push(2); err != nil {
		t.Fatalf("第 2 条不该被拒：%v", err)
	}
	if err := push(3); err == nil {
		t.Fatal("超出并发重组上限的应当被拒")
	}
	if n := r.Stats().TableFull.Load(); n != 1 {
		t.Errorf("TableFull 应为 1，实际 %d", n)
	}
}

func TestReassemblerRefusesBeyondItsByteCeiling(t *testing.T) {
	// 只限条数不限字节的话，MaxPending 个「宣称 65535 字节」的数据报
	// 就能占掉几百 MiB —— 而每一条都在条数配额内。
	r := NewReassembler(ReassemblerConfig{MaxPending: 100, MaxBytes: 100000})

	push := func(dgramID uint32, total uint16) error {
		h := Header{Tunnel: 1, FlowID: 1, DgramID: dgramID, Flags: FlagFragmented}
		h.FragOff, h.FragLen, h.TotalLen = 0, 10, total
		frame, err := h.AppendTo(nil, bytes.Repeat([]byte("x"), 10))
		if err != nil {
			t.Fatal(err)
		}
		hh, pp, err := ParseFrame(frame)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = r.Push(hh, pp)
		return err
	}

	// 两条 60000 字节的就超过 100000 的上限。
	if err := push(1, 60000); err != nil {
		t.Fatalf("第 1 条不该被拒：%v", err)
	}
	if err := push(2, 60000); err == nil {
		t.Fatal("超出字节上限的应当被拒 —— 否则条数配额形同虚设")
	}
	if n := r.Stats().BytesFull.Load(); n != 1 {
		t.Errorf("BytesFull 应为 1，实际 %d", n)
	}
	// 条数远未到上限，所以不能记成 TableFull —— 两者对应不同的运维动作。
	if n := r.Stats().TableFull.Load(); n != 0 {
		t.Errorf("字节超限不该被记成条数超限，实际 %d", n)
	}
}

func TestReassemblerRejectsUnfragmentedFrames(t *testing.T) {
	// 非分片帧进重组器意味着调用方的分派逻辑写错了。
	// 静默接受会掩盖它 —— 那条数据报会被当成「只有一片的分片」
	// 走一遍重组，多一次拷贝且多一个表项。
	r := NewReassembler(ReassemblerConfig{})
	if _, _, err := r.Push(Header{Tunnel: 1, FlowID: 1}, []byte("x")); err == nil {
		t.Fatal("非分片帧应当被拒")
	}
}

func TestReassemblerRejectsSelfContradictoryFragments(t *testing.T) {
	// Push 可能被直接调用（测试、将来的其他承载），而这段代码会拿这些
	// 数字去做切片下标 —— 信任上游是可选的，越界 panic 不是。
	r := NewReassembler(ReassemblerConfig{})

	cases := []struct {
		name string
		h    Header
		load []byte
	}{
		{"FragLen 与载荷不符",
			Header{Flags: FlagFragmented, FragOff: 0, FragLen: 50, TotalLen: 100},
			bytes.Repeat([]byte("x"), 10)},
		{"分片越过 TotalLen",
			Header{Flags: FlagFragmented, FragOff: 95, FragLen: 10, TotalLen: 100},
			bytes.Repeat([]byte("x"), 10)},
		{"TotalLen 为 0",
			Header{Flags: FlagFragmented, FragOff: 0, FragLen: 0, TotalLen: 0},
			nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := r.Push(c.h, c.load); err == nil {
				t.Fatal("应当被拒")
			}
		})
	}
	if n := r.Stats().Malformed.Load(); n == 0 {
		t.Error("自相矛盾的分片应当被计数")
	}
}

func TestReassemblerRefusesTooManyFragmentsPerDatagram(t *testing.T) {
	// 前三条界（并发数、字节数、超时）都拦不住只发**稀疏 1 字节分片**的
	// 对端：它们既不占多少字节、不超并发数，还在超时窗口之内。
	// 可 received 会长到 TotalLen 那么多条（最多 65535），而 overlapKind
	// 是线性扫描、insertSpan 是 O(n) 重建 —— 单个数据报 O(n²) ≈ 2×10⁹ 次
	// 比较，**持着锁跑在数据报解复用循环上**。
	//
	// 实测约 279 KB/s 的完全合法分片流量就能把一条承载的解复用循环
	// 钉在 100% CPU 上，而那条循环是这个 agent 上所有 UDP 隧道共用的。
	r := NewReassembler(ReassemblerConfig{MaxFragments: 8})

	// 稀疏：每片 1 字节，偏移隔一个 —— 于是 insertSpan 永远合并不了。
	var lastErr error
	for i := 0; i < 20; i++ {
		h := Header{
			Tunnel: 1, FlowID: 1, DgramID: 1, TotalLen: 4096,
			Flags:   FlagFragmented,
			FragOff: uint16(i * 2), FragLen: 1,
		}
		_, _, err := r.Push(h, []byte{byte(i)})
		if err != nil {
			lastErr = err
			break
		}
	}
	if !errors.Is(lastErr, ErrReasmTooManyFrags) {
		t.Fatalf("超过分片条数上限必须被拒，实际最后一个错误：%v", lastErr)
	}
	if got := r.Stats().TooManyFrags.Load(); got != 1 {
		t.Errorf("TooManyFrags 应为 1，实际 %d", got)
	}
	// 整个数据报要被丢掉，缓冲要归还 —— 否则这条路径就成了新的泄漏点。
	if n, b := r.Pending(); n != 0 || b != 0 {
		t.Errorf("被拒的数据报应当被丢弃并归还字节，实际 %d 条 / %d 字节", n, b)
	}
}

func TestReassemblerTreatsARepeatedFragmentAsDuplicateNotTeardrop(t *testing.T) {
	// insertSpan 会**合并**相邻区间。第一版的重复判据是「与集合里某条
	// (off,length) 逐字相等」，于是一个完全正常的重复片（它的范围已经被
	// 并进一个更大的区间）会落进 overlapPartial —— 整个数据报被作废，
	// 还误报一次 teardrop 安全信号。
	//
	// 一个网络重复包就能触发。而 Overlapping 是我们打算让人认真看的
	// 安全指标，误报会让它失去意义。
	r := NewReassembler(ReassemblerConfig{})
	mk := func(off, ln int) Header {
		return Header{
			Tunnel: 1, FlowID: 1, DgramID: 1, TotalLen: 300,
			Flags:   FlagFragmented,
			FragOff: uint16(off), FragLen: uint16(ln),
		}
	}
	a := bytes.Repeat([]byte{0xAA}, 100)
	b := bytes.Repeat([]byte{0xBB}, 100)

	if _, _, err := r.Push(mk(0, 100), a); err != nil {
		t.Fatal(err)
	}
	// 相邻片：insertSpan 会把它与前一片合并成 [0,200)。
	if _, _, err := r.Push(mk(100, 100), b); err != nil {
		t.Fatal(err)
	}

	// 现在重发第一片。它在集合里已经没有一条与它逐字相等的记录了。
	if _, _, err := r.Push(mk(0, 100), a); err != nil {
		t.Fatalf("内容相同的重复片只该被计数，不该报错：%v", err)
	}
	if got := r.Stats().Duplicated.Load(); got != 1 {
		t.Errorf("Duplicated 应为 1，实际 %d", got)
	}
	if got := r.Stats().Overlapping.Load(); got != 0 {
		t.Errorf("一个网络重复包不该被记成 teardrop 安全信号，实际 %d", got)
	}
	// 数据报还活着，最后一片能把它凑齐。
	full, ok, err := r.Push(mk(200, 100), bytes.Repeat([]byte{0xCC}, 100))
	if err != nil || !ok {
		t.Fatalf("重复片不该把数据报作废：ok=%v err=%v", ok, err)
	}
	if len(full) != 300 {
		t.Errorf("重组结果长度应为 300，实际 %d", len(full))
	}
}

func TestReassemblerStillRejectsAnOverwriteAttempt(t *testing.T) {
	// 反面：范围重复但**内容不同** = 真的在试图改写已收到的字节。
	// 合并区间反而让这一判定变强了（能拿缓冲里的字节直接比）。
	r := NewReassembler(ReassemblerConfig{})
	mk := func(off, ln int) Header {
		return Header{
			Tunnel: 1, FlowID: 1, DgramID: 1, TotalLen: 200,
			Flags:   FlagFragmented,
			FragOff: uint16(off), FragLen: uint16(ln),
		}
	}
	if _, _, err := r.Push(mk(0, 100), bytes.Repeat([]byte{0xAA}, 100)); err != nil {
		t.Fatal(err)
	}
	_, _, err := r.Push(mk(0, 100), bytes.Repeat([]byte{0xEE}, 100))
	if !errors.Is(err, ErrReasmOverlap) {
		t.Fatalf("同范围不同内容必须被拒（那是改写已收字节的手法），实际：%v", err)
	}
	if got := r.Stats().Overlapping.Load(); got != 1 {
		t.Errorf("Overlapping 应为 1，实际 %d", got)
	}
	if got := r.Stats().Duplicated.Load(); got != 0 {
		t.Errorf("内容不同不该被算成重复，实际 %d", got)
	}
}

func TestReassemblerStillRejectsPartialOverlap(t *testing.T) {
	// 经典 teardrop 形状：有新字节也有旧字节。
	r := NewReassembler(ReassemblerConfig{})
	mk := func(off, ln int) Header {
		return Header{
			Tunnel: 1, FlowID: 1, DgramID: 1, TotalLen: 300,
			Flags:   FlagFragmented,
			FragOff: uint16(off), FragLen: uint16(ln),
		}
	}
	if _, _, err := r.Push(mk(0, 100), bytes.Repeat([]byte{0xAA}, 100)); err != nil {
		t.Fatal(err)
	}
	_, _, err := r.Push(mk(50, 100), bytes.Repeat([]byte{0xEE}, 100))
	if !errors.Is(err, ErrReasmOverlap) {
		t.Fatalf("部分重叠必须被拒，实际：%v", err)
	}
}
