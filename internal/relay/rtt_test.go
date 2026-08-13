package relay

import (
	"testing"
	"time"
)

func TestRTTOnlyCountsAMatchingPong(t *testing.T) {
	// seq 用随机数而不是自增，理由是自增可猜：一个恶意 agent 能预先把
	// Pong(1..N) 灌进控制流。那些帧在对应 ping 发出前会被丢弃，正常情况下没事；
	// 但只要读循环有一瞬间落后（GC、调度），一个已经排在缓冲里的 Pong 就可能
	// 被当成刚发出那个 ping 的回应 —— 于是 RTT 被报成接近 0。
	var r rttState
	now := time.Now()

	seq := r.beginPing(now)
	if seq == 0 {
		t.Fatal("第一次应当能领到序号")
	}

	// 不匹配的 seq 必须被静默忽略，**绝不**产生观测。
	if _, ok := r.notePong(seq+1, now.Add(time.Millisecond)); ok {
		t.Fatal("seq 不匹配的 Pong 不该被算成观测 —— 那正是把 RTT 报成接近 0 的路径")
	}
	if _, ok := r.notePong(0, now.Add(time.Millisecond)); ok {
		t.Fatal("seq=0 是保留值，不该被接受")
	}

	rtt, ok := r.notePong(seq, now.Add(20*time.Millisecond))
	if !ok {
		t.Fatal("匹配的 Pong 应当产生观测")
	}
	if rtt != 20*time.Millisecond {
		t.Fatalf("RTT 应为 20ms，实际 %s", rtt)
	}

	// 同一个 seq 不能被用两次（重放）。
	if _, ok := r.notePong(seq, now.Add(30*time.Millisecond)); ok {
		t.Fatal("同一个 seq 的第二个 Pong 不该再产生观测")
	}
}

func TestOnlyOnePingInFlight(t *testing.T) {
	// 只允许一个在飞的 ping：「seq → 发出时刻」做成表的话，那张表的清理
	// 就成了一个必须想清楚的问题（没回的 ping 会积累）。
	// 一个 slot 换掉一整类无界增长。
	var r rttState
	now := time.Now()

	seq := r.beginPing(now)
	if seq == 0 {
		t.Fatal("第一次应当能领到序号")
	}
	if again := r.beginPing(now.Add(time.Second)); again != 0 {
		t.Fatal("已有在飞的 ping 时不该再领到序号")
	}

	// 超时之后 slot 要能空出来，否则一次丢包会让这条会话**永久**不再测 RTT。
	if after := r.beginPing(now.Add(pingTimeout + time.Second)); after == 0 {
		t.Fatal("超时之后应当允许发下一个 ping")
	}
	// 而超时**不该**被算成一次观测（那会让一次丢包污染分位数）。
	if r.n != 0 {
		t.Fatalf("超时不该产生观测，实际有 %d 个样本", r.n)
	}
}

func TestRTTPercentilesReportZeroUntilThereIsAnObservation(t *testing.T) {
	// 0 表示**还没测到**，不是 0 毫秒。控制台必须把这两者区分开 ——
	// 0 会被读成「测过，是零」，那是撒谎。
	s := &Session{}
	if got := s.LastRTT(); got != 0 {
		t.Fatalf("还没测到时应当是 0，实际 %s", got)
	}
	p50, p95, p99 := s.RTTPercentiles()
	if p50 != 0 || p95 != 0 || p99 != 0 {
		t.Fatalf("还没测到时三个分位数都该是 0：%s / %s / %s", p50, p95, p99)
	}

	// 有观测之后才给数字。
	now := time.Now()
	for i := range 10 {
		seq := s.rtt.beginPing(now)
		if seq == 0 {
			t.Fatalf("第 %d 次领不到序号", i)
		}
		if _, ok := s.rtt.notePong(seq, now.Add(time.Duration(i+1)*time.Millisecond)); !ok {
			t.Fatalf("第 %d 次观测失败", i)
		}
	}
	p50, p95, p99 = s.RTTPercentiles()
	if p50 <= 0 || p95 <= 0 || p99 <= 0 {
		t.Fatalf("有观测之后必须给出数字：%s / %s / %s", p50, p95, p99)
	}
	// 分位数必须单调不减 —— 反了说明排序或取秩写错了。
	if !(p50 <= p95 && p95 <= p99) {
		t.Fatalf("分位数必须单调不减：%s / %s / %s", p50, p95, p99)
	}
	// p50 应当落在中间附近（样本是 1..10ms）。
	if p50 < 4*time.Millisecond || p50 > 7*time.Millisecond {
		t.Errorf("p50 看起来不像中位数：%s（样本是 1..10ms）", p50)
	}
}

func TestRTTRingKeepsOnlyTheRecentWindow(t *testing.T) {
	// 环形缓冲有界：分位数要的是分布而不是历史，
	// 而无界的样本表就是一个随运行时长增长的内存泄漏。
	s := &Session{}
	now := time.Now()
	for i := range rttRingSize * 3 {
		seq := s.rtt.beginPing(now)
		if _, ok := s.rtt.notePong(seq, now.Add(time.Duration(i+1)*time.Microsecond)); !ok {
			t.Fatalf("第 %d 次观测失败", i)
		}
	}
	if got := len(s.rtt.samples()); got != rttRingSize {
		t.Fatalf("样本数应当被环形缓冲封顶在 %d，实际 %d", rttRingSize, got)
	}
}
