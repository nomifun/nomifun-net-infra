package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestArgon2ConcurrencyIsBounded 是这道闸存在的全部理由，也是它内存上界的**唯一**断言。
//
// 每次密码校验分配 64 MiB，而 POST /api/login 与 /api/setup 都未鉴权 ——
// 任何人都能让中继做这件事，用一个**不存在的**用户名也算（等时处理会跑一次
// 假校验）。没有闸时并发数就是放大倍数：一百个并发 = 6.4 GiB，中继被 OOM 杀掉，
// 名下所有隧道同时断掉。
//
// 这条测量的是**峰值同时在飞数**。没有它，argonConcurrency 这个常量就只是一个
// 没人验证过的数字 —— 而它是整个内存上界的来源。
func TestArgon2ConcurrencyIsBounded(t *testing.T) {
	var inFlight, peak atomic.Int64

	const callers = 24
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = withArgonSlot(func() {
				cur := inFlight.Add(1)
				for {
					old := peak.Load()
					if cur <= old || peak.CompareAndSwap(old, cur) {
						break
					}
				}
				// 停一下，让并发真的重叠 —— 不停的话每个 fn 快到几乎不可能撞上，
				// 于是峰值恒为 1，测试变成空转。
				time.Sleep(5 * time.Millisecond)
				inFlight.Add(-1)
			})
		}()
	}
	wg.Wait()

	if p := peak.Load(); p > argonConcurrency {
		t.Fatalf("峰值并发 %d 超过上限 %d —— 内存上界（%d × 64 MiB）失效",
			p, argonConcurrency, argonConcurrency)
	}
	if peak.Load() < 2 && argonConcurrency >= 2 {
		t.Errorf("峰值并发只有 %d，说明并发没真的重叠，本测试是空转的", peak.Load())
	}
	// 闸必须被完全归还，否则下一次调用会永久排不上队。
	if n := len(argonGate); n != 0 {
		t.Errorf("闸没归零，还占着 %d 个槽位 —— 槽位泄漏会让管理面永久 503", n)
	}
}

// TestArgonSlotIsReleasedEvenOnPanic 钉住「用 defer 而不是自己记账」这条决定。
//
// 任何「计数器 +1 / -1」的写法都有一条出口会被漏掉，而漏掉的后果是槽位永久
// 泄漏 → 管理面**永久** 503，连正确口令都进不来。这是本轮设计评审里被点名的
// 一个真 bug（waiting 只增不减）。
func TestArgonSlotIsReleasedEvenOnPanic(t *testing.T) {
	func() {
		defer func() { _ = recover() }()
		_ = withArgonSlot(func() { panic("boom") })
	}()
	if n := len(argonGate); n != 0 {
		t.Fatalf("panic 之后槽位没归还，还占着 %d 个 —— 管理面会永久 503", n)
	}
	// 归还之后必须还能正常用。
	if err := withArgonSlot(func() {}); err != nil {
		t.Fatalf("槽位归还后应当能继续用：%v", err)
	}
}

// TestCorrectPasswordStillWorksAfterAFlood 是复审明确要求的那条断言。
//
// 洪水退去之后，正确口令必须还能登进去。做不到就意味着这道防护把它要保护的
// 东西一起关掉了 —— 那比没有防护更糟（攻击者只要打一轮就能永久锁死管理面）。
func TestCorrectPasswordStillWorksAfterAFlood(t *testing.T) {
	db := openTestDB(t)
	const user, pass = "ops", "a-very-long-password"
	if err := db.CreateAdmin(t.Context(), user, pass, false); err != nil {
		t.Fatal(err)
	}

	// 一轮并发洪水（错口令 + 不存在的用户名各一半）。
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				_, _, _ = db.VerifyAdmin(context.Background(), user, "wrong-wrong-wrong")
			} else {
				_, _, _ = db.VerifyAdmin(context.Background(), "no-such-user", "whatever")
			}
		}(i)
	}
	wg.Wait()

	if n := len(argonGate); n != 0 {
		t.Fatalf("洪水之后闸没归零（%d）—— 后续登录会永久排不上队", n)
	}
	_, ok, err := db.VerifyAdmin(t.Context(), user, pass)
	if err != nil {
		t.Fatalf("洪水退去后正确口令不该拿到错误：%v", err)
	}
	if !ok {
		t.Fatal("洪水退去后正确口令登不进去 —— 这道防护把它要保护的东西一起关掉了")
	}
}

// TestBusyIsNotReportedAsBadCredentials 钉住三返回值那个设计。
//
// 合成一个 bool 的话，洪水期间正常用户会看到「用户名或密码错误」→ 去查密码
// （查错方向），而上层限速器还会把这次失败记到他头上。
func TestBusyIsNotReportedAsBadCredentials(t *testing.T) {
	// 把闸占满，让下一次校验必然超时。
	for range argonConcurrency {
		argonGate <- struct{}{}
	}
	t.Cleanup(func() {
		for len(argonGate) > 0 {
			<-argonGate
		}
	})

	// 缩短等待，否则这条测试要跑 argonWait 那么久。
	orig := argonWaitForTest
	argonWaitForTest = 50 * time.Millisecond
	t.Cleanup(func() { argonWaitForTest = orig })

	ok, err := VerifyPassword(dummyHash, "whatever")
	if !errors.Is(err, ErrHashBusy) {
		t.Fatalf("闸满时应当返回 ErrHashBusy，实际 ok=%v err=%v", ok, err)
	}
	if ok {
		t.Error("繁忙时绝不能返回「校验通过」")
	}
}

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(Options{Path: filepath.Join(t.TempDir(), "auth.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestArgonMemoryCeilingIsPinned 钉住**内存上界本身**，而不只是「闸执行了它的常量」。
//
// TestArgon2ConcurrencyIsBounded 验的是「峰值不超过 argonConcurrency」——
// 那条断言在有人把 argonConcurrency 从 2 改成 64 时**照样绿**（实测过：
// 它是一次真实的假绿）。而那个改动会把峰值内存从 128 MiB 抬到 4 GiB，
// 也就是把这道闸要挡的 OOM 面原样放回来。
//
// 所以上界必须被算出来、直接断言，而且断言里要带上那个乘法 ——
// 让下一个想调大它的人在测试失败信息里直接读到代价。
func TestArgonMemoryCeilingIsPinned(t *testing.T) {
	const ceilingMiB = 256

	peakMiB := argonConcurrency * argonMemory / 1024
	if peakMiB > ceilingMiB {
		t.Fatalf("argon2 峰值内存 = %d 并发 × %d MiB = %d MiB，超过上限 %d MiB。\n"+
			"这道闸的全部意义就是这个上界：未鉴权的 POST /api/login 能驱动它，"+
			"超了就是把「一个匿名请求 OOM 掉整台中继、所有隧道同时断掉」放回来。\n"+
			"要调大先想清楚部署下限（本产品的目标包括 512 MiB 的小机器）。",
			argonConcurrency, argonMemory/1024, peakMiB, ceilingMiB)
	}
}

// TestVerifyAdminReportsBusyRatherThanBadPassword 补上 TestBusyIsNotReportedAsBadCredentials
// 覆盖不到的那一层。
//
// 那条测的是 VerifyPassword；而 VerifyAdmin 里**另有**一次 errors.Is 判断，
// 删掉它测试照样绿（实测过，是一次真实的假绿）。而删掉的后果正是这个三返回值
// 设计要避免的：洪水期间正常用户看到「用户名或密码错误」→ 去查密码（查错方向），
// 上层限速器还会把这次失败记到他头上。
func TestVerifyAdminReportsBusyRatherThanBadPassword(t *testing.T) {
	db := openTestDB(t)
	const user, pass = "ops", "a-very-long-password"
	if err := db.CreateAdmin(t.Context(), user, pass, false); err != nil {
		t.Fatal(err)
	}

	orig := argonWaitForTest
	argonWaitForTest = 50 * time.Millisecond
	t.Cleanup(func() { argonWaitForTest = orig })

	// 占满闸，让接下来的校验必然超时。
	for range argonConcurrency {
		argonGate <- struct{}{}
	}
	t.Cleanup(func() {
		for len(argonGate) > 0 {
			<-argonGate
		}
	})

	for _, tc := range []struct{ name, user, pass string }{
		// 正确口令也要报繁忙 —— 这是最要紧的一格：把它报成密码错，
		// 用户会以为自己记错了口令。
		{"正确口令", user, pass},
		{"错误口令", user, "wrong-wrong-wrong"},
		// 不存在的用户名走假校验路径，那条也分配 64 MiB，同样要报繁忙。
		{"不存在的用户", "no-such-user", "whatever"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ok, err := db.VerifyAdmin(t.Context(), tc.user, tc.pass)
			if !errors.Is(err, ErrHashBusy) {
				t.Errorf("闸满时 VerifyAdmin 应当返回 ErrHashBusy，实际 ok=%v err=%v —— "+
					"报成「密码错」会让用户查错方向，还会被上层限速器记一次失败",
					ok, err)
			}
			if ok {
				t.Error("繁忙时绝不能返回校验通过")
			}
		})
	}
}
