package store

import (
	"context"
	"testing"
	"time"
)

func TestRecordRTTAcceptsManyObservationsInOneTransaction(t *testing.T) {
	// 变参不是「顺手支持一下」：采样循环每分钟跑一次，而 ping 每 5 秒一次 ——
	// 一次调用带 12 个观测。逐个调用的话是 12 个写事务，
	// 而 SQLite 的写事务在长期运行的中继上是最贵的那一项。
	db := open(t)
	ctx := context.Background()
	at := time.Unix(1786190000, 0)

	// 12 个观测，跨几个桶。
	rtts := []time.Duration{
		200 * time.Microsecond, 300 * time.Microsecond, 400 * time.Microsecond,
		1 * time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond,
		5 * time.Millisecond, 8 * time.Millisecond, 12 * time.Millisecond,
		20 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond,
	}
	if err := db.RecordRTT(ctx, "t1", at, rtts...); err != nil {
		t.Fatal(err)
	}

	// +Inf 桶（le_us = -1）就是总观测数 —— 它必须等于 12，
	// 而不是 1（那是「每次调用记一个」的形状）。
	var total int64
	if err := db.read.QueryRowContext(ctx,
		`SELECT count FROM tunnel_rtt_hist_1m WHERE tunnel_id=? AND le_us=-1`,
		"t1").Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != int64(len(rtts)) {
		t.Fatalf("总观测数应为 %d，实际 %d —— 变参没有真的把 N 个观测都记进去",
			len(rtts), total)
	}

	// 分位数要能算出来，且落在样本范围内。
	from, to := at.Add(-time.Minute), at.Add(time.Minute)
	p50, err := db.Quantile(ctx, "t1", from, to, 0.50)
	if err != nil {
		t.Fatal(err)
	}
	if p50 <= 0 {
		t.Fatal("有 12 个观测时 p50 不该是 0")
	}
	p99, err := db.Quantile(ctx, "t1", from, to, 0.99)
	if err != nil {
		t.Fatal(err)
	}
	if p99 < p50 {
		t.Fatalf("p99(%d) 不该小于 p50(%d)", p99, p50)
	}

	// 空调用是安全的空操作 —— 采样循环在没有观测时会这样调。
	if err := db.RecordRTT(ctx, "t1", at); err != nil {
		t.Fatalf("空观测应当是空操作：%v", err)
	}
	if err := db.read.QueryRowContext(ctx,
		`SELECT count FROM tunnel_rtt_hist_1m WHERE tunnel_id=? AND le_us=-1`,
		"t1").Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != int64(len(rtts)) {
		t.Fatalf("空调用不该改变总数，实际 %d", total)
	}
}
