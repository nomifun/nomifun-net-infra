package store

import (
	"context"
	"fmt"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// ── 事件 ────────────────────────────────────────────────────────────────────

// Event 是一条事件/审计记录。
type Event struct {
	ID      int64     `json:"id"`
	At      time.Time `json:"at"`
	Level   string    `json:"level"`
	Kind    string    `json:"kind"`
	Subject string    `json:"subject,omitempty"`
	Message string    `json:"message"`
	Actor   string    `json:"actor,omitempty"`
}

// 事件级别。
const (
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

// 事件种类。
//
// 这些字符串是**稳定标识**，会进数据库、SSE 事件流与控制台筛选器。
// 不要为了措辞好看而改动它们；新增语义请加新的种类。
const (
	KindAgentOnline   = "agent.online"
	KindAgentOffline  = "agent.offline"
	KindAgentEnrolled = "agent.enrolled"
	KindAgentRevoked  = "agent.revoked"
	// KindAgentKicked 是「被控制台踢下线」。
	//
	// 与 KindAgentRevoked 分开：踢是**连接层**操作，agent 会立刻重连；
	// 撤销是永久的。文案混在一起会让用户以为踢了就永久生效，
	// 然后在它十秒后重新上线时以为功能坏了。
	KindAgentKicked     = "agent.kicked"
	KindHandshakeFailed = "agent.handshake_failed"
	KindTunnelCreated   = "tunnel.created"
	KindTunnelUpdated   = "tunnel.updated"
	KindTunnelDeleted   = "tunnel.deleted"
	KindTunnelRejected  = "tunnel.rejected"
	// KindStreamDenied 是**拨号期**否决：agent 的本地策略在真正拨号时拒掉了目标。
	//
	// 与 KindTunnelRejected（配置期预检）是两件事，必须分开：预检只判 IP
	// 字面量，主机名一律放过、留给拨号时判定（DNS 可以在预检之后改变解析
	// 结果）。所以一条「已被接受」的隧道完全可能在每次拨号时被拒 ——
	// 若这条路不产生事件，用户看到的就只是一条不通的隧道，
	// 不知道是自己的策略挡住的。那正是 frp 让人无从下手的老毛病。
	KindStreamDenied = "tunnel.stream_denied"
	// KindTurnCredential 是签发临时 TURN 凭据。
	//
	// 必须留痕：那是一次授予访问权的动作，事后要能回答
	// 「谁在什么时候拿走了一对能用 10 分钟的中继凭据」。
	KindTurnCredential = "turn.credential_issued"

	// KindSupportBundle 是下载支持包。
	//
	// **必须留痕**：支持包是要发给别人看的，所以「谁在什么时候导出了一份」
	// 与「谁拿走了一对 TURN 凭据」是同一类事件 —— 外发。
	KindSupportBundle = "console.support_bundle"

	// KindConfigApplied 是应用一份声明式配置文档。
	//
	// 与 KindTunnelCreated/Updated/Deleted 分开而不是逐条记那三种：
	// 一次导入可能同时新建、更新、**删除**多条，逐条记会把「用户做了一次
	// 整体替换」拆成一串看起来互不相关的事件 —— 而事后要回答的问题是
	// 「谁把配置整体换掉了」，不是「谁删了 svc-3」。
	KindConfigApplied = "console.config_applied"

	KindConsoleLogin         = "console.login"
	KindConsoleLoginBad      = "console.login_failed"
	KindPairingInviteCreated = "pairing_invite.created"

	// KindConsoleLoginThrottled 是未鉴权端点被限速。
	//
	// 与 login_failed 分开：后者是「某人密码错了」，前者是「有人在打这台机器」。
	// 两者的处置完全不同（改密码 vs 看防火墙），混在一起会让真正的攻击信号
	// 淹在正常的手滑里。事件按源 IP 一分钟一条去重 —— 不去重的话一次爆破
	// 几秒钟就能写上千条，把有用的事件挤出可视范围。
	KindConsoleLoginThrottled = "console.login_throttled"
	KindRelayStarted          = "relay.started"
	KindRelayDraining         = "relay.draining"
)

// AppendEvent 追加一条事件。
//
// 失败只记日志不返错给调用方 —— 事件是可观测性，不该因为写事件失败
// 而让一次成功的业务操作看起来失败了。所以返回值是 error 但调用方通常忽略；
// 这里仍然返回它，以便测试能断言。
func (d *DB) AppendEvent(ctx context.Context, e Event) error {
	if e.Level == "" {
		e.Level = LevelInfo
	}
	at := e.At.Unix()
	if e.At.IsZero() {
		at = now()
	}
	_, err := d.write.ExecContext(ctx, `
		INSERT INTO events (tenant_id, at, level, kind, subject, message, actor)
		VALUES (?,?,?,?,?,?,?)`,
		tunnel.DefaultTenantID, at, e.Level, e.Kind, e.Subject, e.Message, e.Actor)
	if err != nil {
		return fmt.Errorf("store: 写事件失败：%w", err)
	}
	return nil
}

// ListEvents 返回最近的事件，最新在前。
//
// limit 上限强制为 500：控制台的「近期事件」面板不需要更多，
// 而一个不设上限的查询接口迟早会被某个前端 bug 变成全表扫描。
func (d *DB) ListEvents(ctx context.Context, limit int, sinceID int64) ([]Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := d.read.QueryContext(ctx, `
		SELECT id, at, level, kind, subject, message, actor
		FROM events WHERE id > ? ORDER BY id DESC LIMIT ?`, sinceID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: 查询事件失败：%w", err)
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var (
			e  Event
			at int64
		)
		if err := rows.Scan(&e.ID, &at, &e.Level, &e.Kind, &e.Subject, &e.Message, &e.Actor); err != nil {
			return nil, fmt.Errorf("store: 读取事件失败：%w", err)
		}
		e.At = time.Unix(at, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneEvents 删除早于 cutoff 的事件，返回删除条数。
func (d *DB) PruneEvents(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := d.write.ExecContext(ctx, `DELETE FROM events WHERE at < ?`, cutoff.Unix())
	if err != nil {
		return 0, fmt.Errorf("store: 清理事件失败：%w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ── 时序 ────────────────────────────────────────────────────────────────────

// Sample 是一个粒度桶内的聚合指标。
type Sample struct {
	TunnelID string `json:"tunnel_id"`
	// Bucket 是桶起始的 unix 秒。
	Bucket   int64 `json:"bucket"`
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
	PktsIn   int64 `json:"pkts_in"`
	PktsOut  int64 `json:"pkts_out"`
	ConnsOK  int64 `json:"conns_ok"`
	ConnsErr int64 `json:"conns_err"`
	// LossPPM 是百万分率，用整数避免浮点漂移累积。
	LossPPM  int64 `json:"loss_ppm"`
	RTTSumUS int64 `json:"rtt_sum_us"`
	RTTMaxUS int64 `json:"rtt_max_us"`
	// Samples 是折叠计数，上卷时重新求均值需要它。
	Samples int64 `json:"samples"`
}

// RTTBuckets 是 RTT 直方图的上界（微秒）。
//
// 覆盖 1ms 到 2s：局域网在头几个桶，跨洲在中段，超过 2s 的进 +Inf 桶。
// 桶边界一旦发布就**不可更改** —— 改了之后新旧数据无法合并，
// 历史图表会在改动时刻出现断崖。
var RTTBuckets = []int64{
	1_000, 2_500, 5_000, 10_000, 25_000, 50_000,
	100_000, 250_000, 500_000, 1_000_000, 2_000_000,
}

// RecordSample 把一个 1 分钟桶的增量累加进去。
//
// 用 UPSERT 累加而不是覆盖：一个桶内会有多次上报（每次采集一份增量），
// 覆盖会丢掉除最后一次以外的全部数据。
func (d *DB) RecordSample(ctx context.Context, s Sample) error {
	bucket := s.Bucket - s.Bucket%60
	_, err := d.write.ExecContext(ctx, `
		INSERT INTO tunnel_sample_1m (
			tunnel_id, bucket, bytes_in, bytes_out, pkts_in, pkts_out,
			conns_ok, conns_err, loss_ppm, rtt_sum_us, rtt_max_us, samples
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(tunnel_id, bucket) DO UPDATE SET
			bytes_in   = bytes_in  + excluded.bytes_in,
			bytes_out  = bytes_out + excluded.bytes_out,
			pkts_in    = pkts_in   + excluded.pkts_in,
			pkts_out   = pkts_out  + excluded.pkts_out,
			conns_ok   = conns_ok  + excluded.conns_ok,
			conns_err  = conns_err + excluded.conns_err,
			-- 丢包率是比率不是计数，累加会得到无意义的结果；取最新值。
			loss_ppm   = excluded.loss_ppm,
			rtt_sum_us = rtt_sum_us + excluded.rtt_sum_us,
			-- 最大值取两者较大者，不是相加。
			rtt_max_us = MAX(rtt_max_us, excluded.rtt_max_us),
			samples    = samples + excluded.samples`,
		s.TunnelID, bucket, s.BytesIn, s.BytesOut, s.PktsIn, s.PktsOut,
		s.ConnsOK, s.ConnsErr, s.LossPPM, s.RTTSumUS, s.RTTMaxUS, s.Samples)
	if err != nil {
		return fmt.Errorf("store: 记录时序样本失败：%w", err)
	}
	return nil
}

// RecordRTT 把一次 RTT 观测计入直方图。
//
// 存桶而不是存分位数：**分位数不能被平均**。把每分钟的 p95 再平均成
// 每小时的 p95 在算术上是错的，而这正是很多监控系统的经典错误。
// RecordRTT 把若干次 RTT 观测计入直方图。
//
// **变参而不是单个观测**：采样循环每分钟跑一次，而 ping 每 5 秒一次 ——
// 一次调用带 12 个观测。逐个调用的话是 12 个事务，而 SQLite 的写事务
// 在一个长期运行的中继上是最贵的那一项；先在内存里累好、一个事务发出去，
// 语句数与单个观测那版**一样**，却带了 12 倍的信息量。
func (d *DB) RecordRTT(ctx context.Context, tunnelID string, at time.Time, rtts ...time.Duration) error {
	if len(rtts) == 0 {
		return nil
	}
	bucket := at.Unix() - at.Unix()%60

	// 先在内存里把每个桶该加多少累好。
	//
	// 累积直方图语义：一次观测要让所有 le >= 该值的桶都 +1，
	// 这样任意分位数都能通过一次线性扫描算出。
	counts := make(map[int64]int64, len(RTTBuckets))
	for _, rtt := range rtts {
		us := rtt.Microseconds()
		for _, le := range RTTBuckets {
			if us <= le {
				counts[le]++
			}
		}
	}

	tx, err := d.write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: 开启事务失败：%w", err)
	}
	defer tx.Rollback()

	for _, le := range RTTBuckets {
		n := counts[le]
		if n == 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO tunnel_rtt_hist_1m (tunnel_id, bucket, le_us, count)
			VALUES (?,?,?,?)
			ON CONFLICT(tunnel_id, bucket, le_us) DO UPDATE SET count = count + ?`,
			tunnelID, bucket, le, n, n); err != nil {
			return fmt.Errorf("store: 记录 RTT 直方图失败：%w", err)
		}
	}
	// +Inf 桶（用 -1 表示）加上全部观测数，作为总观测数。
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO tunnel_rtt_hist_1m (tunnel_id, bucket, le_us, count)
		VALUES (?,?,-1,?)
		ON CONFLICT(tunnel_id, bucket, le_us) DO UPDATE SET count = count + ?`,
		tunnelID, bucket, int64(len(rtts)), int64(len(rtts))); err != nil {
		return fmt.Errorf("store: 记录 RTT 总数失败：%w", err)
	}
	return tx.Commit()
}

// Quantile 从直方图算出一个区间内的分位数。
//
// p 取 0..1。返回值是该分位数所在桶的上界（微秒），无数据时返回 0。
//
// 这是「存桶」的回报：任意时间范围、任意分位数都能正确计算，
// 而存 p95 列的方案只能回答它当初记录的那一个分位数、那一个粒度。
func (d *DB) Quantile(ctx context.Context, tunnelID string, from, to time.Time, p float64) (time.Duration, error) {
	if p <= 0 || p > 1 {
		return 0, fmt.Errorf("store: 分位数 %v 超出 (0,1] 范围", p)
	}

	var total int64
	err := d.read.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(count),0) FROM tunnel_rtt_hist_1m
		WHERE tunnel_id = ? AND bucket >= ? AND bucket <= ? AND le_us = -1`,
		tunnelID, from.Unix(), to.Unix()).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("store: 查询 RTT 总数失败：%w", err)
	}
	if total == 0 {
		return 0, nil
	}
	target := int64(float64(total) * p)
	if target < 1 {
		target = 1
	}

	rows, err := d.read.QueryContext(ctx, `
		SELECT le_us, SUM(count) FROM tunnel_rtt_hist_1m
		WHERE tunnel_id = ? AND bucket >= ? AND bucket <= ? AND le_us != -1
		GROUP BY le_us ORDER BY le_us`,
		tunnelID, from.Unix(), to.Unix())
	if err != nil {
		return 0, fmt.Errorf("store: 查询 RTT 直方图失败：%w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var le, cnt int64
		if err := rows.Scan(&le, &cnt); err != nil {
			return 0, err
		}
		// 桶是累积的，所以第一个 count >= target 的桶就是答案。
		if cnt >= target {
			return time.Duration(le) * time.Microsecond, nil
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	// 所有桶都不够 target，说明该分位数落在 +Inf 桶里。
	return time.Duration(RTTBuckets[len(RTTBuckets)-1]) * time.Microsecond, nil
}

// QuerySamples 返回一个隧道在时间范围内的 1 分钟样本，按时间升序。
func (d *DB) QuerySamples(ctx context.Context, tunnelID string, from, to time.Time) ([]Sample, error) {
	rows, err := d.read.QueryContext(ctx, `
		SELECT tunnel_id, bucket, bytes_in, bytes_out, pkts_in, pkts_out,
		       conns_ok, conns_err, loss_ppm, rtt_sum_us, rtt_max_us, samples
		FROM tunnel_sample_1m
		WHERE tunnel_id = ? AND bucket >= ? AND bucket <= ?
		ORDER BY bucket`,
		tunnelID, from.Unix(), to.Unix())
	if err != nil {
		return nil, fmt.Errorf("store: 查询时序样本失败：%w", err)
	}
	defer rows.Close()

	var out []Sample
	for rows.Next() {
		var s Sample
		if err := rows.Scan(&s.TunnelID, &s.Bucket, &s.BytesIn, &s.BytesOut,
			&s.PktsIn, &s.PktsOut, &s.ConnsOK, &s.ConnsErr,
			&s.LossPPM, &s.RTTSumUS, &s.RTTMaxUS, &s.Samples); err != nil {
			return nil, fmt.Errorf("store: 读取时序样本失败：%w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Rollup 把 1 分钟样本上卷到 5 分钟与 1 小时，并按留存策略清理。
//
// 留存：1m→48h、5m→30d、1h→400d。
// 应由一个周期性 goroutine 调用（建议每分钟一次）。
func (d *DB) Rollup(ctx context.Context) error {
	if err := d.rollupInto(ctx, "tunnel_sample_5m", "tunnel_sample_1m", 300); err != nil {
		return err
	}
	if err := d.rollupInto(ctx, "tunnel_sample_1h", "tunnel_sample_5m", 3600); err != nil {
		return err
	}

	ts := now()
	for _, r := range []struct {
		table string
		keep  int64
	}{
		{"tunnel_sample_1m", 48 * 3600},
		{"tunnel_rtt_hist_1m", 48 * 3600},
		{"tunnel_sample_5m", 30 * 24 * 3600},
		{"tunnel_sample_1h", 400 * 24 * 3600},
	} {
		if _, err := d.write.ExecContext(ctx,
			`DELETE FROM `+r.table+` WHERE bucket < ?`, ts-r.keep); err != nil {
			return fmt.Errorf("store: 清理 %s 失败：%w", r.table, err)
		}
	}
	return nil
}

// rollupInto 把 src 表按 interval 秒聚合进 dst 表。
//
// 表名来自本包内的常量，不来自外部输入，故字符串拼接是安全的。
func (d *DB) rollupInto(ctx context.Context, dst, src string, interval int64) error {
	_, err := d.write.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s (
			tunnel_id, bucket, bytes_in, bytes_out, pkts_in, pkts_out,
			conns_ok, conns_err, loss_ppm, rtt_sum_us, rtt_max_us, samples
		)
		SELECT tunnel_id, bucket - bucket %% %d,
		       SUM(bytes_in), SUM(bytes_out), SUM(pkts_in), SUM(pkts_out),
		       SUM(conns_ok), SUM(conns_err),
		       -- 丢包率按样本数加权平均，而不是简单平均：
		       -- 一个只有 1 个样本的桶不该与 1000 个样本的桶等权。
		       CASE WHEN SUM(samples) > 0
		            THEN SUM(loss_ppm * samples) / SUM(samples) ELSE 0 END,
		       SUM(rtt_sum_us), MAX(rtt_max_us), SUM(samples)
		FROM %s
		GROUP BY tunnel_id, bucket - bucket %% %d
		ON CONFLICT(tunnel_id, bucket) DO UPDATE SET
			bytes_in=excluded.bytes_in, bytes_out=excluded.bytes_out,
			pkts_in=excluded.pkts_in, pkts_out=excluded.pkts_out,
			conns_ok=excluded.conns_ok, conns_err=excluded.conns_err,
			loss_ppm=excluded.loss_ppm, rtt_sum_us=excluded.rtt_sum_us,
			rtt_max_us=excluded.rtt_max_us, samples=excluded.samples`,
		dst, interval, src, interval))
	if err != nil {
		return fmt.Errorf("store: 上卷 %s → %s 失败：%w", src, dst, err)
	}
	return nil
}
