package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// ── 隧道 ────────────────────────────────────────────────────────────────────

// PutTunnel 新建或更新一条隧道。
//
// 冲突（slug 重复、入口端口被占）返回 ErrConflict，映射到 HTTP 409。
// 这一点很重要：frp 的 store 会按名字**静默覆盖**，那种沉默覆盖在排障时极难发现。
func (d *DB) PutTunnel(ctx context.Context, t *tunnel.Tunnel) error {
	t.Complete()
	if err := t.Validate(); err != nil {
		return err
	}

	routerJSON, err := marshalOptional(t.Router)
	if err != nil {
		return err
	}
	policyJSON, err := marshalOptional(t.Policy)
	if err != nil {
		return err
	}
	backendJSON, err := json.Marshal(t.Backend)
	if err != nil {
		return fmt.Errorf("store: 编码 backend 失败：%w", err)
	}

	// 短标识由**存储层独占决定**，调用方传什么都不算。
	//
	// 既有隧道沿用库里那个号，新隧道分配一个最小可用号。两点都必须在这里做：
	// 它要在整个租户内唯一，而只有存储层看得见「已经用掉了哪些」。
	//
	// # 为什么不能只在 t.ShortID == 0 时才管
	//
	// 那是此前的写法，它留下两个都很隐蔽的口子：
	//
	//   * 下面的 UPDATE 子句只在库里那个号还是 0 时才写 short_id
	//     （改号会让在途的 UDP 数据报被当成未知隧道丢掉）。于是
	//     「t.ShortID 与库里不一致」这件事**不会**被写库暴露 ——
	//     它只会顺着返回值流出去。控制台 PUT 的响应体里那个号就是这么来的：
	//     一个当时**空闲**的号，从未落库，而下一条新建的隧道会真的拿到它。
	//     手里那份响应就在事后变成了别人的标识。
	//   * 声明式导入的文档里可以带 short_id。库拦得住（不写这一列），
	//     但返回给用户的 diff 与对象里带的是文档指定的号。
	//
	// 把决定权收回存储层，两个口子一起没了，而上面那句注释也才真正成立。
	cur, err := d.shortIDOf(ctx, t.ID)
	if err != nil {
		return err
	}
	if cur != 0 {
		t.ShortID = cur
	} else {
		id, err := d.allocShortID(ctx, t.TenantID)
		if err != nil {
			return err
		}
		t.ShortID = id
	}

	ts := now()
	_, err = d.write.ExecContext(ctx, `
		INSERT INTO tunnels (
			id, tenant_id, slug, kind, tls_mode, exposure, l4, agent_id,
			listen_port, short_id, router_json, policy_json, backend_json,
			state, state_reason, enabled, created_at, updated_at
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			slug=excluded.slug, kind=excluded.kind, tls_mode=excluded.tls_mode,
			exposure=excluded.exposure, l4=excluded.l4, agent_id=excluded.agent_id,
			listen_port=excluded.listen_port, router_json=excluded.router_json,
			policy_json=excluded.policy_json, backend_json=excluded.backend_json,
			state=excluded.state, state_reason=excluded.state_reason,
			enabled=excluded.enabled, updated_at=excluded.updated_at,
			-- 短标识**只回填、绝不改号**。
			--
			-- 改号会让在途的 UDP 数据报被当成未知隧道丢掉（帧头带的是旧号），
			-- 现象是「改了一次隧道配置，UDP 就断了几秒」，而配置本身毫无问题。
			-- 回填那一支是给升级路径留的：万一有一行的号还是 0，
			-- 它就该在下一次写入时拿到一个真号，而不是永远带着 0
			--（Tunnel=0 的数据报解复用直接错位，静默送到别处）。
			short_id=CASE WHEN tunnels.short_id = 0
				THEN excluded.short_id ELSE tunnels.short_id END`,
		t.ID, t.TenantID, t.Slug, string(t.Kind), string(t.TLS), string(t.Exposure),
		string(t.L4), nullableString(t.AgentID), t.ListenPort, t.ShortID,
		routerJSON, policyJSON, string(backendJSON),
		string(t.State), t.StateReason, nullableBool(t.Enabled), ts, ts,
	)
	if err != nil {
		return classifyConstraint(err)
	}
	return nil
}

// shortIDOf 读一条隧道当前的短标识，行不存在时回 0。
//
// 按 ID 查而不是按 slug：PutTunnel 的冲突键是 id，两者必须一致，
// 否则一次「改 slug」的更新会被当成新隧道去分配新号。
func (d *DB) shortIDOf(ctx context.Context, id string) (uint16, error) {
	if id == "" {
		return 0, nil
	}
	var got uint16
	err := d.read.QueryRowContext(ctx,
		`SELECT short_id FROM tunnels WHERE id = ?`, id).Scan(&got)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store: 读短标识失败：%w", err)
	}
	return got, nil
}

// ErrShortIDExhausted 表示一个租户的隧道短标识用尽了。
//
// 65535 条隧道的家用中继不存在，但把它当作「不可能」而静默回绕会造成
// 两条隧道共用一个标识 —— 那会让 UDP 流量串到错误的后端去，
// 是比拒绝创建严重得多的故障。
var ErrShortIDExhausted = errors.New("store: 隧道短标识已用尽（上限 65535）")

// allocShortID 取一个租户内最小的可用短标识。
//
// 「最小可用」而不是「最大值 +1」：反复增删隧道的部署下，后者会很快爬到上限，
// 而前者会复用被删掉隧道的号。复用的代价是一条已删隧道的在途数据报可能
// 命中新隧道 —— 所以复用前提是数据报里同时带 FlowID，
// 而 FlowID 由会话表按需分配、旧会话不存在于新表中，在途包会被当作未知流丢弃。
func (d *DB) allocShortID(ctx context.Context, tenantID string) (uint16, error) {
	rows, err := d.read.QueryContext(ctx,
		`SELECT short_id FROM tunnels WHERE tenant_id = ? AND short_id != 0 ORDER BY short_id`,
		tenantID)
	if err != nil {
		return 0, fmt.Errorf("store: 查询已用短标识失败：%w", err)
	}
	defer rows.Close()

	// 已用标识是升序的，所以第一个「不等于期望值」的位置就是空洞。
	want := uint16(1)
	for rows.Next() {
		var used uint16
		if err := rows.Scan(&used); err != nil {
			return 0, fmt.Errorf("store: 读取短标识失败：%w", err)
		}
		if used != want {
			break
		}
		if want == 0xFFFF {
			return 0, ErrShortIDExhausted
		}
		want++
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: 遍历短标识失败：%w", err)
	}
	return want, nil
}

// GetTunnel 按 ID 取一条隧道。
func (d *DB) GetTunnel(ctx context.Context, id string) (*tunnel.Tunnel, error) {
	row := d.read.QueryRowContext(ctx, tunnelSelect+` WHERE id = ?`, id)
	return scanTunnel(row)
}

// ListTunnels 列出一个租户的全部隧道，按 slug 排序。
//
// 排序不是装饰：结果要用于「下发给 agent 的期望集合」与控制台列表，
// 不确定的顺序会让 diff 与快照比对产生假变更。
func (d *DB) ListTunnels(ctx context.Context, tenantID string) ([]*tunnel.Tunnel, error) {
	rows, err := d.read.QueryContext(ctx,
		tunnelSelect+` WHERE tenant_id = ? ORDER BY slug`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: 查询隧道失败：%w", err)
	}
	defer rows.Close()

	var out []*tunnel.Tunnel
	for rows.Next() {
		t, err := scanTunnel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteTunnel 删除一条隧道。
func (d *DB) DeleteTunnel(ctx context.Context, id string) error {
	res, err := d.write.ExecContext(ctx, `DELETE FROM tunnels WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: 删除隧道失败：%w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetTunnelState 更新隧道状态与原因。
//
// 单独一个方法而不是走 PutTunnel：状态是运行时反馈（例如 agent 否决），
// 不该顺带把配置字段也覆盖一遍 —— 那会造成「控制台刚改的配置被状态上报冲掉」。
func (d *DB) SetTunnelState(ctx context.Context, id string, state tunnel.State, reason string) error {
	res, err := d.write.ExecContext(ctx,
		`UPDATE tunnels SET state = ?, state_reason = ?, updated_at = ? WHERE id = ?`,
		string(state), reason, now(), id)
	if err != nil {
		return fmt.Errorf("store: 更新隧道状态失败：%w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

const tunnelSelect = `
	SELECT id, tenant_id, slug, kind, tls_mode, exposure, l4, agent_id,
	       listen_port, short_id, router_json, policy_json, backend_json,
	       state, state_reason, enabled
	FROM tunnels`

// rowScanner 抽象 *sql.Row 与 *sql.Rows 的共同能力。
type rowScanner interface {
	Scan(dest ...any) error
}

func scanTunnel(sc rowScanner) (*tunnel.Tunnel, error) {
	var (
		t           tunnel.Tunnel
		kind        string
		tlsMode     string
		exposure    string
		l4          string
		agentID     sql.NullString
		routerJSON  sql.NullString
		policyJSON  sql.NullString
		backendJSON string
		state       string
		enabled     sql.NullBool
	)
	err := sc.Scan(&t.ID, &t.TenantID, &t.Slug, &kind, &tlsMode, &exposure, &l4,
		&agentID, &t.ListenPort, &t.ShortID, &routerJSON, &policyJSON, &backendJSON,
		&state, &t.StateReason, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: 读取隧道失败：%w", err)
	}

	t.Kind = tunnel.Kind(kind)
	t.TLS = tunnel.TLSMode(tlsMode)
	t.Exposure = tunnel.Exposure(exposure)
	t.L4 = tunnel.L4(l4)
	t.State = tunnel.State(state)
	if agentID.Valid {
		t.AgentID = agentID.String
	}
	if enabled.Valid {
		v := enabled.Bool
		t.Enabled = &v
	}
	if routerJSON.Valid && routerJSON.String != "" {
		t.Router = new(tunnel.Router)
		if err := json.Unmarshal([]byte(routerJSON.String), t.Router); err != nil {
			return nil, fmt.Errorf("store: 解码隧道 %s 的 router 失败：%w", t.ID, err)
		}
	}
	if policyJSON.Valid && policyJSON.String != "" {
		t.Policy = new(tunnel.Policy)
		if err := json.Unmarshal([]byte(policyJSON.String), t.Policy); err != nil {
			return nil, fmt.Errorf("store: 解码隧道 %s 的 policy 失败：%w", t.ID, err)
		}
	}
	if err := json.Unmarshal([]byte(backendJSON), &t.Backend); err != nil {
		return nil, fmt.Errorf("store: 解码隧道 %s 的 backend 失败：%w", t.ID, err)
	}
	return &t, nil
}

// ── Agent ───────────────────────────────────────────────────────────────────

// Agent 是一条 agent 注册记录。
type Agent struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	MachineID  string    `json:"machine_id"`
	Hostname   string    `json:"hostname"`
	OS         string    `json:"os"`
	Arch       string    `json:"arch"`
	Version    string    `json:"version"`
	Revoked    bool      `json:"revoked"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at,omitzero"`
}

// AgentExists 判断一个 agent 是否存在且未被撤销。
func (d *DB) AgentExists(ctx context.Context, agentID string) bool {
	var one int
	err := d.read.QueryRowContext(ctx,
		`SELECT 1 FROM agents WHERE id = ? AND revoked_at IS NULL`, agentID).Scan(&one)
	return err == nil
}

// TouchAgent 更新 last_seen 与设备画像。
func (d *DB) TouchAgent(ctx context.Context, a *Agent) error {
	_, err := d.write.ExecContext(ctx, `
		UPDATE agents SET last_seen_at = ?, hostname = ?, os = ?, arch = ?, version = ?, machine_id = ?
		WHERE id = ?`,
		now(), a.Hostname, a.OS, a.Arch, a.Version, a.MachineID, a.ID)
	if err != nil {
		return fmt.Errorf("store: 更新 agent 活跃时间失败：%w", err)
	}
	return nil
}

// RevokeAgent 撤销一个 agent 的凭据。
//
// 撤销是 UPDATE 而不是 DELETE：审计需要知道这个 ID 曾经存在过，
// 而且删除会让引用它的隧道失去可解释的上下文。
func (d *DB) RevokeAgent(ctx context.Context, agentID string) error {
	res, err := d.write.ExecContext(ctx,
		`UPDATE agents SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now(), agentID)
	if err != nil {
		return fmt.Errorf("store: 撤销 agent 失败：%w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListAgents 列出一个租户的全部 agent。
func (d *DB) ListAgents(ctx context.Context, tenantID string) ([]*Agent, error) {
	rows, err := d.read.QueryContext(ctx, `
		SELECT id, tenant_id, machine_id, hostname, os, arch, version,
		       revoked_at, created_at, last_seen_at
		FROM agents WHERE tenant_id = ? ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: 查询 agent 失败：%w", err)
	}
	defer rows.Close()

	var out []*Agent
	for rows.Next() {
		var (
			a          Agent
			revokedAt  sql.NullInt64
			createdAt  int64
			lastSeenAt sql.NullInt64
		)
		if err := rows.Scan(&a.ID, &a.TenantID, &a.MachineID, &a.Hostname,
			&a.OS, &a.Arch, &a.Version, &revokedAt, &createdAt, &lastSeenAt); err != nil {
			return nil, fmt.Errorf("store: 读取 agent 失败：%w", err)
		}
		a.Revoked = revokedAt.Valid
		a.CreatedAt = time.Unix(createdAt, 0)
		if lastSeenAt.Valid {
			a.LastSeenAt = time.Unix(lastSeenAt.Int64, 0)
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

// ── 入网令牌 ────────────────────────────────────────────────────────────────

// CreateEnrolToken 签发一个一次性入网令牌，返回明文。
//
// 库里只存 SHA-256。TTL 是强制的（EasyTier 把凭据 TTL 设为必填是对的）——
// 一个永不过期的入网令牌本质上是一把长期主密钥。
func (d *DB) CreateEnrolToken(ctx context.Context, tenantID string, ttl time.Duration, note string) (string, error) {
	if ttl <= 0 {
		return "", errors.New("store: 入网令牌必须有正的有效期")
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("store: 生成入网令牌失败：%w", err)
	}
	plain := "nf_enrol_" + hex.EncodeToString(raw)

	ts := now()
	_, err := d.write.ExecContext(ctx, `
		INSERT INTO enrol_tokens (token_hash, tenant_id, created_at, expires_at, note)
		VALUES (?,?,?,?,?)`,
		hashToken(plain), tenantID, ts, ts+int64(ttl.Seconds()), note)
	if err != nil {
		return "", fmt.Errorf("store: 保存入网令牌失败：%w", err)
	}
	return plain, nil
}

// RedeemEnrolToken 兑换一个入网令牌并创建 agent，返回 agent ID 与明文密钥。
//
// 整个过程在**一个事务**里完成：否则「令牌已标记为用过但 agent 创建失败」
// 会让那个令牌永久作废且没有对应的 agent —— 用户只能重新签发，
// 却不知道为什么第一次失败了。
func (d *DB) RedeemEnrolToken(ctx context.Context, plainToken string, profile *Agent) (agentID, plainKey string, err error) {
	tx, err := d.write.BeginTx(ctx, nil)
	if err != nil {
		return "", "", fmt.Errorf("store: 开启事务失败：%w", err)
	}
	defer tx.Rollback()

	hash := hashToken(plainToken)

	var (
		tenantID  string
		expiresAt int64
		usedAt    sql.NullInt64
	)
	err = tx.QueryRowContext(ctx,
		`SELECT tenant_id, expires_at, used_at FROM enrol_tokens WHERE token_hash = ?`, hash).
		Scan(&tenantID, &expiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("store: 查询入网令牌失败：%w", err)
	}
	if usedAt.Valid {
		return "", "", ErrTokenUsed
	}
	ts := now()
	if ts > expiresAt {
		return "", "", ErrTokenExpired
	}

	// agent ID 由令牌哈希派生，使**重复兑换同一令牌得到同一 ID**。
	// 这不是为了允许重复兑换（上面已经拒绝了），而是让日志与审计里
	// 「这个令牌对应哪个 agent」是可推导的。
	newID := EnrolAgentID(plainToken)

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("store: 生成 agent 密钥失败：%w", err)
	}

	if profile == nil {
		profile = &Agent{}
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO agents (id, tenant_id, secret, machine_id, hostname, os, arch, version, created_at, last_seen_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			secret=excluded.secret, machine_id=excluded.machine_id,
			hostname=excluded.hostname, os=excluded.os, arch=excluded.arch,
			version=excluded.version, last_seen_at=excluded.last_seen_at,
			revoked_at=NULL`,
		newID, tenantID, raw, profile.MachineID, profile.Hostname,
		profile.OS, profile.Arch, profile.Version, ts, ts)
	if err != nil {
		return "", "", fmt.Errorf("store: 创建 agent 失败：%w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE enrol_tokens SET used_at = ?, used_by = ? WHERE token_hash = ?`,
		ts, newID, hash); err != nil {
		return "", "", fmt.Errorf("store: 标记令牌已用失败：%w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", "", fmt.Errorf("store: 提交事务失败：%w", err)
	}
	return newID, hex.EncodeToString(raw), nil
}

// AgentSecret 取出一个 agent 的密钥明文，供握手时重算 HMAC。
//
// 已撤销的 agent 返回 ok=false —— 撤销必须立即生效。
// 关于「为什么存明文而不是哈希」见迁移文件里 agents.secret 列的注释。
func (d *DB) AgentSecret(ctx context.Context, agentID string) ([]byte, bool) {
	var (
		secret  []byte
		revoked sql.NullInt64
	)
	err := d.read.QueryRowContext(ctx,
		`SELECT secret, revoked_at FROM agents WHERE id = ?`, agentID).Scan(&secret, &revoked)
	if err != nil || revoked.Valid {
		return nil, false
	}
	return secret, true
}

func hashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// ── 辅助 ────────────────────────────────────────────────────────────────────

func marshalOptional(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	// 用反射之外的办法判空：调用方传的是 *Router / *Policy，
	// nil 指针经 any 包装后不等于 nil，所以要显式检查。
	switch t := v.(type) {
	case *tunnel.Router:
		if t == nil {
			return nil, nil
		}
	case *tunnel.Policy:
		if t == nil {
			return nil, nil
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("store: 编码失败：%w", err)
	}
	return string(b), nil
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableBool(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

// classifyConstraint 把 SQLite 的约束冲突翻译成 ErrConflict。
//
// 不这么做的话，上层拿到的是一条驱动内部的错误字符串，
// 无法映射到 HTTP 409，最后只能给用户返 500 —— 而这明显是客户端错误。
func classifyConstraint(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "constraint failed: UNIQUE") {
		return fmt.Errorf("%w：%v", ErrConflict, err)
	}
	return fmt.Errorf("store: 写入失败：%w", err)
}

// ── 服务端密钥 ──────────────────────────────────────────────────────────────

// SecretNameTURN 是内置 TURN 的临时凭据密钥名。
const SecretNameTURN = "turn_rest_secret"

// turnSecretBytes 是 TURN 凭据密钥的长度。
//
// 32 字节：HMAC-SHA1 的分组是 64 字节，超过分组长度的密钥会先被哈希一遍，
// 白占空间；而 32 字节远超 SHA-1 的 160 位输出，不构成短板。
const turnSecretBytes = 32

// TurnSecret 取内置 TURN 的凭据密钥，不存在时生成并持久化。
//
// 必须持久化：临时凭据是 HMAC(secret, 用户名)，重启换密钥会让所有已签发
// 而未过期的凭据立刻失效 —— 正在通话的浏览器会断掉，而日志里只显示
// 「鉴权失败」，看不出是重启导致的。
func (d *DB) TurnSecret(ctx context.Context) ([]byte, error) {
	return d.orCreateSecret(ctx, SecretNameTURN, turnSecretBytes)
}

// orCreateSecret 取一个命名密钥，不存在时生成。
func (d *DB) orCreateSecret(ctx context.Context, name string, size int) ([]byte, error) {
	var secret []byte
	err := d.read.QueryRowContext(ctx,
		`SELECT secret FROM server_secrets WHERE name = ?`, name).Scan(&secret)
	if err == nil {
		return secret, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("store: 读取密钥 %s 失败：%w", name, err)
	}

	fresh := make([]byte, size)
	if _, err := rand.Read(fresh); err != nil {
		return nil, fmt.Errorf("store: 生成密钥 %s 失败：%w", name, err)
	}
	// INSERT OR IGNORE 而不是 INSERT：两个进程同时首启时（比如
	// 容器编排重试）后一个不该报错，而应当读到前一个写好的那份。
	if _, err := d.write.ExecContext(ctx,
		`INSERT OR IGNORE INTO server_secrets (name, secret, created_at) VALUES (?,?,?)`,
		name, fresh, now()); err != nil {
		return nil, fmt.Errorf("store: 持久化密钥 %s 失败：%w", name, err)
	}
	// 重新读一次：上面的 IGNORE 可能什么都没写。
	if err := d.read.QueryRowContext(ctx,
		`SELECT secret FROM server_secrets WHERE name = ?`, name).Scan(&secret); err != nil {
		return nil, fmt.Errorf("store: 回读密钥 %s 失败：%w", name, err)
	}
	return secret, nil
}
