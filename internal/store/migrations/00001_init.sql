-- +goose Up
-- 初始 schema。
--
-- 设计要点：
--  * tenant_id 恒为 'default' 但**非空保留**——v1 单租户，将来做多租户不需要迁移。
--  * Tunnel 是期望状态，Session 是观测状态，两张表。frp 把两者混在一起，
--    这才是它需要「清理离线」按钮的原因。
--  * RTT 存直方图桶而不是 p95 列：p95 的 p95 在算术上是错的。

CREATE TABLE agents (
    id           TEXT    PRIMARY KEY,
    tenant_id    TEXT    NOT NULL DEFAULT 'default',
    -- secret 是 agent 密钥的**明文**。
    --
    -- 这里不能存哈希，原因是握手证明是 HMAC-SHA256(secret, canonical)，
    -- 中继必须用同一个密钥重算 MAC 才能校验 —— 哈希做不到这件事。
    -- 这与「人类密码只存哈希」不矛盾：密码校验只需判等，HMAC 校验需要密钥本身。
    --
    -- 对应防护：库文件 0600 + 规格 §7 要求的 KEK 封装（v1 未实现，见 §16 已知缺口）。
    secret       BLOB    NOT NULL,
    machine_id   TEXT    NOT NULL DEFAULT '',
    hostname     TEXT    NOT NULL DEFAULT '',
    os           TEXT    NOT NULL DEFAULT '',
    arch         TEXT    NOT NULL DEFAULT '',
    version      TEXT    NOT NULL DEFAULT '',
    -- revoked_at 非空即已撤销。撤销是一次 UPDATE 而不是删除，
    -- 因为审计需要知道「这个 ID 曾经存在过」。
    revoked_at   INTEGER,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER
) STRICT;

CREATE INDEX idx_agents_tenant ON agents(tenant_id);

-- 一次性入网令牌。
--
-- 存 SHA-256 而不是明文：数据库泄露时令牌不应可直接使用。
-- used_at 非空即已用——**不删除**，否则无法区分「用过」与「从未存在」，
-- 而这两种情况在排障时含义完全不同。
CREATE TABLE enrol_tokens (
    token_hash TEXT    PRIMARY KEY,
    tenant_id  TEXT    NOT NULL DEFAULT 'default',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    used_by    TEXT,
    note       TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE TABLE tunnels (
    id           TEXT    PRIMARY KEY,
    tenant_id    TEXT    NOT NULL DEFAULT 'default',
    slug         TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    tls_mode     TEXT    NOT NULL,
    exposure     TEXT    NOT NULL,
    l4           TEXT    NOT NULL,
    agent_id     TEXT,
    listen_port  INTEGER NOT NULL DEFAULT 0,
    -- router / policy / backend 以 JSON 存。
    --
    -- 之所以不拆成列：它们是可选的嵌套结构，拆开会得到几十个可空列，
    -- 而我们从不按它们的内部字段查询。**规格要求「一种规范 JSON 形态
    -- 同时用于文件、存储、API、UI」**，存 JSON 正好落实这一条——
    -- frp 的同一对象有三种形态（文件扁平、store 扁平、API 按类型嵌套），
    -- 迫使前端到处 any 转换。
    router_json  TEXT,
    policy_json  TEXT,
    backend_json TEXT    NOT NULL,
    state        TEXT    NOT NULL,
    state_reason TEXT    NOT NULL DEFAULT '',
    enabled      INTEGER,   -- NULL=未设置（视为启用）/ 0 / 1，三态
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
) STRICT;

-- slug 在租户内唯一：它出现在 URL 里，重复会导致寻址歧义。
CREATE UNIQUE INDEX idx_tunnels_slug ON tunnels(tenant_id, slug);
-- 入口端口不可冲突。0 表示「由中继分配」，可以有多条，故加 WHERE 过滤。
CREATE UNIQUE INDEX idx_tunnels_port ON tunnels(listen_port) WHERE listen_port != 0;
CREATE INDEX idx_tunnels_agent ON tunnels(agent_id);

-- 控制台管理员。
--
-- 只有一行（v1 单管理员）。password_hash 是 Argon2id 的 PHC 串，
-- 参数编码在串里，所以将来调强度不需要迁移。
CREATE TABLE admins (
    username        TEXT    PRIMARY KEY,
    password_hash   TEXT    NOT NULL,
    -- must_rotate 为 1 时强制首次登录改密。
    must_rotate     INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    last_login_at   INTEGER
) STRICT;

-- 控制台会话。
--
-- 持久化而不是放内存：EasyTier 每次启动 Key::generate()，重启即失效所有会话
-- （easytier-web/src/restful/mod.rs:219），那是很差的运维体验。
CREATE TABLE console_sessions (
    id         TEXT    PRIMARY KEY,   -- 随机 token 的 SHA-256
    username   TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    -- csrf_token 用于双提交校验。
    csrf_token TEXT    NOT NULL
) STRICT;

CREATE INDEX idx_sessions_expiry ON console_sessions(expires_at);

-- 事件流。控制台的「近期事件」与审计都读它。
CREATE TABLE events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id  TEXT    NOT NULL DEFAULT 'default',
    at         INTEGER NOT NULL,
    level      TEXT    NOT NULL,   -- info | warn | error
    kind       TEXT    NOT NULL,   -- agent.online | tunnel.rejected | console.login | ...
    subject    TEXT    NOT NULL DEFAULT '',
    message    TEXT    NOT NULL,
    -- actor 记录是谁触发的（管理员用户名 / agent ID / 空表示系统）。
    -- 审计要求能回答「谁改的」。
    actor      TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX idx_events_at ON events(at DESC);
CREATE INDEX idx_events_kind ON events(kind, at DESC);

-- ── 时序 rollup ────────────────────────────────────────────────────────────
-- 三个粒度同构表。frp 的流量历史只在内存、重启即失（ReserveDays=7），
-- 且完全没有延迟与丢包——对场景一的音视频毫无用处。

CREATE TABLE tunnel_sample_1m (
    tunnel_id  TEXT    NOT NULL,
    bucket     INTEGER NOT NULL,   -- unix 秒，向下取整到粒度
    bytes_in   INTEGER NOT NULL DEFAULT 0,
    bytes_out  INTEGER NOT NULL DEFAULT 0,
    pkts_in    INTEGER NOT NULL DEFAULT 0,
    pkts_out   INTEGER NOT NULL DEFAULT 0,
    conns_ok   INTEGER NOT NULL DEFAULT 0,
    conns_err  INTEGER NOT NULL DEFAULT 0,
    -- 丢包率用整数 ppm（百万分率）避免浮点漂移累积。
    loss_ppm   INTEGER NOT NULL DEFAULT 0,
    rtt_sum_us INTEGER NOT NULL DEFAULT 0,
    rtt_max_us INTEGER NOT NULL DEFAULT 0,
    -- samples 是折叠计数，上卷到更粗粒度时重新求均值需要它。
    samples    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tunnel_id, bucket)
) STRICT, WITHOUT ROWID;

CREATE TABLE tunnel_sample_5m (
    tunnel_id  TEXT    NOT NULL,
    bucket     INTEGER NOT NULL,
    bytes_in   INTEGER NOT NULL DEFAULT 0,
    bytes_out  INTEGER NOT NULL DEFAULT 0,
    pkts_in    INTEGER NOT NULL DEFAULT 0,
    pkts_out   INTEGER NOT NULL DEFAULT 0,
    conns_ok   INTEGER NOT NULL DEFAULT 0,
    conns_err  INTEGER NOT NULL DEFAULT 0,
    loss_ppm   INTEGER NOT NULL DEFAULT 0,
    rtt_sum_us INTEGER NOT NULL DEFAULT 0,
    rtt_max_us INTEGER NOT NULL DEFAULT 0,
    samples    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tunnel_id, bucket)
) STRICT, WITHOUT ROWID;

CREATE TABLE tunnel_sample_1h (
    tunnel_id  TEXT    NOT NULL,
    bucket     INTEGER NOT NULL,
    bytes_in   INTEGER NOT NULL DEFAULT 0,
    bytes_out  INTEGER NOT NULL DEFAULT 0,
    pkts_in    INTEGER NOT NULL DEFAULT 0,
    pkts_out   INTEGER NOT NULL DEFAULT 0,
    conns_ok   INTEGER NOT NULL DEFAULT 0,
    conns_err  INTEGER NOT NULL DEFAULT 0,
    loss_ppm   INTEGER NOT NULL DEFAULT 0,
    rtt_sum_us INTEGER NOT NULL DEFAULT 0,
    rtt_max_us INTEGER NOT NULL DEFAULT 0,
    samples    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tunnel_id, bucket)
) STRICT, WITHOUT ROWID;

-- RTT 直方图。
--
-- **必须存桶而不是存 p95**：分位数不能被平均，把 1 分钟的 p95 再平均成
-- 1 小时的 p95 是算术错误。存 le_us（小于等于该微秒数的计数）之后，
-- 任意粒度的分位数都能正确算出来。
CREATE TABLE tunnel_rtt_hist_1m (
    tunnel_id TEXT    NOT NULL,
    bucket    INTEGER NOT NULL,
    le_us     INTEGER NOT NULL,
    count     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tunnel_id, bucket, le_us)
) STRICT, WITHOUT ROWID;

-- +goose Down
DROP TABLE tunnel_rtt_hist_1m;
DROP TABLE tunnel_sample_1h;
DROP TABLE tunnel_sample_5m;
DROP TABLE tunnel_sample_1m;
DROP TABLE events;
DROP TABLE console_sessions;
DROP TABLE admins;
DROP TABLE tunnels;
DROP TABLE enrol_tokens;
DROP TABLE agents;
