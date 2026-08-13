-- +goose Up
-- 给隧道加一个连接内短标识，供 UDP 数据报帧头使用。
--
-- # 为什么需要它
--
-- 数据报帧头只有 16 字节（见 internal/udpflow/frame.go），装不下一个字符串
-- 隧道 ID。而帧必须能自己说明「我属于哪条隧道」—— 否则一条承载上多个 UDP
-- 隧道的流量就分不开。这正是 frp UDP 路径的第四个结构性问题：它把原始目的
-- 地址整个丢掉了（pkg/proto/udp/udp.go:64 传 nil），一条隧道因此只能承载
-- 一个 UDP 服务。
--
-- # 为什么不直接用 listen_port 代替
--
-- 独占端口的隧道确实可以用端口区分，但共享入口的隧道 listen_port 为 0。
-- 拿一个「碰巧现在唯一」的字段当标识，等到共享 UDP 入口出现时就要改线协议。
-- 帧格式一开始就留了这个字段，这里把它填上。
--
-- # 0 的含义
--
-- 0 保留为「未分配」，所以唯一索引带 WHERE short_id != 0 —— 与
-- idx_tunnels_port 同一手法：SQLite 的 UNIQUE 允许多个 NULL，
-- 但这里用的是 NOT NULL DEFAULT 0，得靠部分索引才能让 0 可重复。
ALTER TABLE tunnels ADD COLUMN short_id INTEGER NOT NULL DEFAULT 0;

-- 回填已有隧道。
--
-- 不回填的话，升级上来的隧道会一直带着默认值 0：allocShortID 只在 PutTunnel
-- 时跑，而一条从没被改过的隧道永远不会经过那里。它一旦是 UDP 隧道，
-- 数据报就带着 Tunnel=0 出去，解复用直接错位 —— 静默地把流量送到别处，
-- 比启动失败糟糕得多。
--
-- 按 rowid 在租户内排序给 1..N。相关子查询在这里可接受：
-- 它只在升级时跑一次，且隧道数量是几十的量级。
UPDATE tunnels SET short_id = (
    SELECT COUNT(*) FROM tunnels AS t2
    WHERE t2.tenant_id = tunnels.tenant_id AND t2.rowid <= tunnels.rowid
);

CREATE UNIQUE INDEX idx_tunnels_short_id ON tunnels(tenant_id, short_id) WHERE short_id != 0;

-- +goose Down
DROP INDEX idx_tunnels_short_id;
ALTER TABLE tunnels DROP COLUMN short_id;
