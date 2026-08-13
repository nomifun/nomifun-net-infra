-- +goose Up
-- 一张放服务端长期密钥的小表。
--
-- # 为什么必须持久化，不能每次启动生成
--
-- TURN 的临时凭据是 HMAC(secret, 用户名)，校验方要用**同一个** secret
-- 重算。每次启动换一个的话，中继一重启，所有已签发但还没过期的凭据
-- 立刻全部失效 —— 正在通话的浏览器会在下一次 ICE 重启时断掉，
-- 而日志里只会显示「鉴权失败」，看不出是重启导致的。
--
-- # 为什么单独一张表而不是塞进某个既有表
--
-- 这里放的是**服务端自己的**密钥，与租户、隧道、agent 都无关。
-- 塞进任何一张业务表都会让「删掉最后一条隧道」之类的操作有机会连带
-- 删掉它。名字用 name 而不是 key：key 在 SQL 里是保留字。
CREATE TABLE server_secrets (
    name       TEXT    PRIMARY KEY,
    secret     BLOB    NOT NULL,
    created_at INTEGER NOT NULL
);

-- +goose Down
DROP TABLE server_secrets;
