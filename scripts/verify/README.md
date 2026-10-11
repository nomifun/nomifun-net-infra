# 真实进程验证脚本

每个脚本都会起**真的** `nfrelay` + `nfagent`，建真的隧道，打真的流量。
它们不属于 `make check`（太慢、要抢端口），但 `docs/integration/09-known-gaps.md`
里若干条断言的证据就是它们跑出来的。

放进仓库的理由很直接：**这些断言必须可复核。** 一条写在文档里的「已经生效」，
如果证据只在某台机器的 `/tmp` 里，那它下一个月就退化成一句需要重新相信的话。

## 跑之前：先清残留进程

```sh
ps -eo pid,etime,args | grep -E "[n]frelay|[n]fagent"
```

有残留就先杀掉。残留进程占着端口时，你会连到一台**陈旧的**中继（库里已初始化过），
症状与真实原因毫无关系 —— 这个坑踩过两次，各浪费一轮排查。

脚本自己用 `free_port()` 拿端口、退出时 terminate + kill 兜底，
并且**先 `go build` 再跑二进制**（`go run` 的 SIGTERM 只到父进程，
真正监听端口的子进程会活下来）。

## 每个脚本证明什么

| 脚本 | 证明的事 | 为什么单元测试不够 |
|---|---|---|
| `limits_e2e.py` | 共享入口上 `bytes_per_second` / `max_conns` 真的生效；**改一条已上线隧道的带宽不重启就生效** | 单元测试证明零件对。这里证明的是原始现象「我在控制台配了 1 Mbps，它照样跑满」不再发生 —— 那需要控制台 → 库 → 路由表 → 数据面整条链路 |
| `slot_exhaustion.py` | 共享端口的 512 个判别器槽位**能被空闲 keep-alive 连接占死**，且此时 ACME 挑战一并被关掉；释放后立刻恢复 | 这是一条**发布阻断项**的证据（条目在 `BACKLOG.md` A15）。它无需鉴权、无需真实负载。httptest 里没有判别器信号量 |
| `l2_check.py` | 封 UDP 的网络下 agent 自动退到 L2（TLS/TCP:443 + smux），隧道照常通 | 降级发生在**拨号失败之后**，只有真的拨不通才会走到那条路 |
| `learn_e2e.py` | 学习模式三个端点 + 面板：观测到的源地址能被逐条勾选并写进 `allow_cidrs` | 观测点挂在三条数据面路径上，且只记**被放行之后**的流量 —— 要真打流量才有东西可观测 |
| `mtu_check.py` | 数据报 MTU 是反应式学到的，学到之后进 `TunnelStatus.dgram_mtu`（快照与 SSE 都带） | 它只在**一次超限之后**才有值 |

## 跑法

```sh
python3 scripts/verify/limits_e2e.py     # 约 40 s
python3 scripts/verify/slot_exhaustion.py
python3 scripts/verify/l2_check.py
python3 scripts/verify/learn_e2e.py
python3 scripts/verify/mtu_check.py
```

退出码 0 = 全部通过。失败时会把哪一条失败列出来。

浏览器侧另有 `scripts/browser-smoke.py`（Firefox/WebDriver，真实渲染八节）。
