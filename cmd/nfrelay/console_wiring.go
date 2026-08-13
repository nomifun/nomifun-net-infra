package main

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/nomifun/nomifun-net-infra/internal/console"
	"github.com/nomifun/nomifun-net-infra/internal/store"
)

// consoleConfig 是控制台相关的命令行参数。
//
// # 为什么把这几行抽出来
//
// console.Options 有八个字段，此前是一个内联字面量埋在 400 行的 run() 里。
// 那正是本轮要修的那个 bug 的温床：`Secure` 字段**从来没有被赋过值**，
// 于是 __Host- 前缀、Cookie 的 Secure 属性、HSTS 三样全是死代码 ——
// 而没有任何测试能看见这件事，因为构造它的那段代码不可达。
//
// 抽成纯函数之后「flag 到 Options」这一步就有判据了（console_wiring_test.go）。
// 这不是为了好看：一个不可测的装配步骤里，漏掉一个字段与写对一个字段
// 长得一模一样。
type consoleConfig struct {
	addr      string
	hosts     string
	behindTLS bool
}

// consoleOptions 把命令行参数映射成 console.Options。
func consoleOptions(
	cfg consoleConfig, db *store.DB, rt *runtime,
	turn console.TurnSource, log *slog.Logger,
) console.Options {
	return console.Options{
		DB:           db,
		Snapshot:     rt,
		Turn:         turn,
		Settings:     rt,
		Log:          log,
		BindAddr:     cfg.addr,
		AllowedHosts: splitCSV(cfg.hosts),
		// 必须真的接上。这一行缺席就是本轮修的那个 bug。
		Secure: cfg.behindTLS,
	}
}

// ValidateListenAddr 校验一个「host:port」形式的监听地址。
//
// # 为什么空串必须被拒
//
// http.Server 与 net.Listen 对空 Addr 的默认是 **":80"**（标准库
// net/http/server.go：Addr 为空时用 ":http"）。也就是说 `-console ""`
// 不是「关掉控制台」，而是**把控制台开到 80 端口上**：
//
//   - 它会与 -acme-http 抢端口（报 address already in use，而报错文案指向 ACME）；
//   - warnConsoleExposure 那条暴露告警**一条都不会打** —— 因为空串既不是
//     loopback 也解析不出主机，日志里毫无线索；
//   - 而 80 通常是对公网开放的。
//
// 本仓没有「关闭控制台」的开关。要限制可达性只能靠绑 loopback + SSH 隧道，
// 或者容器/编排层的端口映射。所以空串一定是笔误，必须当场拒绝而不是猜。
func ValidateListenAddr(what, addr string) error {
	if strings.TrimSpace(addr) == "" {
		return fmt.Errorf("%s 不能为空：空值会让标准库回落到 \":80\"（不是「关闭」）；"+
			"本程序没有关闭它的开关，要限制可达性请绑 127.0.0.1 或用编排层的端口映射", what)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s %q 不是合法的 host:port：%w", what, addr, err)
	}
	if port == "" {
		return fmt.Errorf("%s %q 缺少端口 —— 缺端口时标准库会回落到 \":80\"", what, addr)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return fmt.Errorf("%s 的端口 %q 不是数字", what, port)
	}
	_ = host // 空 host（"0.0.0.0" 的等价写法 ":9443"）是合法的
	return nil
}

// ValidatePortRange 校验一对端口边界，并**拒绝静默截断**。
//
// flag.Uint 收下的值会被强转成 uint16 送进 TURN 配置。写 70000 会静默变成
// 4464 —— 于是 TURN 的中继端口落在一个你没预期、防火墙也没放通的低号段，
// 现象是「分配成功但媒体不通」，而启动日志一切正常。
//
// 写 0 或 65536 则会静默退回默认值，同样看不出来。
func ValidatePortRange(what string, lo, hi uint) error {
	for name, v := range map[string]uint{"下界": lo, "上界": hi} {
		if v < 1 || v > 65535 {
			return fmt.Errorf("%s的%s %d 超出 1-65535 —— 强转成 uint16 会静默截断，"+
				"于是端口落在一个你没预期、防火墙也没放通的号段（现象是「分配成功但媒体不通」）",
				what, name, v)
		}
	}
	if lo > hi {
		return fmt.Errorf("%s的下界 %d 大于上界 %d", what, lo, hi)
	}
	return nil
}
