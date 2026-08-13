package main

import (
	"log/slog"
	"net"
	"net/netip"
)

// warnConsoleExposure 在启动时把控制台的暴露形态说清楚。
//
// # 为什么这必须是启动时的一条日志，而不是文档里的一句话
//
// 控制台是明文 HTTP（`consoleSrv` 走 ListenAndServe，没有 TLS）。这在默认形态下
// 完全正确 —— 它只绑 loopback，流量不出机器。但一旦有人把它绑到 0.0.0.0
// 而前面**没有**做 TLS 终止的反代，那么管理员口令、会话 Cookie、CSRF 令牌
// 全部以明文经过网络。而这件事在界面上、在日志里此前都看不出来：
// 中继照常启动、控制台照常能用，一切正常，只是凭据在网上裸奔。
//
// 所以这条检查的产物是一条**显著的**启动告警。不做成启动失败：
// 本仓自带的 docker-compose 就用 `-console=0.0.0.0:9443` 配
// 「只发布到 127.0.0.1」的端口映射，那是一个完全正当的形态，
// 而拒绝启动会直接打死它。
//
// # 与 docs/research/12-security-ops.md 的立场分歧
//
// 那份档案（:192-193）主张「非 loopback 绑定时拒绝以明文 HTTP 提供服务」。
// v1 不那样做，理由就是上一段：容器与 k8s 里「绑 0.0.0.0 + 由编排限制可达性」
// 是主流形态，而我们无法从进程内部区分它与「真的暴露在公网」。
// 档案是设计输入不是规范性文档，这处偏离在此显式记账。
func warnConsoleExposure(consoleAddr string, behindTLS bool, log *slog.Logger) {
	if consoleAddr == "" {
		return
	}
	host, _, err := net.SplitHostPort(consoleAddr)
	if err != nil {
		return
	}

	loopback := false
	if addr, perr := netip.ParseAddr(host); perr == nil {
		loopback = addr.IsLoopback()
	} else if host == "localhost" {
		loopback = true
	}

	switch {
	case loopback && behindTLS:
		// 反代在同一台机器上（走 loopback 回源）——最常见的正确形态。
		log.Info("控制台已按「反代之后」加固：会话 Cookie 带 Secure 与 __Host- 前缀",
			"地址", consoleAddr)
	case behindTLS:
		// 绑了非 loopback 又声明在反代之后：反代大概在另一台机器上，
		// 那一段回源是明文的。是正当形态，但值得说一句。
		log.Warn("控制台已加固（Cookie 带 Secure），但它绑在非回环地址上："+
			"反代到中继这一段是明文 HTTP，确认那段链路是可信网络",
			"地址", consoleAddr)
	case !loopback:
		// 最危险的一格：明文 + 对外可达 + 没有声明反代。
		log.Warn("控制台绑在非回环地址且未声明前置 TLS 反代 —— "+
			"管理员口令、会话 Cookie、CSRF 令牌将以**明文**经过网络。"+
			"若前面确有做 TLS 终止的反代，请加 -console-behind-tls-proxy；"+
			"若没有，请改回 -console 127.0.0.1:9443 并用 SSH 隧道或 VPN 访问",
			"地址", consoleAddr)
	default:
		// loopback 明文：默认形态，正确，不打扰。
		log.Debug("控制台只绑回环地址，明文 HTTP（默认形态）", "地址", consoleAddr)
	}
}
