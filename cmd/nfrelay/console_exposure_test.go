package main

import (
	"log/slog"
	"strings"
	"testing"
)

// TestConsoleExposureWarningCoversTheDangerousCombination 钉住那条启动告警。
//
// 控制台是明文 HTTP。默认形态（只绑 loopback）下这完全正确。危险的是
// 「绑到 0.0.0.0 且前面没有做 TLS 终止的反代」—— 那时管理员口令、会话 Cookie、
// CSRF 令牌全部以明文经过网络，而中继照常启动、控制台照常能用，
// **界面上与日志里此前都看不出来**。
//
// 所以这条告警是那个形态唯一的信号。而它必须**只在**那个形态下响：
// 一条对着自带 docker-compose 每次启动都误报的告警，一周之后就被所有人忽略了
// （那正是设计复审里被点名要切掉的「狼来了」）。
func TestConsoleExposureWarningCoversTheDangerousCombination(t *testing.T) {
	cases := []struct {
		name      string
		addr      string
		behindTLS bool
		wantWarn  bool
		mustSay   string
		why       string
	}{
		{
			name: "默认形态：loopback 明文", addr: "127.0.0.1:9443", behindTLS: false,
			wantWarn: false,
			why:      "流量不出机器，正确且最常见 —— 对它告警就是狼来了",
		},
		{
			name: "loopback + 声明反代", addr: "127.0.0.1:9443", behindTLS: true,
			wantWarn: false,
			why:      "反代在同一台机器上回源，最常见的正确加固形态",
		},
		{
			name: "非 loopback 且未声明反代", addr: "0.0.0.0:9443", behindTLS: false,
			wantWarn: true, mustSay: "-console-behind-tls-proxy",
			why: "口令明文过网络。告警里必须给出解法，否则用户只知道「有问题」",
		},
		{
			name: "具体公网 IP 且未声明反代", addr: "203.0.113.7:9443", behindTLS: false,
			wantWarn: true, mustSay: "明文",
			why: "绑具体地址与绑 0.0.0.0 一样危险 —— 判据是「是不是回环」",
		},
		{
			name: "非 loopback + 声明反代", addr: "0.0.0.0:9443", behindTLS: true,
			wantWarn: true, mustSay: "明文",
			why: "是正当形态，但反代到中继这一段仍是明文，值得说一句",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
			warnConsoleExposure(tc.addr, tc.behindTLS, log)
			out := buf.String()

			gotWarn := strings.Contains(out, "level=WARN")
			if gotWarn != tc.wantWarn {
				t.Fatalf("告警=%v，期望 %v（%s）\n日志：%s", gotWarn, tc.wantWarn, tc.why, out)
			}
			if tc.mustSay != "" && !strings.Contains(out, tc.mustSay) {
				t.Errorf("告警里必须出现 %q（%s），实际：%s", tc.mustSay, tc.why, out)
			}
		})
	}

	// localhost 这个写法也算回环 —— 不认它会对一个正确形态误报。
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	warnConsoleExposure("localhost:9443", false, log)
	if strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("localhost 应当被认成回环，实际告警了：%s", buf.String())
	}
}
