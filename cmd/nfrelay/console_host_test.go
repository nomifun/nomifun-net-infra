package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nomifun/nomifun-net-infra/internal/console"
)

// hostCheckHandler 造一个带指定白名单的控制台处理器。
func hostCheckHandler(t *testing.T, bind string, hosts []string) http.Handler {
	t.Helper()
	return newTestConsoleHandlerWith(t, func(o *console.Options) {
		o.BindAddr = bind
		o.AllowedHosts = hosts
	})
}

func get(h http.Handler, host, path string, accept string) *http.Response {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Host = host
	if accept != "" {
		r.Header.Set("Accept", accept)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Result()
}

// TestConsoleHostsAcceptsAHostPortForm 是这个文件里最要紧的一条：
// 它抓的是一个**此前静默失效**的配置项。
//
// allowedHosts 这张表有两个消费者（HostCheck 比 Host 头、originAllowed 比
// Origin 头），两处都在查表前剥掉端口 —— 所以入表的键也必须剥过端口。
// 修之前 `-console-hosts relay.example.com:9443` 会把带端口的字符串做键，
// 而查的是不带端口的，于是**两种 Host 写法都 421**：运维以为自己配好了
// DNS 重绑定防护，实际上是把自己关在门外。而 docker-compose 的注释里
// 恰好就在教人写这个 flag。
func TestConsoleHostsAcceptsAHostPortForm(t *testing.T) {
	for _, configured := range []string{
		"relay.example.com",
		"relay.example.com:9443", // 带端口 —— 修之前这一行会让整个 flag 失效
		"  RELAY.Example.COM  ",  // 大小写与空白
	} {
		t.Run(configured, func(t *testing.T) {
			h := hostCheckHandler(t, "127.0.0.1:9443", []string{configured})
			for _, reqHost := range []string{"relay.example.com", "relay.example.com:9443"} {
				res := get(h, reqHost, "/api/setup", "")
				if res.StatusCode == http.StatusMisdirectedRequest {
					t.Errorf("配置 %q 之后，Host=%q 仍被拒 —— 这个 flag 静默失效了",
						configured, reqHost)
				}
			}
		})
	}
}

// TestIPv6WhitelistEntriesWorkInEveryWrittenForm 钉住一条真实存在过的 bug。
//
// 不带端口的 IPv6 常被写成带方括号的 `[2001:db8::1]`（那是 URL 里的写法），
// 而 Host 头里不带端口时**不带**方括号。入表不剥方括号的话这条条目永远匹配不上：
// 键是 `[2001:db8::1]`，而查表用的是剥完端口的 `2001:db8::1`。
//
// 症状具有误导性：同一份配置里的域名条目工作正常，看起来像「只有 IPv6 被歧视」。
//
// 线索早就在代码里：默认白名单同时放了 `[::1]` 与 `::1` 两种写法 ——
// 那是这个歧义早就存在的痕迹，只是当时用「两个都加」绕过去了，
// 而用户给的条目没人替他绕。
func TestIPv6WhitelistEntriesWorkInEveryWrittenForm(t *testing.T) {
	for _, configured := range []string{
		"[2001:db8::1]",      // URL 写法，不带端口 —— 修之前这一行整条失效
		"2001:db8::1",        // 裸写法
		"[2001:db8::1]:9443", // 带端口
	} {
		t.Run(configured, func(t *testing.T) {
			h := hostCheckHandler(t, "127.0.0.1:9443", []string{configured})
			// Host 头里带端口的 IPv6 必须带方括号（RFC 3986），
			// 不带端口时则不带 —— 两种都要认。
			for _, reqHost := range []string{"[2001:db8::1]:9443", "2001:db8::1"} {
				if res := get(h, reqHost, "/api/setup", ""); res.StatusCode == http.StatusMisdirectedRequest {
					t.Errorf("配置 %q 之后，Host=%q 仍被拒 —— 这条白名单条目静默失效了",
						configured, reqHost)
				}
			}
		})
	}
}

// TestUnspecifiedAddressesNeverBecomeAllowedHosts 防的是一个不可见的洞。
//
// `-console 0.0.0.0:9443` 会把 0.0.0.0 送进白名单构造，而那不是任何客户端
// 会发出的 Host。更糟的是 `-console-hosts=":9443"` 这种笔误剥完端口是**空串**
// —— 一个空键会放行所有**不带 Host 头**的请求（HTTP/1.0 客户端、手写 socket），
// 也就是在 DNS 重绑定防护上开一个看不出来的缺口。
func TestUnspecifiedAddressesNeverBecomeAllowedHosts(t *testing.T) {
	h := hostCheckHandler(t, "0.0.0.0:9443", []string{":9443", "", "   ", "0.0.0.0", "::", "*"})

	for _, bad := range []string{"", "0.0.0.0", "0.0.0.0:9443", "evil.example.com", "*"} {
		res := get(h, bad, "/api/setup", "")
		if res.StatusCode != http.StatusMisdirectedRequest {
			t.Errorf("Host=%q 应当被拒（状态 %d）—— 通配/未指定/空值绝不能进白名单",
				bad, res.StatusCode)
		}
	}
	// loopback 仍然必须能用，否则本机运维被自己的防护挡在门外。
	if res := get(h, "127.0.0.1:9443", "/api/setup", ""); res.StatusCode == http.StatusMisdirectedRequest {
		t.Error("loopback 永远要放行")
	}
}

// TestSPAIsBehindTheHostGateToo 钉住一条**刻意改掉的**行为。
//
// 此前 `/` 在闸门外：别名 Host 下页面 200 载入正常、而所有 /api/* 421，
// 于是运维看到一个渲染完整却什么都点不动的控制台，界面上没有任何解释。
// 现在整个 mux 都在闸内，失败是闭合的，而且 421 自己会说怎么修。
//
// 附带的收益：完整的 index.html 里有产品名与带哈希的资源名，
// 足够确认「这是一台 NomiRelay」并推断版本。没有理由把它交给一个
// 我们已经判定为「发错了」的请求。
func TestSPAIsBehindTheHostGateToo(t *testing.T) {
	h := hostCheckHandler(t, "127.0.0.1:9443", nil)

	for _, path := range []string{"/", "/index.html", "/tunnels", "/assets/x.js", "/api/setup"} {
		res := get(h, "evil.attacker.example", path, "text/html")
		if res.StatusCode != http.StatusMisdirectedRequest {
			t.Errorf("别名 Host 下 %s = %d，期望 421 —— 半开状态（页面能开、API 全挂）"+
				"是最难排查的失败形态", path, res.StatusCode)
		}
		body := readAll(t, res)
		if strings.Contains(body, "<div id=\"root\">") {
			t.Errorf("别名 Host 下 %s 返回了 index.html —— 泄露产品指纹", path)
		}
	}
}

// TestMisdirectedResponseExplainsHowToFixIt 钉住这条响应存在的意义。
//
// 修之前它只有一句「Host 不被允许」：既没说是哪个 Host，也没说去配什么。
// 一个正在排障的人拿到那句话之后唯一的下一步是去读源码。
func TestMisdirectedResponseExplainsHowToFixIt(t *testing.T) {
	h := hostCheckHandler(t, "127.0.0.1:9443", nil)

	// 浏览器导航（Accept 要 HTML）：纯文本，直接显示在页面上。
	res := get(h, "relay.example.com", "/", "text/html,application/xhtml+xml")
	if res.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("状态 %d，期望 421", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("浏览器导航应当收到 text/plain（一坨 JSON 对正在排障的人是噪音），实际 %q", ct)
	}
	body := readAll(t, res)
	for _, want := range []string{"relay.example.com", "-console-hosts"} {
		if !strings.Contains(body, want) {
			t.Errorf("响应里必须出现 %q，否则用户不知道该改什么：%q", want, body)
		}
	}
	if !strings.Contains(body, "不是鉴权失败") {
		t.Error("必须说清这不是鉴权失败 —— 否则用户会去查密码，查错方向")
	}

	// 程序化调用：JSON 信封，与其他错误同形状。
	res = get(h, "relay.example.com", "/api/setup", "application/json")
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("API 调用应当收到 JSON，实际 %q", ct)
	}
	if b := readAll(t, res); !strings.Contains(b, "misdirected_host") {
		t.Errorf("JSON 里应当有稳定的 code 供客户端分支，实际 %q", b)
	}
}

// TestHealthzAnswersProbesOnAnyHost 钉住编排探针那条豁免。
//
// k8s 的 httpGet 默认拿 Pod IP 当 Host、Docker healthcheck 同理 ——
// 它们不可能知道运维配了什么 -console-hosts。让它们拿 421 会把一个健康的
// 中继标成不健康并反复重启它。
//
// 这不削弱 DNS 重绑定防护：那类攻击的目的是借浏览器的 Cookie 去调有副作用的
// 接口，而 /healthz 不鉴权、无副作用、只回 {"ok":true}，攻击者直连就能拿到
// 同样的字节。但**只放行 GET/HEAD**：写方法即使在无副作用路径上也没有理由
// 被放过，而 ServeMux 的模式匹配不区分方法。
func TestHealthzAnswersProbesOnAnyHost(t *testing.T) {
	h := hostCheckHandler(t, "0.0.0.0:9443", nil)

	for _, host := range []string{"10.42.0.7:9443", "evil.attacker.example", "", "192.0.2.1"} {
		res := get(h, host, "/healthz", "")
		if res.StatusCode != http.StatusOK {
			t.Errorf("Host=%q 的 /healthz = %d，期望 200 —— 编排探针会把中继反复重启",
				host, res.StatusCode)
		}
		// 安全头必须仍然覆盖它（它在 SecurityHeaders 里面）。
		if res.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("Host=%q 的 /healthz 丢了安全头", host)
		}
	}

	// 写方法不在豁免范围内。
	for _, m := range []string{http.MethodPost, http.MethodDelete, http.MethodPut} {
		r := httptest.NewRequest(m, "/healthz", nil)
		r.Host = "evil.attacker.example"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusMisdirectedRequest {
			t.Errorf("别名 Host 下 %s /healthz = %d，期望 421 —— 豁免只该给 GET/HEAD",
				m, w.Code)
		}
	}
}

func readAll(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := res.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return sb.String()
}
