package console

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestAPIContractVersionMatchesTheFrontend 钉住两处各写一遍的契约版本。
//
// 前端把 API_CONTRACT_VERSION 编译进包里（web/vite.config.ts 的 define），
// 服务端在 hello 帧里发 APIContractVersion。两者不一致时前端会**误报**
// 「请刷新」——而刷新解决不了问题，因为不一致的是常量本身。
// 那种提示比没有提示更糟：它把用户引向一个无效的动作。
func TestAPIContractVersionMatchesTheFrontend(t *testing.T) {
	path := filepath.Join("..", "..", "web", "vite.config.ts")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 %s 失败：%v", path, err)
	}
	m := regexp.MustCompile(`const API_CONTRACT_VERSION = (\d+)`).FindStringSubmatch(string(b))
	if m == nil {
		t.Fatal("在 vite.config.ts 里找不到 API_CONTRACT_VERSION —— " +
			"它被改名或改写法了？那这条契约测试就失效了，必须一起改")
	}
	want, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatal(err)
	}
	if APIContractVersion != want {
		t.Fatalf("契约版本不一致：Go 是 %d，前端是 %d。\n"+
			"两边必须同时改 —— 不一致会让前端**误报**「请刷新」，"+
			"而刷新解决不了问题（不一致的是常量本身）",
			APIContractVersion, want)
	}
}

// TestHelloFrameCarriesTheContractVersion 是那条提示能不能出现的前提。
//
// 前端的判据是
// `f.api_contract_version !== undefined && ... !== __API_CONTRACT_VERSION__`。
// 服务端不发的话第一个条件就不成立 —— 整条机制（算了、有类型、有横幅）
// 在生产里是死的。这正是本次改动之前的状态：那个字段只存在于前端，
// 服务端一次都没发过。
func TestHelloFrameCarriesTheContractVersion(t *testing.T) {
	s, _ := newTestServer(t)
	auth := setupAndLogin(t, s)

	r := auth(req(http.MethodGet, "/api/events", nil))
	ctx, cancel := contextWithTimeout(t, 2*time.Second)
	defer cancel()
	r = r.WithContext(ctx)

	rec := newStreamRecorder()
	go func() { s.Handler().ServeHTTP(rec, r) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(rec.String(), "event: "+EventHello) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	body := rec.String()
	if !strings.Contains(body, "event: "+EventHello) {
		t.Fatalf("没收到 hello 帧：%s", body[:min(len(body), 300)])
	}

	// 把 hello 帧的 data 抠出来解析，确认字段真的在里面且值对得上。
	// 只 grep 字符串是不够的：那分不清「字段在 hello 里」与
	// 「字段在某个别的帧里」。
	var payload map[string]any
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var p map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &p); err != nil {
			continue
		}
		if _, ok := p["server_time"]; ok {
			payload = p
			break
		}
	}
	if payload == nil {
		t.Fatal("解析不出 hello 帧的 data")
	}
	got, ok := payload["api_contract_version"]
	if !ok {
		t.Fatal("hello 帧必须带 api_contract_version —— " +
			"不发它的话前端那条「请刷新」提示永远不会出现，" +
			"而它要覆盖的正是「中继升级了、浏览器还挂着旧前端」那段时间")
	}
	if int(got.(float64)) != APIContractVersion {
		t.Errorf("契约版本值不对：发了 %v，常量是 %d", got, APIContractVersion)
	}
}
