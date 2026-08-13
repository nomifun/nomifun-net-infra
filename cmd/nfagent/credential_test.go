package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/agent"
)

func newDirtyRunner(t *testing.T, w io.Writer) (*runner, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	log := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))
	st, err := agent.OpenStore(dir, log)
	if err != nil {
		t.Fatal(err)
	}
	return &runner{
		store: st, log: log,
		cred: agent.Credential{AgentID: "agent-abc123", Key: "deadbeef"},
	}, dir
}

// TestCredentialSaveFailureDoesNotMasqueradeAsHealthy 钉住一个我自己写出来的洞。
//
// 初版把落盘失败写成「致命，当场退出」。而实际上 session() 返回的是普通
// fmt.Errorf，不是 *proto.Error —— loop() 的 errors.As 不匹配，于是落到退避重试；
// 而 r.cred 在 Save **之前**就已填好，200ms 后的重连走 HMAC 分支并**成功**，
// 那次的 IssuedKey 为空，所以再也不会尝试落盘。
//
// 净效果：一个「一次性 agent」在整个进程生命周期里**伪装成健康节点**，
// 直到某次因升级/reboot/OOM 重启才暴露成崩溃循环。而 ERROR 只在入网那一刻打过一次。
//
// 顺带说清为什么**不该**退出：令牌是一次性的、已经作废，退出后重启会拿着空目录 +
// 废令牌 → exit(1) → 配 Restart=always 就是崩溃循环。也就是说退出把一次
// **可恢复**的磁盘故障放大成了永久下线。
func TestCredentialSaveFailureDoesNotMasqueradeAsHealthy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("以 root 跑时只读目录照样可写")
	}
	var buf strings.Builder
	r, dir := newDirtyRunner(t, &buf)

	// 把目录改成只读，模拟「启动之后盘变了」（OpenStore 时它是可写的）。
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	r.persistIssued(r.cred.AgentID)

	if !r.credDirty {
		t.Fatal("落盘失败后必须置脏标记 —— 否则再也不会重试，" +
			"这个进程就变成一个伪装成健康节点的一次性 agent")
	}
	if !strings.Contains(buf.String(), "重启后会永久失联") {
		t.Errorf("必须说清后果（不是笼统的「落盘失败」）：%s", buf.String())
	}

	// 关键：这条路径**不能**让 agent 停止工作。persistIssued 无返回值本身
	// 就是那个保证，这里断言的是它没有 panic 且状态可继续使用。
	if r.cred.AgentID == "" {
		t.Error("内存里的凭据必须保留 —— 本次连接还要靠它继续服务")
	}
}

// TestCredentialPersistenceSelfHealsWhenTheDiskComesBack 钉住自愈。
//
// 磁盘修好之后不需要人工介入、也不需要重启 —— 而重启恰恰是这个状态下
// 最危险的动作（那一刻凭据还没落盘）。
func TestCredentialPersistenceSelfHealsWhenTheDiskComesBack(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("以 root 跑时只读目录照样可写")
	}
	var buf strings.Builder
	r, dir := newDirtyRunner(t, &buf)

	_ = os.Chmod(dir, 0o500)
	r.persistIssued(r.cred.AgentID)
	if !r.credDirty {
		t.Fatal("前置不成立：应当先进入脏状态")
	}

	// 运维修好了目录。下一次重连时重试。
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r.retryPersist()

	if r.credDirty {
		t.Fatal("磁盘恢复后重试应当成功并清掉脏标记 —— " +
			"不自愈就意味着必须重启，而重启是这个状态下最危险的动作")
	}
	if _, err := os.Stat(filepath.Join(dir, "credential.json")); err != nil {
		t.Errorf("补写之后凭据文件必须存在：%v", err)
	}
	if !strings.Contains(buf.String(), "已补写成功") {
		t.Errorf("自愈必须留一条可见的日志，否则运维不知道能安全重启了：%s", buf.String())
	}
}

// TestUnsavedCredentialKeepsComplaining 钉住「保持可见」这半边。
//
// 一条只在入网那一刻出现的 ERROR 会被后面几千行日志淹掉，而这个状态的含义是
// 「你离永久下线只差一次重启」—— 它必须一直可见。
//
// 同时不能变成噪音：一个连接稳定的 agent 每 5 秒上报一次计量，
// 若每次都喊就是每小时 720 条。
func TestUnsavedCredentialKeepsComplaining(t *testing.T) {
	var buf strings.Builder
	r, _ := newDirtyRunner(t, &buf)
	r.credDirty = true

	// 第一次必须喊。
	r.remindIfCredentialUnsaved()
	if n := strings.Count(buf.String(), "仍未落盘"); n != 1 {
		t.Fatalf("第一次应当喊一次，实际 %d 次", n)
	}
	// 窗口内多次调用（模拟 5 秒一次的计量 tick）只能算一次。
	for range 100 {
		r.remindIfCredentialUnsaved()
	}
	if n := strings.Count(buf.String(), "仍未落盘"); n != 1 {
		t.Errorf("窗口内喊了 %d 次 —— 每 5 秒一条会把日志刷成噪音", n)
	}
	// 窗口过去之后必须再喊。
	r.lastDirtyWarn = time.Now().Add(-dirtyWarnInterval - time.Second)
	r.remindIfCredentialUnsaved()
	if n := strings.Count(buf.String(), "仍未落盘"); n != 2 {
		t.Errorf("窗口过去后应当再喊，实际总共 %d 次 —— "+
			"一条只出现一次的 ERROR 会被淹掉", n)
	}

	// 不脏的时候一声都不能出。
	//
	// **必须用一个新的 runner**：复用上面那个的话，它的 lastDirtyWarn 刚被设过，
	// 于是限速会把提醒压住 —— 绿色来自限速而不是来自「不脏」这个判据。
	// 这一点是变异验证抓出来的（删掉 `if !r.credDirty` 那道判断，旧写法照样绿）。
	var clean strings.Builder
	fresh, _ := newDirtyRunner(t, &clean)
	// 只清 OpenStore 自己打的那些（比如「状态目录在易失文件系统上」——
	// t.TempDir() 在 /tmp 下，那条告警是**正确**的，不该被这条测试当成噪音）。
	clean.Reset()
	fresh.credDirty = false
	for range 10 {
		fresh.remindIfCredentialUnsaved()
	}
	if strings.Contains(clean.String(), "仍未落盘") {
		t.Errorf("凭据已落盘时不该有任何提醒（狼来了）：%s", clean.String())
	}
}
