package agent

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(t.TempDir(), quietLog())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestCredentialSurvivesAProcessRestart 是这个文件存在的全部理由。
//
// 入网令牌是一次性的，而中继下发的长期密钥此前只在内存里 —— 于是任何
// Restart=always 的部署第一次重启后就永久失联，要人工重签令牌，
// 而重签又会换掉 agent ID 让既有隧道全部悬空。
//
// 「第二个进程」在这里就是「用同一个目录再 OpenStore 一次」：
// 那正是重启后发生的事。
func TestCredentialSurvivesAProcessRestart(t *testing.T) {
	dir := t.TempDir()

	first, err := OpenStore(dir, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	want := Credential{AgentID: "agent-abc123", Key: "deadbeef00112233"}
	if err := first.Save(want); err != nil {
		t.Fatalf("落盘失败：%v", err)
	}

	second, err := OpenStore(dir, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	got, err := second.Load()
	if err != nil {
		t.Fatalf("重启后读凭据失败：%v", err)
	}
	if got.AgentID != want.AgentID || got.Key != want.Key {
		t.Fatalf("重启后凭据不一致：读到 {%q,%q}，期望 {%q,%q} —— "+
			"这正是「重启即永久失联」那个 bug", got.AgentID, got.Key, want.AgentID, want.Key)
	}
	if got.MachineID == "" {
		t.Error("读出来的凭据必须带机器标识（握手要用它上报）")
	}
}

// TestNoCredentialIsNotAnError 钉住首次启动的形状。
//
// 第一次跑 nfagent 时状态目录是空的。那是**正常状态**，不是错误 ——
// 报错会让调用方要么忽略它、要么在启动时打一条假故障。
func TestNoCredentialIsNotAnError(t *testing.T) {
	s := newStore(t)
	got, err := s.Load()
	if err != nil {
		t.Fatalf("空目录不该报错：%v", err)
	}
	if got.AgentID != "" || got.Key != "" {
		t.Fatalf("空目录应当返回零值凭据，实际 %+v", got)
	}
}

// TestMachineIDIsStableAcrossRestartsAndUniqueAcrossMachines 钉住这个字段的两个性质。
//
// 它此前恒为空串：管道从 proto.Hello 一直通到 agents.machine_id，
// 唯独 agent 侧从不赋值。而它的语义（区分物理机，与可撤销的 AgentID 不同）
// 要求「同机稳定、异机不同」——只满足一半的实现毫无用处。
func TestMachineIDIsStableAcrossRestartsAndUniqueAcrossMachines(t *testing.T) {
	dir := t.TempDir()
	s1, _ := OpenStore(dir, quietLog())
	first, err := s1.MachineID()
	if err != nil {
		t.Fatal(err)
	}
	if !isMachineID(first) {
		t.Fatalf("机器标识格式不对：%q（应当是 32 位小写 hex）", first)
	}

	// 同一个目录再打开 = 重启。必须一模一样。
	s2, _ := OpenStore(dir, quietLog())
	again, err := s2.MachineID()
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Errorf("重启后机器标识变了：%q → %q —— 那这个字段就不再标识物理机了",
			first, again)
	}

	// 另一台机器（另一个目录）必须不同。
	other := newStore(t)
	o, err := other.MachineID()
	if err != nil {
		t.Fatal(err)
	}
	if o == first {
		t.Error("两台机器拿到同一个标识 —— 这个字段唯一的用途就被摧毁了")
	}
}

// TestMachineIDIsNotDerivedFromTheHostMachineID 钉住一条**刻意的**设计决定。
//
// 从 /etc/machine-id 派生看起来更稳，但它是要外发的（走线协议进中继、落库、
// 进数据库备份），而我们能用的派生密钥只能是源码里的公开常量 ——
// 那挡不住关联分析，只是让人以为挡住了。更要紧的是它在本产品的目标形态里
// 恰好不可靠：OpenWrt 没有这个文件；容器里它可能是空文件，或被烤进镜像
// 而让每个副本报同一个值。
//
// 这条测试的判据是「本机的 machine_id 不等于宿主 /etc/machine-id 的任何
// 直接形态」。它抓的是「有人为了『更稳』把实现换成读那个文件」。
func TestMachineIDIsNotDerivedFromTheHostMachineID(t *testing.T) {
	host, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		t.Skip("本机没有 /etc/machine-id，这条判据无从建立")
	}
	h := strings.TrimSpace(string(host))
	if h == "" {
		t.Skip("/etc/machine-id 是空的（容器里常见）")
	}

	got, err := newStore(t).MachineID()
	if err != nil {
		t.Fatal(err)
	}
	if got == h {
		t.Fatal("机器标识就是宿主的 /etc/machine-id —— 那个值 systemd 自己" +
			"定性为应当视作机密，而这个字段会走线协议外发、落进中继的库与备份")
	}
}

// TestFirstEnrolmentCarriesTheMachineID 钉住首次入网那一跳。
//
// 中继在 RedeemEnrolToken 的 INSERT 里落库 machine_id，后续 TouchAgent
// 只是刷新 —— 所以**第一次**握手的 Hello 必须带上它。只在「凭据有效」
// 路径上填的实现会让库里那行永远是空串，也就是修之前的现状。
func TestFirstEnrolmentCarriesTheMachineID(t *testing.T) {
	s := newStore(t)
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.AgentID != "" {
		t.Fatal("前置不成立：这应当是首次启动（无凭据）")
	}
	if !isMachineID(got.MachineID) {
		t.Fatalf("首次启动的凭据必须带机器标识（%q）—— 首次入网的 Hello "+
			"是中继落库这个字段的唯一一次", got.MachineID)
	}
}

// TestCorruptCredentialIsMovedAsideNotDeleted 钉住损坏时的处置。
//
// 三件事必须同时成立：不 panic、不删原文件（那可能是这台机器身份的唯一副本）、
// 且按「未入网」处理让带令牌的启动能自愈。
func TestCorruptCredentialIsMovedAsideNotDeleted(t *testing.T) {
	cases := []struct{ name, body string }{
		{"不是 JSON", "这不是 JSON"},
		{"版本不对", `{"v":99,"agent_id":"a","key":"00"}`},
		{"缺 key", `{"v":1,"agent_id":"a"}`},
		{"缺 agent_id", `{"v":1,"key":"00"}`},
		{"key 不是 hex", `{"v":1,"agent_id":"a","key":"zzzz"}`},
		{"被截断", `{"v":1,"agent_id":"age`},
		{"空文件", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, credentialFile)
			if err := os.WriteFile(path, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			s, err := OpenStore(dir, quietLog())
			if err != nil {
				t.Fatal(err)
			}

			got, err := s.Load()
			if err != nil {
				t.Fatalf("坏凭据不该让 agent 起不来：%v", err)
			}
			if got.AgentID != "" {
				t.Fatalf("坏凭据不该被当成有效的：%+v", got)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Error("坏凭据应当被挪走，否则下次启动会再撞一次同样的错")
			}
			saved, err := os.ReadFile(path + corruptSuffix)
			if err != nil {
				t.Fatalf("坏凭据必须留证而不是删除：%v", err)
			}
			if string(saved) != c.body {
				t.Errorf("留下来的内容被改动过：%q", saved)
			}
		})
	}
}

// TestSaveRefusesIncompleteCredentials 防的是写出一份「看起来有」的坏凭据。
//
// 写进去之后下次启动会走凭据路径、握手失败、而令牌已经作废 ——
// 那比一开始就没写更难查。
func TestSaveRefusesIncompleteCredentials(t *testing.T) {
	s := newStore(t)
	for _, c := range []Credential{
		{AgentID: "a"},
		{Key: "00"},
		{},
	} {
		if err := s.Save(c); err == nil {
			t.Errorf("不完整的凭据 %+v 应当被拒", c)
		}
	}
	if _, err := os.Stat(filepath.Join(s.Dir(), credentialFile)); !os.IsNotExist(err) {
		t.Error("被拒的写入不该留下文件")
	}
}

// TestCredentialFileIsNotWorldReadable 钉住权限。
//
// 文件 mode 是这份明文密钥**唯一**的访问控制手段（本包刻意不做加密：
// 同一块盘上在密文旁边放解密密钥是自欺，而 keyring 会弄坏 MIPS 路由器上的
// 无人值守启动）。所以 0600 不是加固，是那道唯一的锁。
func TestCredentialFileIsNotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 不用 unix mode 位")
	}
	// 用一个我们从零建的子目录，不用 t.TempDir()（后者是 0755，测的就不是
	// 我们 MkdirAll 出来的 mode 了）。
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenStore(dir, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	// 走真实启动顺序：Load 先跑（顺手生成 machine_id），Save 在入网后。
	if _, err := s.Load(); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(Credential{AgentID: "a", Key: "00ff"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{credentialFile, machineIDFile} {
		fi, err := os.Stat(filepath.Join(s.Dir(), name))
		if err != nil {
			t.Fatal(err)
		}
		if perm := fi.Mode().Perm(); perm != fileMode {
			t.Errorf("%s 的权限是 %04o，必须是 %04o —— 这是明文密钥唯一的锁",
				name, perm, fileMode)
		}
	}
	di, err := os.Stat(s.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if perm := di.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("状态目录权限 %04o 允许同组/其他用户访问", perm)
	}
}

// TestSaveLeavesNoTemporaryFilesBehind 钉住原子写不会长垃圾。
//
// 用固定名 + O_EXCL 的实现会在一次崩溃后留下残留，于是此后**每一次**落盘
// 都永久失败 —— 正好复现我们要修的那个 bug。所以实现用 CreateTemp，
// 而这条测试确认成功路径也不留下 .tmp。
func TestSaveLeavesNoTemporaryFilesBehind(t *testing.T) {
	s := newStore(t)
	for i := range 3 {
		if err := s.Save(Credential{AgentID: "a", Key: "00"}); err != nil {
			t.Fatalf("第 %d 次落盘失败：%v", i+1, err)
		}
	}
	ents, err := os.ReadDir(s.Dir())
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") || strings.Contains(e.Name(), ".writable-") {
			left = append(left, e.Name())
		}
	}
	if len(left) > 0 {
		t.Errorf("留下了临时文件 %v —— 反复重连会让状态目录慢慢长满", left)
	}
}

// TestExplicitStateDirIsNeverSilentlyReplaced 钉住 -state-dir 的语义。
//
// 显式指定了却不可用时**必须失败**，绝不能悄悄换到别的候选目录：
// 换了就是重新入网，中继上凭空多一个 agent、原 agent 名下的隧道全部悬空，
// 而运维看到的现象是「隧道一条都没了」，命令行却一个字都没改。
func TestExplicitStateDirIsNeverSilentlyReplaced(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("以 root 跑时不存在不可写目录")
	}
	// 一个存在但不可写的目录。
	parent := t.TempDir()
	locked := filepath.Join(parent, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(locked, "state")

	got, err := ResolveStateDir(target)
	if err == nil {
		t.Fatalf("不可用的 -state-dir 必须报错，实际返回了 %q", got)
	}
	if !strings.Contains(err.Error(), target) {
		t.Errorf("错误信息里必须出现用户给的那个路径，否则他不知道该修哪个：%v", err)
	}
}

// TestResolvePrefersTheDirectoryThatAlreadyHasCredentials 钉住候选表的挑选顺序。
//
// 这条防的是「先以 root 跑、后改普通用户跑」这个真实场景：若只按
// 「第一个可写」挑，就会落到另一个目录并重新入网。
//
// 用 XDG_STATE_HOME 造出「第二个候选里已有凭据」的局面 ——
// 第一个候选 /var/lib/nfagent 在测试环境下通常不可写（非 root），
// 于是若实现只看可写性就会挑 XDG；这里要验的是**即使**顺序靠后，
// 有凭据的那个也必须赢。
func TestResolvePrefersTheDirectoryThatAlreadyHasCredentials(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("候选表按平台不同，这条只在 unix 布局下成立")
	}
	xdg := t.TempDir()
	t.Setenv("XDG_STATE_HOME", xdg)
	home := t.TempDir()
	t.Setenv("HOME", home)

	// 在 $HOME/.local/state/nfagent（**最后**一个候选）里放一份凭据。
	last := filepath.Join(home, ".local", "state", "nfagent")
	if err := os.MkdirAll(last, dirMode); err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(credentialDoc{
		Version: credentialVersion, AgentID: "agent-existing", Key: "00ff",
	})
	if err := os.WriteFile(filepath.Join(last, credentialFile), blob, fileMode); err != nil {
		t.Fatal(err)
	}

	got, err := ResolveStateDir("")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.Abs(last)
	if got != want {
		t.Errorf("挑中了 %q，应当挑已有凭据的 %q —— 挑错就是重新入网，"+
			"既有隧道会全部悬空", got, want)
	}
}

// TestVolatileStateDirIsCalledOut 钉住 OpenWrt 那条陷阱的告警。
//
// OpenWrt 的 /var 是指向 /tmp 的符号链接（tmpfs），默认路径在那里重启即清空
// —— 落盘修了照样失联，而且**更难查**：这次日志会说「已持久化」。
func TestVolatileStateDirIsCalledOut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("路径判据是 unix 形态")
	}
	// 用一个真的在 /tmp 下的目录（t.TempDir 在多数系统上就是），
	// 若本机 TMPDIR 不在 /tmp 下则跳过 —— 不为了测试去造符号链接。
	dir := t.TempDir()
	real, err := filepath.EvalSymlinks(dir)
	if err != nil || !strings.HasPrefix(real, "/tmp") {
		t.Skipf("本机临时目录不在 /tmp 下（%q），这条判据无从建立", real)
	}

	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if _, err := OpenStore(dir, log); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "易失") {
		t.Errorf("状态目录在 tmpfs 上时必须告警，实际日志：%q", out)
	}
	if !strings.Contains(out, "-state-dir") {
		t.Error("告警里必须给出解法（用 -state-dir 指到持久盘），" +
			"只说「有问题」等于让用户自己猜")
	}
}
