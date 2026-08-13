package agent

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// agent 的状态目录：入网凭据与机器标识落盘的地方。
//
// # 为什么必须有这个文件
//
// 入网令牌是**一次性**的（存储层对已用令牌返回 ErrTokenUsed，中继把它翻译成
// 不可重试的 auth_failed）。而中继在首次入网时下发的长期密钥，此前只写在
// 内存里 —— 于是任何配了 `Restart=always` 的部署，在第一次进程重启后就
// 永久失联，必须人工回控制台重签一枚令牌。而重签会产生一个**新的** agent ID
// （ID 派生自令牌哈希），于是既有隧道全部悬空。
//
// 也就是说：不落盘不是「少一个优化」，而是让这个程序在它最主要的部署形态下
// 只能用一次。
//
// # 为什么凭据与机器标识是两个文件
//
// AgentID 可以被撤销、可以重新签发；MachineID 标识**物理机**。它们同居一个
// 文件的话，「删掉凭据重新入网」这个我们在错误信息里推荐的恢复动作，
// 会顺手换掉机器身份 —— 中继的设备台账里凭空多出一台机器，
// 而这个字段唯一的用途就是区分物理机。
//
// # 为什么明文存
//
// 同一块盘、同一套 ACL 下，在密文旁边放一把解密密钥是自欺。真正的控制是
// 文件 mode（0600）加上部署层的 ProtectSystem=strict / StateDirectory=。
// 而引入 keyring 会直接弄坏 MIPS 路由器上的无人值守启动 —— 那是本产品的
// 旗舰目标平台，它没有 keyring，也没有人在开机时输密码。

const (
	credentialFile = "credential.json"
	// corruptSuffix 是坏凭据被挪到的后缀。
	//
	// 坏文件**改名留证而不是删除**：那可能是这台机器身份的唯一副本，
	// 而「解析不出来」与「内容没价值」是两件事（截断、编码错、被别的程序
	// 覆盖了半截，都可能人工救回来）。删掉之后运维连「原来存的是什么」
	// 都答不上来。
	corruptSuffix = ".corrupt"
	machineIDFile = "machine_id"

	// dirMode / fileMode 是唯一的访问控制手段（见包头注释）。
	dirMode  os.FileMode = 0o700
	fileMode os.FileMode = 0o600
)

// credentialDoc 是 credential.json 的磁盘格式。
//
// 刻意**不**直接序列化 Credential：磁盘格式是一份要长期兼容的契约，
// 而 Credential 是内存结构，将来加一个内存字段不该改变文件格式。
// Version 是将来换格式（比如加轮换）唯一的低成本入口。
type credentialDoc struct {
	Version int    `json:"v"`
	AgentID string `json:"agent_id"`
	// Key 是 hex 编码的长期密钥。字段名跟 Credential.Key 的 json tag 一致 ——
	// 研究档案里管它叫 secret，但同一个东西有两个名字只会给排障加噪音。
	Key string `json:"key"`
	// IssuedAt 只用于人看（排障时回答「这份凭据是什么时候拿到的」）。
	// 不参与任何判定：本地时钟不可信，拿它做过期判断会在时钟错的机器上
	// 把一份好凭据判死。
	IssuedAt string `json:"issued_at,omitempty"`
}

// credentialVersion 是当前磁盘格式版本。
const credentialVersion = 1

// Store 是一个已经打开、已经确认可写的状态目录。
type Store struct {
	dir string
	log *slog.Logger
}

// Dir 返回状态目录的绝对路径。
//
// 调用方要把它打进启动日志：「它到底存哪了」如果不可观测，
// 支持工单里就只能猜（而候选路径有好几个）。
func (s *Store) Dir() string { return s.dir }

// ResolveStateDir 决定状态目录用哪个路径。
//
// explicit 非空时直接用它（不可用即失败，不静默换地方）。否则按平台候选表挑。
//
// # 为什么候选表要「先挑已经有凭据的那个」
//
// 不这样做会产生一个很难查的故障：先以 root 跑过一次（凭据落在
// /var/lib/nfagent），后来改成普通用户跑，若只按「第一个可写」挑就会落到
// $HOME 下，于是**重新入网** —— 中继上凭空多一个 agent，而原来那个 agent
// 名下的隧道全部悬空。运维看到的现象是「隧道一条都没了」，
// 而两次启动的命令行一模一样。
func ResolveStateDir(explicit string) (string, error) {
	if explicit != "" {
		if err := ensureUsable(explicit); err != nil {
			return "", fmt.Errorf("agent: -state-dir %q 不可用：%w", explicit, err)
		}
		return filepath.Abs(explicit)
	}

	cands := stateDirCandidates()
	if len(cands) == 0 {
		return "", errors.New("agent: 无法推断状态目录，请用 -state-dir 显式指定")
	}

	// 第一轮：已经有凭据的优先，不管它排第几。
	for _, d := range cands {
		if _, err := os.Stat(filepath.Join(d, credentialFile)); err == nil {
			if err := ensureUsable(d); err != nil {
				return "", fmt.Errorf(
					"agent: %q 里已有凭据但目录不可用：%w（不会改用别的目录 —— "+
						"那会重新入网并让既有隧道悬空）", d, err)
			}
			return filepath.Abs(d)
		}
	}
	// 第二轮：第一个能用的。
	var tried []string
	for _, d := range cands {
		if err := ensureUsable(d); err != nil {
			tried = append(tried, fmt.Sprintf("%s（%v）", d, err))
			continue
		}
		return filepath.Abs(d)
	}
	// 逐个列出试过什么、各自为什么不行。只回一句 permission denied
	// 会让人不知道该去修哪个路径的权限。
	return "", fmt.Errorf("agent: 没有可用的状态目录，试过：%s；"+
		"请用 -state-dir 指定一个可写目录", strings.Join(tried, "；"))
}

// stateDirCandidates 给出本平台的候选目录，按优先级。
//
// 不使用相对路径（对比中继的 -data-dir 默认 ./data）：systemd 下
// WorkingDirectory 默认是 /，而 ProtectSystem=strict 让 / 只读 ——
// 要么启动失败，要么状态跟着 CWD 漂移，于是「手工跑一次、再交给 systemd 跑」
// 就变成了两份身份。
func stateDirCandidates() []string {
	var out []string
	add := func(p string) {
		if p != "" {
			out = append(out, p)
		}
	}
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		if pd := os.Getenv("ProgramData"); pd != "" {
			add(filepath.Join(pd, "nomifun", "agent", "state"))
		}
		if la := os.Getenv("LOCALAPPDATA"); la != "" {
			add(filepath.Join(la, "nomifun", "agent", "state"))
		}
	case "darwin":
		add("/Library/Application Support/nomifun/agent")
		if home != "" {
			add(filepath.Join(home, "Library", "Application Support", "nomifun", "agent"))
		}
	default: // linux 与各 BSD
		add("/var/lib/nfagent")
		if x := os.Getenv("XDG_STATE_HOME"); x != "" {
			add(filepath.Join(x, "nfagent"))
		}
		if home != "" {
			add(filepath.Join(home, ".local", "state", "nfagent"))
		}
	}
	return out
}

// ensureUsable 建出目录并确认**真的能写**。
//
// 判据是「建一个临时文件再删掉」，不是看 mode 位：只读挂载、磁盘满、
// inode 用尽都能通过 mode 检查，而在真正要写的那一刻失败 ——
// 而那一刻恰好是**令牌刚被消费掉**的那一刻，是整个流程里最贵的时刻。
// 所以可写性必须在握手之前就证明。
func ensureUsable(dir string) error {
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".writable-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}

// OpenStore 打开状态目录。dir 为空时按平台候选表解析。
func OpenStore(dir string, log *slog.Logger) (*Store, error) {
	resolved, err := ResolveStateDir(dir)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	s := &Store{dir: resolved, log: log}
	s.warnIfVolatile()
	return s, nil
}

// warnIfVolatile 在状态目录落在易失文件系统上时告警。
//
// OpenWrt 的 /var 是指向 /tmp 的**符号链接**（tmpfs），所以默认的
// /var/lib/nfagent 在路由器上重启即清空 —— 修了落盘照样失联，
// 而且更难查：这次日志会说「已持久化」。而 MIPS 路由器是本产品的旗舰目标。
//
// 用 EvalSymlinks 而不是 statfs：后者要按 GOOS 分文件、结构还不一样，
// 而它多抓到的只是「有人把 tmpfs 挂在 /var/lib 上」这种罕见情形。
// 这条盲区如实写在这里，不假装检测得到。
//
// 只告警不拒绝启动：容器里跑一个故意短命的 agent 是正当用法。
func (s *Store) warnIfVolatile() {
	real, err := filepath.EvalSymlinks(s.dir)
	if err != nil {
		return
	}
	for _, v := range []string{"/tmp", "/dev/shm", "/run"} {
		if real == v || strings.HasPrefix(real, v+string(os.PathSeparator)) {
			s.log.Warn("状态目录在易失文件系统上，重启后凭据会丢失、需要重新签发入网令牌",
				"目录", s.dir, "实际路径", real,
				"建议", "OpenWrt 等 /var 指向 tmpfs 的系统请用 -state-dir /etc/nfagent")
			return
		}
	}
}

// Load 读出凭据。文件不存在时返回零值 Credential 且 err 为 nil。
//
// 坏文件会被挪到 .corrupt 并返回零值 —— 调用方据此走首次入网路径。
// 这样做而不是直接报错退出：一个坏了的凭据文件不该让 agent 永远起不来，
// 而带着令牌的启动本来就能自愈。
func (s *Store) Load() (Credential, error) {
	// 机器标识先于凭据解析：**每一条**返回路径都必须带上它。
	//
	// 只在「凭据有效」那条路径上填的话，首次入网（文件不存在）与凭据损坏
	// 两条路径会带着空 machine_id 去握手 —— 而首次入网的 Hello 恰恰是
	// 中继**落库**这个字段的那一次（RedeemEnrolToken 的 INSERT），
	// 后续 TouchAgent 只是刷新。漏了这一次，库里那行就一直是空串，
	// 正好复现要修的 bug。
	mid, err := s.MachineID()
	if err != nil {
		return Credential{}, err
	}

	path := filepath.Join(s.dir, credentialFile)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Credential{MachineID: mid}, nil
	}
	if err != nil {
		// 读不出来（权限、IO 错）与「内容坏了」不同：前者重试可能成功，
		// 不该把文件改名。
		return Credential{}, fmt.Errorf("agent: 读凭据失败：%w", err)
	}

	var doc credentialDoc
	bad := ""
	switch {
	case json.Unmarshal(raw, &doc) != nil:
		bad = "不是合法 JSON"
	case doc.Version != credentialVersion:
		bad = fmt.Sprintf("版本 %d 不是本程序支持的 %d", doc.Version, credentialVersion)
	case doc.AgentID == "" || doc.Key == "":
		bad = "缺 agent_id 或 key"
	default:
		if _, err := hex.DecodeString(doc.Key); err != nil {
			bad = "key 不是合法 hex"
		}
	}
	if bad != "" {
		s.isolateCorrupt(path, bad)
		return Credential{MachineID: mid}, nil
	}

	return Credential{AgentID: doc.AgentID, Key: doc.Key, MachineID: mid}, nil
}

// isolateCorrupt 把坏凭据改名留证。
func (s *Store) isolateCorrupt(path, why string) {
	dst := path + corruptSuffix
	if err := os.Rename(path, dst); err != nil {
		s.log.Error("凭据文件损坏且无法改名保留", "文件", path, "原因", why, "err", err)
		return
	}
	// Error 而不是 Warn：这条意味着这台机器**将要重新入网**（需要一枚新令牌），
	// 而它名下的既有隧道会悬空。运维必须立刻看到。
	s.log.Error("凭据文件损坏，已改名保留；本次将按「未入网」处理，需要一枚新的入网令牌",
		"原因", why, "已挪到", dst)
}

// Save 原子地写入凭据。
//
// # 为什么是临时文件 + fsync + rename + **父目录 fsync**
//
// 前三步保证读者永远看不到半个文件。第四步保证这次 rename 本身在掉电后不会
// 整个丢掉 —— 少了它，ext4/xfs 上会出现「入网成功过、日志也打了，
// 但重启后 credential.json 不存在」的稀有不可复现版，也就是本 bug 的幽灵。
// 而 MIPS 路由器的正常关机方式就是拔电。
func (s *Store) Save(c Credential) error {
	if c.AgentID == "" || c.Key == "" {
		return errors.New("agent: 拒绝写入不完整的凭据（缺 agent_id 或 key）")
	}
	doc := credentialDoc{
		Version: credentialVersion,
		AgentID: c.AgentID,
		Key:     c.Key,
		// 只给人看，不参与判定：本地时钟不可信，拿它做过期判断会在时钟错的
		// 机器上把一份好凭据判死。用 RFC3339 是为了 grep 得动。
		IssuedAt: time.Now().UTC().Format(time.RFC3339),
	}
	blob, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("agent: 编码凭据失败：%w", err)
	}
	return s.atomicWrite(credentialFile, append(blob, '\n'))
}

// atomicWrite 把 data 原子地写成 dir/name。
func (s *Store) atomicWrite(name string, data []byte) error {
	// 用 CreateTemp 而不是固定名 + O_EXCL：固定名在一次崩溃后会留下残留，
	// 于是此后**每一次**落盘都永久 EEXIST —— 正好复现我们要修的那个 bug。
	f, err := os.CreateTemp(s.dir, name+".*.tmp")
	if err != nil {
		return fmt.Errorf("agent: 建临时文件失败：%w", err)
	}
	tmp := f.Name()
	// 失败路径上一定要清掉临时文件，否则状态目录会慢慢长出一堆 .tmp。
	defer func() {
		if tmp != "" {
			_ = os.Remove(tmp)
		}
	}()

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("agent: 写临时文件失败：%w", err)
	}
	// CreateTemp 已经是 0600，但显式设一次：将来有人换成别的建法时
	// 不至于静默把密钥写成 0644。
	if err := f.Chmod(fileMode); err != nil {
		_ = f.Close()
		return fmt.Errorf("agent: 设置文件权限失败：%w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("agent: fsync 临时文件失败：%w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("agent: 关闭临时文件失败：%w", err)
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, name)); err != nil {
		return fmt.Errorf("agent: 重命名到目标失败：%w", err)
	}
	tmp = "" // rename 成功，别再删它
	s.syncDir()
	return nil
}

// syncDir fsync 状态目录，让上一步的 rename 真的落盘。
//
// 失败**不算错误**：Windows 上目录句柄不支持 Sync，而那个平台的 rename
// 语义本身就不依赖它。把它当错误会让每次重连都刷一条内容与事实相反的 ERROR。
func (s *Store) syncDir() {
	d, err := os.Open(s.dir)
	if err != nil {
		return
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		s.log.Debug("fsync 状态目录失败（本平台可能不支持，不影响正确性）", "err", err)
	}
}

// MachineID 返回本机的稳定标识，不存在时生成一个并落盘。
//
// # 为什么是随机数而不是从 /etc/machine-id 派生
//
// 派生看起来更「稳」，实际上三条都不成立：
//
//  1. **它是要外发的。** 这个值走线协议进中继、落进库、进数据库备份。
//     systemd 自己把 /etc/machine-id 定性为应当视作机密（正因如此才提供
//     sd_id128_get_machine_app_specific 让人派生）。而我们能用的派生密钥
//     只能是一个写在源码里的公开常量 —— 那挡不住任何关联分析，
//     只是让人以为挡住了。
//  2. **在我们的目标形态里它恰好不可靠。** OpenWrt 没有 systemd，
//     这个文件根本不存在；容器里它可能缺失、可能是**长度 0 的空文件**
//     （systemd 用它标记「首启待初始化」），最糟的是被烤进镜像 ——
//     那样每个副本报同一个值，而这个字段唯一的用途（区分物理机）
//     就被静默摧毁了。
//  3. **一旦持久化，派生就一分钱都不值。** 派生的唯一收益是「删掉状态目录后
//     仍认得出同一台机器」，而 v1 里这个收益**没有任何消费者**：
//     中继不比对它、控制台的 AgentStatus 没这个字段、支持包也不含它。
//
// MAC 派生同样否掉：换网卡就变，而且它本身能反查厂商。
//
// 读不出来或格式不对时**重新生成并告警**，不报错：它是观测性字段，
// 错了顶多让设备台账多一行；而凭据错了是另一回事（见 Load）。
func (s *Store) MachineID() (string, error) {
	path := filepath.Join(s.dir, machineIDFile)
	raw, err := os.ReadFile(path)
	if err == nil {
		if id := strings.TrimSpace(string(raw)); isMachineID(id) {
			return id, nil
		}
		s.log.Warn("机器标识文件内容不合法，重新生成", "文件", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		s.log.Warn("读机器标识失败，重新生成", "文件", path, "err", err)
	}

	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("agent: 生成机器标识失败：%w", err)
	}
	id := hex.EncodeToString(buf)
	if err := s.atomicWrite(machineIDFile, []byte(id+"\n")); err != nil {
		return "", err
	}
	return id, nil
}

// isMachineID 判断一个字符串是不是本程序写出的机器标识。
//
// 32 位小写 hex。刻意不接受带横线的 UUID 写法：只允许一种形态，
// 就不会出现「同一台机器在两处显示成两个不同的字符串」。
func isMachineID(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}
