package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
)

// ── 管理员与密码 ────────────────────────────────────────────────────────────

// argon2 参数。
//
// m=64MiB, t=3, p=2 是 OWASP 当前推荐的下限档。参数编码进 PHC 串，
// 所以将来调强度不需要迁移 —— 旧哈希仍能用它自己记录的参数校验。
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// argon2 的并发闸。
//
// # 为什么必须有它
//
// 每一次密码校验分配 argonMemory（64 MiB）。而 POST /api/login 与
// POST /api/setup 都是**未鉴权**端点 —— 任何人都能让中继做这件事，
// 而且**用一个不存在的用户名也算**（等时处理会照样跑一次假校验，见 dummyHash）。
// 没有这道闸时并发数就是放大倍数：一百个并发请求 = 6.4 GiB，
// 中继被 OOM 杀掉，而它名下**所有隧道同时断掉**。
//
// 也就是说这不是「登录慢一点」的问题，是一个匿名请求就能打掉整台中继的
// 资源耗尽面。实测过：连打错密码零退避、耗时恒 ~42ms。
//
// # 为什么闸开在这里，而不是包住 VerifyAdmin
//
// VerifyAdmin 成功路径上有一次 SQL 写（UPDATE last_login_at），走的是
// 存储层那条**唯一的**写连接。把闸包在外面就意味着「持有 argon2 槽位时
// 去抢写连接」，两个稀缺资源嵌套获取 —— 那是教科书式的死锁形状。
// 所以闸只包住真正分配那 64 MiB 的一行。
//
// # 为什么用 defer 释放而不是自己记账
//
// 任何「计数器 +1 / -1」的写法都有一条出口会被漏掉（早返回、panic），
// 而漏掉的后果是槽位永久泄漏 → 管理面**永久** 503，连正确口令也进不来。
// defer 让这件事在结构上不可能发生。
const (
	// argonConcurrency 是同时允许几次 argon2 计算。
	//
	// 2 而不是 GOMAXPROCS：内存是这里的稀缺资源，不是 CPU。
	// 峰值内存 = 2 × 64 MiB = 128 MiB，一台 512 MiB 的小机器扛得住，
	// 而这个上界现在是**有断言的**（见 TestArgon2ConcurrencyIsBounded）。
	argonConcurrency = 2
)

// argonWaitForTest 是等一个槽位的上限。
//
// 超时返回错误而不是无限等：无限等会把请求 goroutine 堆到内存耗尽，
// 只是把 OOM 从 argon2 挪到了 goroutine 栈上。
// 5 秒远大于正常校验耗时（~40ms），正常用户永远碰不到它。
//
// 是变量而不是常量**只为了测试能缩短它** —— 否则「闸满时返回 ErrHashBusy」
// 那条判据每跑一次要等 5 秒，而一条要等 5 秒的测试迟早会被人删掉。
// 生产路径上没有任何地方改它。
var argonWaitForTest = 5 * time.Second

var argonGate = make(chan struct{}, argonConcurrency)

// ErrHashBusy 表示密码哈希计算排不上队。
//
// **必须与「密码错」区分开**：混在一起的话，一次洪水期间正常用户会看到
// 「用户名或密码错误」，于是去查密码（查错方向），而上层的限速器还会把这次
// 失败记到他头上。调用方应当映射成 503 + Retry-After，而不是 401。
var ErrHashBusy = errors.New("store: 密码哈希计算繁忙，请稍后重试")

// withArgonSlot 拿一个 argon2 槽位跑 fn。
func withArgonSlot(fn func()) error {
	timer := time.NewTimer(argonWaitForTest)
	defer timer.Stop()

	select {
	case argonGate <- struct{}{}:
		defer func() { <-argonGate }()
		fn()
		return nil
	case <-timer.C:
		return ErrHashBusy
	}
}

// HasAdmin 报告是否已完成首启设置。
//
// 控制台据此决定「把任何请求都导向 /setup」还是正常提供服务。
func (d *DB) HasAdmin(ctx context.Context) bool {
	var n int
	err := d.read.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&n)
	return err == nil && n > 0
}

// CreateAdmin 创建管理员。mustRotate 为 true 时强制首次登录改密。
func (d *DB) CreateAdmin(ctx context.Context, username, password string, mustRotate bool) error {
	if username == "" || password == "" {
		// 空凭据是 frp 那个「监听 0.0.0.0 的无鉴权控制台」漏洞的根源
		//（pkg/util/net/http.go:48 在双空时放行一切）。这里从存储层就拒绝。
		return errors.New("store: 管理员用户名与密码都不能为空")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	rotate := 0
	if mustRotate {
		rotate = 1
	}
	_, err = d.write.ExecContext(ctx,
		`INSERT INTO admins (username, password_hash, must_rotate, created_at) VALUES (?,?,?,?)`,
		username, hash, rotate, now())
	if err != nil {
		return classifyConstraint(err)
	}
	return nil
}

// VerifyAdmin 校验管理员口令。
//
// 三个返回值而不是两个：**「繁忙」必须与「密码错」分开**。合成一个 bool 的话，
// 一次洪水期间正常用户会看到「用户名或密码错误」→ 去查密码（查错方向），
// 而上层限速器还会把这次失败记到他头上。err 非 nil 时 ok 无意义。
func (d *DB) VerifyAdmin(
	ctx context.Context, username, password string,
) (mustRotate bool, ok bool, err error) {
	var (
		hash   string
		rotate int
	)
	qerr := d.read.QueryRowContext(ctx,
		`SELECT password_hash, must_rotate FROM admins WHERE username = ?`, username).
		Scan(&hash, &rotate)
	if qerr != nil {
		// 用户不存在时也要走一次假校验，让耗时与真实校验相当，
		// 否则响应时间会泄露「这个用户名存在吗」。
		//
		// 这条假校验**也要过闸**（它同样分配 64 MiB）—— 那正是「用不存在的
		// 用户名也能驱动内存放大」这条攻击路径。繁忙时如实上报，
		// 否则攻击者能靠「繁忙时返回得快」重新把等时性拆开。
		if _, verr := VerifyPassword(dummyHash, password); errors.Is(verr, ErrHashBusy) {
			return false, false, verr
		}
		return false, false, nil
	}
	valid, verr := VerifyPassword(hash, password)
	if errors.Is(verr, ErrHashBusy) {
		return false, false, verr
	}
	if verr != nil || !valid {
		return false, false, nil
	}
	_, _ = d.write.ExecContext(ctx,
		`UPDATE admins SET last_login_at = ? WHERE username = ?`, now(), username)
	return rotate == 1, true, nil
}

// dummyHash 是一个真实形状的哈希，用于用户不存在时的等时校验。
var dummyHash = func() string {
	h, _ := HashPassword("dummy-password-for-timing-equalisation")
	return h
}()

// SetAdminPassword 改密并清除强制改密标记。
func (d *DB) SetAdminPassword(ctx context.Context, username, password string) error {
	if password == "" {
		return errors.New("store: 密码不能为空")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	res, err := d.write.ExecContext(ctx,
		`UPDATE admins SET password_hash = ?, must_rotate = 0 WHERE username = ?`, hash, username)
	if err != nil {
		return fmt.Errorf("store: 更新密码失败：%w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// HashPassword 用 argon2id 生成 PHC 格式的密码哈希。
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("store: 生成盐失败：%w", err)
	}
	var key []byte
	if err := withArgonSlot(func() {
		key = argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	}); err != nil {
		return "", err
	}
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		hex.EncodeToString(salt), hex.EncodeToString(key)), nil
}

// VerifyPassword 用哈希串里记录的参数校验密码。
//
// 从串里读参数而不是用当前常量：这样调高强度之后，旧哈希仍然可校验，
// 不需要一次性把所有用户锁在门外。
func VerifyPassword(phc, password string) (bool, error) {
	var (
		mem, tm uint32
		par     uint8
		saltHex string
		keyHex  string
	)
	n, err := fmt.Sscanf(phc, "$argon2id$v=19$m=%d,t=%d,p=%d$%64s$%64s",
		&mem, &tm, &par, &saltHex, &keyHex)
	if err != nil || n != 5 {
		// 盐与密钥长度可变时上面的 %64s 会失配，改用分段解析。
		parts := splitPHC(phc)
		if parts == nil {
			return false, errors.New("store: 密码哈希格式非法")
		}
		mem, tm, par, saltHex, keyHex = parts.mem, parts.time, parts.par, parts.salt, parts.key
	}

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false, errors.New("store: 密码哈希的盐非法")
	}
	want, err := hex.DecodeString(keyHex)
	if err != nil {
		return false, errors.New("store: 密码哈希的密钥非法")
	}
	var got []byte
	if err := withArgonSlot(func() {
		got = argon2.IDKey([]byte(password), salt, tm, mem, par, uint32(len(want)))
	}); err != nil {
		// 繁忙**不是**「密码错」。原样往上传，让调用方回 503 而不是 401。
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

type phcParts struct {
	mem, time uint32
	par       uint8
	salt, key string
}

func splitPHC(phc string) *phcParts {
	// 形如 $argon2id$v=19$m=65536,t=3,p=2$<saltHex>$<keyHex>
	var fields []string
	start := 0
	for i := 0; i <= len(phc); i++ {
		if i == len(phc) || phc[i] == '$' {
			if i > start {
				fields = append(fields, phc[start:i])
			}
			start = i + 1
		}
	}
	if len(fields) != 5 || fields[0] != "argon2id" {
		return nil
	}
	var p phcParts
	if _, err := fmt.Sscanf(fields[2], "m=%d,t=%d,p=%d", &p.mem, &p.time, &p.par); err != nil {
		return nil
	}
	p.salt, p.key = fields[3], fields[4]
	return &p
}

// ── 会话 ────────────────────────────────────────────────────────────────────

// CreateSession 创建一个控制台会话，返回明文 token 与 CSRF token。
//
// 库里只存 token 的 SHA-256：数据库泄露时不能直接拿去冒充登录。
func (d *DB) CreateSession(ctx context.Context, username string, ttl time.Duration) (token, csrf string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("store: 生成会话令牌失败：%w", err)
	}
	token = hex.EncodeToString(raw)

	craw := make([]byte, 32)
	if _, err := rand.Read(craw); err != nil {
		return "", "", fmt.Errorf("store: 生成 CSRF 令牌失败：%w", err)
	}
	csrf = hex.EncodeToString(craw)

	sum := sha256.Sum256([]byte(token))
	ts := now()
	_, err = d.write.ExecContext(ctx, `
		INSERT INTO console_sessions (id, username, created_at, expires_at, csrf_token)
		VALUES (?,?,?,?,?)`,
		hex.EncodeToString(sum[:]), username, ts, ts+int64(ttl.Seconds()), csrf)
	if err != nil {
		return "", "", fmt.Errorf("store: 保存会话失败：%w", err)
	}
	return token, csrf, nil
}

// LookupSession 按 token 哈希查会话。过期会话视为不存在。
func (d *DB) LookupSession(ctx context.Context, idHash string) (username, csrf string, ok bool) {
	var expires int64
	err := d.read.QueryRowContext(ctx,
		`SELECT username, csrf_token, expires_at FROM console_sessions WHERE id = ?`, idHash).
		Scan(&username, &csrf, &expires)
	if errors.Is(err, sql.ErrNoRows) || err != nil {
		return "", "", false
	}
	if now() > expires {
		return "", "", false
	}
	return username, csrf, true
}

// DeleteSession 删除一个会话（登出）。
func (d *DB) DeleteSession(ctx context.Context, idHash string) error {
	_, err := d.write.ExecContext(ctx, `DELETE FROM console_sessions WHERE id = ?`, idHash)
	if err != nil {
		return fmt.Errorf("store: 删除会话失败：%w", err)
	}
	return nil
}

// PruneSessions 清理过期会话，返回删除条数。
func (d *DB) PruneSessions(ctx context.Context) (int64, error) {
	res, err := d.write.ExecContext(ctx,
		`DELETE FROM console_sessions WHERE expires_at < ?`, now())
	if err != nil {
		return 0, fmt.Errorf("store: 清理会话失败：%w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
