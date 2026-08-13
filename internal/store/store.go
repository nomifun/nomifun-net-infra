// Package store 是 nfrelay 的 SQLite 持久化层。
//
// # 为什么是 modernc.org/sqlite
//
// 纯 Go、无需 CGO，这是「单静态二进制、全平台交叉编译」这个产品承诺的前提。
// 用 mattn/go-sqlite3（CGO）会让承诺当场失效。
//
// 代价是它**没有 MIPS 移植**（支持列表为 linux 386/amd64/arm/arm64/loong64/
// ppc64le/riscv64/s390x + darwin/windows/freebsd/openbsd），所以 MIPS 路由器
// 只能构建不含存储的 nfagent —— 这正是本项目出两个二进制而不是一个带子命令的原因。
// `make check` 会用 go list -deps 断言 agent 不依赖本包。
//
// # 关键取舍
//
// 一个写句柄（SetMaxOpenConns(1)）+ 一个读池。SQLite 的写是全库串行的，
// 与其让并发写去撞 SQLITE_BUSY 再靠 busy_timeout 重试，不如在连接池层面
// 就把写序列化掉 —— 这样 SQLITE_BUSY 从一类需要处理的运行时错误
// 变成了不可能发生的状态。
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite" // 注册 "sqlite" 驱动（注意：不是 "sqlite3"）
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB 是存储层句柄。
type DB struct {
	// write 是唯一的写连接。见包注释里关于 SQLITE_BUSY 的说明。
	write *sql.DB
	// read 是读连接池。
	read *sql.DB

	path string
	log  *slog.Logger
}

// Options 是打开数据库的参数。
type Options struct {
	// Path 是数据库文件路径。":memory:" 用于测试。
	Path string

	// ReadPoolSize 是读连接数上限。<=0 时用 DefaultReadPoolSize。
	ReadPoolSize int

	Log *slog.Logger
}

// DefaultReadPoolSize 是默认读连接数。
const DefaultReadPoolSize = 4

// dsnParams 是打开数据库时应用的 pragma。
//
// 顺序不由我们控制（驱动会按固定顺序应用，见其文档），但取值必须显式给全：
//   - WAL：读写不互斥，控制台读不会被后台 rollup 的写卡住。
//   - synchronous=NORMAL：WAL 下这是公认的安全/性能折中点。
//   - busy_timeout：即使我们已经把写串行化，附加连接（如迁移）仍可能短暂竞争。
//   - foreign_keys：SQLite 默认**关闭**外键，必须显式打开，否则约束形同注释。
const dsnParams = "?_pragma=journal_mode(WAL)" +
	"&_pragma=synchronous(NORMAL)" +
	"&_pragma=busy_timeout(5000)" +
	"&_pragma=foreign_keys(1)"

// Open 打开（必要时创建）数据库并跑完迁移。
func Open(opts Options) (*DB, error) {
	if opts.Path == "" {
		return nil, errors.New("store: Options.Path 不能为空")
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	poolSize := opts.ReadPoolSize
	if poolSize <= 0 {
		poolSize = DefaultReadPoolSize
	}

	inMemory := opts.Path == ":memory:"
	dsn := opts.Path + dsnParams
	if inMemory {
		// 共享缓存的内存库，使写句柄与读池看到同一个数据库。
		// 不加 cache=shared 的话两个 sql.DB 会各自开一个独立的空库，
		// 测试会表现为「写进去了但读不到」这种极难查的症状。
		dsn = "file::memory:?cache=shared" + dsnParams[1:]
	} else {
		if err := os.MkdirAll(filepath.Dir(opts.Path), 0o700); err != nil {
			return nil, fmt.Errorf("store: 创建数据目录失败：%w", err)
		}
	}

	write, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: 打开写连接失败：%w", err)
	}
	// 写串行化。这一行把 SQLITE_BUSY 从一类 bug 变成不可能。
	write.SetMaxOpenConns(1)
	write.SetMaxIdleConns(1)
	// 连接不设最大生命周期：SQLite 是本地文件，重建连接没有收益，
	// 而对内存库来说关掉最后一个连接会**丢库**。
	write.SetConnMaxLifetime(0)

	if err := write.Ping(); err != nil {
		write.Close()
		return nil, fmt.Errorf("store: 连接数据库失败：%w", err)
	}

	read, err := sql.Open("sqlite", dsn)
	if err != nil {
		write.Close()
		return nil, fmt.Errorf("store: 打开读连接池失败：%w", err)
	}
	read.SetMaxOpenConns(poolSize)
	read.SetMaxIdleConns(poolSize)
	read.SetConnMaxLifetime(0)

	db := &DB{write: write, read: read, path: opts.Path, log: log}

	if err := db.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// migrate 跑 embed 进来的 SQL 迁移。
//
// 迁移只前滚、幂等。goose 会在 goose_db_version 表里记录已应用的版本。
func (d *DB) migrate() error {
	goose.SetBaseFS(migrationsFS)
	goose.SetLogger(goose.NopLogger()) // 我们自己用 slog 记，不要它往 stdout 打
	if err := goose.SetDialect("sqlite3"); err != nil {
		return fmt.Errorf("store: 设置 goose 方言失败：%w", err)
	}

	before, _ := goose.GetDBVersion(d.write)
	if err := goose.Up(d.write, "migrations"); err != nil {
		return fmt.Errorf("store: 迁移失败：%w", err)
	}
	after, err := goose.GetDBVersion(d.write)
	if err != nil {
		return fmt.Errorf("store: 读取迁移版本失败：%w", err)
	}
	if after != before {
		d.log.Info("数据库迁移完成", "从", before, "到", after)
	}
	return nil
}

// SchemaVersion 返回当前 schema 版本，用于备份恢复时的兼容判断。
func (d *DB) SchemaVersion() (int64, error) {
	return goose.GetDBVersion(d.write)
}

// Close 关闭两个连接。
func (d *DB) Close() error {
	var errs []error
	if err := d.read.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := d.write.Close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Backup 用 VACUUM INTO 做一致热快照，不需要停服。
//
// 相比直接拷文件：VACUUM INTO 保证快照是事务一致的，
// 而拷一个正在写的 WAL 数据库会得到损坏或半新半旧的结果。
func (d *DB) Backup(ctx context.Context, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return fmt.Errorf("store: 创建备份目录失败：%w", err)
	}
	// VACUUM INTO 要求目标文件不存在。
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("store: 备份目标 %s 已存在", dest)
	}
	// 目标路径无法参数化（SQLite 的 VACUUM INTO 只接受字面量），
	// 所以必须自己转义单引号防注入。
	if _, err := d.write.ExecContext(ctx, `VACUUM INTO '`+escapeSQLLiteral(dest)+`'`); err != nil {
		return fmt.Errorf("store: 备份失败：%w", err)
	}
	return nil
}

// escapeSQLLiteral 转义 SQL 字符串字面量里的单引号。
func escapeSQLLiteral(s string) string {
	out := make([]byte, 0, len(s)+8)
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'', '\'')
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

// 存储层错误。
var (
	// ErrNotFound 对应 HTTP 404。
	ErrNotFound = errors.New("store: 记录不存在")
	// ErrConflict 对应 HTTP 409（slug 重复、端口冲突）。
	ErrConflict = errors.New("store: 记录冲突")
	// ErrTokenUsed 表示入网令牌已被使用。
	ErrTokenUsed = errors.New("store: 入网令牌已被使用")
	// ErrTokenExpired 表示入网令牌已过期。
	ErrTokenExpired = errors.New("store: 入网令牌已过期")
)

// now 返回当前 unix 秒。抽出来便于测试注入。
var now = func() int64 { return time.Now().Unix() }
