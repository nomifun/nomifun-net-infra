package proto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"
)

func newNonce(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func signedProof(t *testing.T, key []byte, ts time.Time, exporter []byte) *Proof {
	t.Helper()
	p := &Proof{UnixMilli: ts.UnixMilli(), Nonce: newNonce(t)}
	p.Sign(key, 1, ALPN, exporter)
	return p
}

// TestProofRoundTrip 验证正常握手能通过。
func TestProofRoundTrip(t *testing.T) {
	key := []byte("agent-key-32-bytes-长度无所谓")
	exporter := []byte("tls-exporter-material")
	now := time.Now()

	p := signedProof(t, key, now, exporter)
	if err := p.Verify(key, 1, ALPN, exporter, now); err != nil {
		t.Fatalf("正常证明应当通过：%v", err)
	}
}

// TestProofIsChannelBound 是本文件最重要的测试。
//
// 它证明：即使在时钟偏移允许的窗口内，把一个合法证明重放到**另一条 TLS 会话**上
// 也会失败，因为 exporter 不同。frp 完全没有这一层 —— 它的证明不绑定信道，
// 中间人终止 TLS 后拿走 PrivilegeKey 就能冒充受害者注册
// （frp 默认 InsecureSkipVerify=true，pkg/transport/tls.go:150-152，使这一步毫无门槛）。
func TestProofIsChannelBound(t *testing.T) {
	key := []byte("agent-key")
	now := time.Now()

	sessionA := []byte("exporter-of-tls-session-A")
	sessionB := []byte("exporter-of-tls-session-B")

	p := signedProof(t, key, now, sessionA)

	// 在原会话上有效。
	if err := p.Verify(key, 1, ALPN, sessionA, now); err != nil {
		t.Fatalf("原会话应当通过：%v", err)
	}
	// 换一条会话立刻失效 —— 这就是信道绑定。
	if err := p.Verify(key, 1, ALPN, sessionB, now); !errors.Is(err, ErrProofBadMAC) {
		t.Fatalf("跨会话重放必须失败，得到 %v", err)
	}
}

// TestProofRejectsStaleTimestamp 验证时钟偏移检查存在。
//
// frp 把 Timestamp 发上来却**从不校验**（全仓无时钟偏移检查），
// 这正是「抓一对凭据可永久重放」的根因。
func TestProofRejectsStaleTimestamp(t *testing.T) {
	key := []byte("k")
	exporter := []byte("e")
	signedAt := time.Now()
	p := signedProof(t, key, signedAt, exporter)

	for _, tc := range []struct {
		name string
		at   time.Time
		ok   bool
	}{
		{"窗口内", signedAt.Add(MaxClockSkew - time.Second), true},
		{"窗口边缘外", signedAt.Add(MaxClockSkew + time.Second), false},
		{"远期重放", signedAt.Add(24 * time.Hour), false},
		{"时钟倒流但在窗口内", signedAt.Add(-(MaxClockSkew - time.Second)), true},
		{"时钟倒流超窗口", signedAt.Add(-(MaxClockSkew + time.Second)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := p.Verify(key, 1, ALPN, exporter, tc.at)
			if tc.ok && err != nil {
				t.Fatalf("应当通过，得到 %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrProofStale) {
				t.Fatalf("应当返回 ErrProofStale，得到 %v", err)
			}
		})
	}
}

// TestProofRejectsWrongKeyAndTamperedFields 确认 MAC 覆盖了所有关键字段。
func TestProofRejectsWrongKeyAndTamperedFields(t *testing.T) {
	key := []byte("right-key")
	exporter := []byte("e")
	now := time.Now()
	p := signedProof(t, key, now, exporter)

	t.Run("错误密钥", func(t *testing.T) {
		if err := p.Verify([]byte("wrong-key"), 1, ALPN, exporter, now); !errors.Is(err, ErrProofBadMAC) {
			t.Fatalf("得到 %v", err)
		}
	})
	t.Run("篡改时间戳", func(t *testing.T) {
		tampered := *p
		tampered.UnixMilli = now.Add(time.Second).UnixMilli()
		// 仍在时钟窗口内，所以只能靠 MAC 抓出来。
		if err := tampered.Verify(key, 1, ALPN, exporter, now); !errors.Is(err, ErrProofBadMAC) {
			t.Fatalf("时间戳必须被 MAC 覆盖，得到 %v", err)
		}
	})
	t.Run("篡改 nonce", func(t *testing.T) {
		tampered := *p
		tampered.Nonce = newNonce(t)
		if err := tampered.Verify(key, 1, ALPN, exporter, now); !errors.Is(err, ErrProofBadMAC) {
			t.Fatalf("nonce 必须被 MAC 覆盖，得到 %v", err)
		}
	})
	t.Run("篡改协议版本", func(t *testing.T) {
		if err := p.Verify(key, 2, ALPN, exporter, now); !errors.Is(err, ErrProofBadMAC) {
			t.Fatalf("协议版本必须被 MAC 覆盖，得到 %v", err)
		}
	})
	t.Run("篡改 ALPN", func(t *testing.T) {
		if err := p.Verify(key, 1, "other/1", exporter, now); !errors.Is(err, ErrProofBadMAC) {
			t.Fatalf("ALPN 必须被 MAC 覆盖，得到 %v", err)
		}
	})
}

// TestProofRejectsMalformedNonce 确认 nonce 长度被强制，
// 避免调用方误用短 nonce 削弱防重放。
func TestProofRejectsMalformedNonce(t *testing.T) {
	key := []byte("k")
	for _, n := range []string{"", "zz", "abcd", hex.EncodeToString(make([]byte, 8)), "not-hex-at-all!!"} {
		p := &Proof{UnixMilli: time.Now().UnixMilli(), Nonce: n}
		p.Sign(key, 1, ALPN, nil)
		if err := p.Verify(key, 1, ALPN, nil, time.Now()); !errors.Is(err, ErrProofBadNonce) {
			t.Errorf("nonce=%q 应当被拒为 ErrProofBadNonce，得到 %v", n, err)
		}
	}
}

func TestProofNilIsRejected(t *testing.T) {
	var p *Proof
	if err := p.Verify([]byte("k"), 1, ALPN, nil, time.Now()); !errors.Is(err, ErrProofMissing) {
		t.Fatalf("得到 %v", err)
	}
}

// TestProofCanonicalIsUnambiguous 验证规范串用长度前缀，
// 不会因为字段内容包含分隔符而产生歧义。
//
// 若用 "a|b" 这种分隔符拼接，(nonce="a|b", alpn="c") 与 (nonce="a", alpn="b|c")
// 会产生相同的字节串，从而让 MAC 无法区分两种不同的输入。
func TestProofCanonicalIsUnambiguous(t *testing.T) {
	// 构造两组会在朴素拼接下撞车的输入。
	a := ProofCanonical(1, 0, "aa", "bb", nil)
	b := ProofCanonical(1, 0, "a", "abb", nil)
	if string(a) == string(b) {
		t.Fatal("规范串出现歧义：不同字段切分产生了相同字节串")
	}

	// exporter 也必须参与长度前缀。
	c := ProofCanonical(1, 0, "n", "x", []byte("yz"))
	d := ProofCanonical(1, 0, "n", "xy", []byte("z"))
	if string(c) == string(d) {
		t.Fatal("规范串在 alpn/exporter 边界上出现歧义")
	}
}

// ── ReplayGuard ────────────────────────────────────────────────────────────

// TestReplayGuardRejectsSecondUse 是重放防护的核心断言。
func TestReplayGuardRejectsSecondUse(t *testing.T) {
	g := NewReplayGuard(100, time.Minute)
	n := newNonce(t)

	if !g.Check("agent-1", n) {
		t.Fatal("首次使用应当被接受")
	}
	if g.Check("agent-1", n) {
		t.Fatal("同一 nonce 第二次使用必须被拒 —— 这正是 frp 缺失的那一层")
	}
}

// TestReplayGuardIsPerAgent 确认 nonce 空间按 agent 隔离。
//
// 若全局分键，攻击者可以预先灌入大量 nonce，去碰撞受害者将来生成的值，
// 造成受害者握手被拒的拒绝服务。
func TestReplayGuardIsPerAgent(t *testing.T) {
	g := NewReplayGuard(100, time.Minute)
	n := newNonce(t)

	if !g.Check("agent-1", n) {
		t.Fatal("agent-1 首次应当通过")
	}
	if !g.Check("agent-2", n) {
		t.Fatal("同一 nonce 对不同 agent 应当独立计算")
	}
}

// TestReplayGuardExpiresEntries 确认 TTL 生效，账本不会无限增长。
func TestReplayGuardExpiresEntries(t *testing.T) {
	base := time.Now()
	cur := base
	g := NewReplayGuard(100, time.Minute)
	g.now = func() time.Time { return cur }

	n := newNonce(t)
	if !g.Check("a", n) {
		t.Fatal("首次应当通过")
	}
	if g.Check("a", n) {
		t.Fatal("窗口内重放应当被拒")
	}

	// 推进到 TTL 之后。
	cur = base.Add(time.Minute + time.Second)
	if !g.Check("a", n) {
		t.Fatal("TTL 过后条目应当已被清理")
	}
	// 注意：这在安全上是可接受的，因为这样的时间戳已经会被
	// Proof.Verify 以 ErrProofStale 拒掉（TTL = 2 × MaxClockSkew）。
}

// TestReplayGuardIsBounded 确认容量上限被强制执行 ——
// 账本本身不能成为内存耗尽攻击面。
func TestReplayGuardIsBounded(t *testing.T) {
	const cap = 64
	g := NewReplayGuard(cap, time.Hour)

	for i := 0; i < cap*10; i++ {
		if !g.Check("a", "nonce-"+strconv.Itoa(i)) {
			t.Fatalf("第 %d 个不同 nonce 应当被接受", i)
		}
	}
	if got := g.Len(); got > cap {
		t.Fatalf("账本长度 %d 超过容量上限 %d —— 无界账本就是 DoS 面", got, cap)
	}
}

// TestReplayGuardDoesNotRefreshOnReplay 确认重复命中不刷新 TTL。
//
// 否则攻击者可以靠反复重放把一个条目永久钉在账本里，挤占有限容量，
// 从而把别人的合法 nonce 挤出去。
func TestReplayGuardDoesNotRefreshOnReplay(t *testing.T) {
	base := time.Now()
	cur := base
	g := NewReplayGuard(10, time.Minute)
	g.now = func() time.Time { return cur }

	n := newNonce(t)
	g.Check("a", n)

	// 在 TTL 内反复重放。
	for i := 0; i < 5; i++ {
		cur = base.Add(time.Duration(i*10) * time.Second)
		if g.Check("a", n) {
			t.Fatalf("第 %d 次重放不该通过", i)
		}
	}

	// 从**首次登记**起算的 TTL 之后就该过期，而不是从最后一次重放起算。
	cur = base.Add(time.Minute + time.Second)
	if !g.Check("a", n) {
		t.Fatal("重放不应刷新 TTL，条目本该已过期")
	}
}

func TestReplayGuardConcurrent(t *testing.T) {
	g := NewReplayGuard(4096, time.Minute)
	const workers = 16
	const each = 100

	done := make(chan struct{})
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < each; i++ {
				key := "w" + strconv.Itoa(w) + "-" + strconv.Itoa(i)
				if !g.Check("agent", key) {
					t.Errorf("唯一 nonce %s 被误判为重放", key)
					return
				}
			}
		}(w)
	}
	for w := 0; w < workers; w++ {
		<-done
	}
}

// ── 能力协商 ────────────────────────────────────────────────────────────────

func TestNegotiateCapabilities(t *testing.T) {
	for _, tc := range []struct {
		name   string
		local  []Capability
		remote []Capability
		want   []Capability
	}{
		{
			name:   "取交集",
			local:  []Capability{CapDatagram, CapUDPCookie, CapSNIRoute},
			remote: []Capability{CapUDPCookie, CapSNIRoute, CapPeerTunnel},
			want:   []Capability{CapSNIRoute, CapUDPCookie},
		},
		{
			name:   "新端遇旧端应降级而非失败",
			local:  []Capability{CapDatagram, CapUDPCookie, CapPeerTunnel, CapHandlerBackend},
			remote: []Capability{CapDatagram},
			want:   []Capability{CapDatagram},
		},
		{
			name:   "无交集",
			local:  []Capability{CapPeerTunnel},
			remote: []Capability{CapDatagram},
			want:   []Capability{},
		},
		{
			name:   "本端重复项不应产生重复输出",
			local:  []Capability{CapDatagram, CapDatagram},
			remote: []Capability{CapDatagram},
			want:   []Capability{CapDatagram},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := NegotiateCapabilities(tc.local, tc.remote)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v，want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v，want %v（结果必须排序以保证确定性）", got, tc.want)
				}
			}
		})
	}
}

// TestScenario3CapabilitiesAreReserved 守护场景三的前向兼容接缝。
//
// 场景三暂缓，但能力标记必须**现在**就存在于常量表里：
// 能力集事后加不破坏线协议，而如果连常量都没定义，
// 将来实现时很容易改成别的拼写，造成新旧端互不识别。
func TestScenario3CapabilitiesAreReserved(t *testing.T) {
	if CapPeerTunnel != "tunnel.peer" {
		t.Errorf("CapPeerTunnel 的线上拼写被改了：%q —— 这会破坏与将来实现的互操作", CapPeerTunnel)
	}
	if CapHandlerBackend != "backend.handler" {
		t.Errorf("CapHandlerBackend 的线上拼写被改了：%q", CapHandlerBackend)
	}
	// v1 的 agent 不应声明这两个能力（还没实现）。
	for _, c := range AgentCapabilities() {
		if c == CapPeerTunnel || c == CapHandlerBackend {
			t.Errorf("v1 agent 不应声明未实现的能力 %q", c)
		}
	}
}
