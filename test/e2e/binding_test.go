//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/agent"
	"github.com/nomifun/nomifun-net-infra/internal/carrier"
	"github.com/nomifun/nomifun-net-infra/internal/proto"
	"github.com/nomifun/nomifun-net-infra/internal/relay"
)

// bindingRig 是一台只做握手的中继：一个监听器 + 一份共享的鉴权后端。
//
// 不复用 setup() 的 harness：那套夹具只接**一条**连接（UDP 数据面需要
// 那个唯一的承载句柄），而这里要的恰恰是「同一个 agent 身份、多条连接」。
type bindingRig struct {
	t    *testing.T
	ln   *carrier.QUICListener
	auth *memAuth
	// guard 在整台中继上共享，与生产一致 —— 否则「换条连接就换个 guard」
	// 会让重放守卫在测试里形同不存在。
	guard     *proto.ReplayGuard
	clientCfg *tls.Config
	log       *slog.Logger
	ctx       context.Context
	wg        sync.WaitGroup
	accepts   chan acceptResult
}

// acceptResult 是中继侧一次接入的结果。
type acceptResult struct {
	outcome *relay.HandshakeOutcome
	binding []byte
	err     error
}

// newBindingRig 起监听器并在后台不停地接入 + 握手。
func newBindingRig(t *testing.T) *bindingRig {
	t.Helper()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx, cancel := context.WithCancel(context.Background())

	cert, leaf := selfSigned(t)
	ln, err := carrier.ListenQUIC("127.0.0.1:0", carrier.QUICConfig{
		TLSConfig: carrier.ServerTLSConfig(cert),
		Rung:      carrier.RungQUIC,
	})
	if err != nil {
		t.Fatal(err)
	}

	clientCfg, err := carrier.ClientTLSConfig("e2e-relay", nil, carrier.SPKIPin(leaf))
	if err != nil {
		t.Fatal(err)
	}

	r := &bindingRig{
		t:       t,
		ln:      ln,
		auth:    newMemAuth(),
		guard:   proto.NewReplayGuard(0, 0),
		log:     log,
		ctx:     ctx,
		accepts: make(chan acceptResult, 8),
	}
	r.clientCfg = clientCfg

	t.Cleanup(func() {
		cancel()
		ln.Close()
		r.wg.Wait()
	})

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		for {
			c, err := ln.Accept(ctx)
			if err != nil {
				return // ctx 取消或监听器关闭
			}
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				r.serveOne(ctx, c)
			}()
		}
	}()
	return r
}

// serveOne 在一条新承载上完成中继侧握手，并把结果送出去。
//
// **绑定材料从承载自己身上取**，与 cmd/nfrelay 完全同形 ——
// 这条测试的全部意义在于验证生产路径上的那次取值与 agent 侧一致。
func (r *bindingRig) serveOne(ctx context.Context, c carrier.Carrier) {
	st, err := c.AcceptStream(ctx)
	if err != nil {
		return
	}
	binding, err := c.ChannelBinding()
	if err != nil {
		r.accepts <- acceptResult{err: fmt.Errorf("中继侧取绑定材料失败：%w", err)}
		return
	}
	out, err := relay.Handshake(st, binding, relay.HandshakeConfig{
		Auth:               r.auth,
		Guard:              r.guard,
		RelayVersion:       "e2e-binding",
		MinProtocolVersion: 1,
		Log:                r.log,
	})
	r.accepts <- acceptResult{outcome: out, binding: binding, err: err}
}

// dial 拨一条新承载并开出控制流。
func (r *bindingRig) dial() (carrier.Carrier, carrier.Stream, []byte) {
	r.t.Helper()

	ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
	defer cancel()

	c, err := carrier.DialQUIC(ctx, r.ln.Addr().String(), carrier.QUICConfig{
		TLSConfig: r.clientCfg,
		Rung:      carrier.RungQUIC,
	})
	if err != nil {
		r.t.Fatalf("拨号失败：%v", err)
	}
	r.t.Cleanup(func() { c.CloseWithError(0, "测试结束") })

	st, err := c.OpenStream(ctx)
	if err != nil {
		r.t.Fatalf("开控制流失败：%v", err)
	}
	binding, err := c.ChannelBinding()
	if err != nil {
		r.t.Fatalf("agent 侧取绑定材料失败：%v", err)
	}
	return c, st, binding
}

// relayResult 等中继侧那一次握手的结果。
func (r *bindingRig) relayResult() acceptResult {
	r.t.Helper()
	select {
	case got := <-r.accepts:
		return got
	case <-time.After(10 * time.Second):
		r.t.Fatal("中继侧握手超时")
		return acceptResult{}
	}
}

// TestChannelBindingSurvivesTheRealHandshakeAndStopsCrossConnectionReplay
// 是信道绑定这层防护**唯一**能证明自己的测试。
//
// # 为什么单元测试不够
//
// 单元测试证明的是「材料不同则验签失败」，那是 HMAC 的性质，不是接线的性质。
// 而这层防护此前的真实状态是：性质成立、单元测试全绿、README 列在
// 「已实现并验证」，两个生产调用点却都传字面量 `nil`。两侧都传 nil 时
// 材料仍然「一致」，所有握手成功，e2e 全绿 —— 失效只在攻击发生时暴露。
//
// 所以这里跑真实的 QUIC 握手、真实的 exporter、真实的 HMAC 校验，
// 并把两个方向都钉住：
//
//  1. **正向**：带凭据重连必须成功。两端各自从自己那一侧的 TLS 状态导出材料，
//     只要有一丁点不对称，每一次重连都会失败 —— 这一条守的是可用性，
//     而它的失效形态是「首次入网正常、之后再也连不上」。
//  2. **反向**：拿连接 A 的材料签出的证明，搬到连接 B 上必须被拒。
//     这才是绑定存在的理由。证明用**新鲜的 nonce**（agent.Handshake 每次
//     自己生成），所以拒绝不可能来自重放守卫 —— 排除掉那个混淆项之后，
//     唯一可能的拒因就是信道绑定。
func TestChannelBindingSurvivesTheRealHandshakeAndStopsCrossConnectionReplay(t *testing.T) {
	rig := newBindingRig(t)

	const enrolToken = "nf_enrol_binding_e2e"
	rig.auth.issueToken(enrolToken)
	ident := agent.Identity{Version: "e2e", Hostname: "binding-host"}

	// ── 连接 1：令牌首次入网 ──────────────────────────────────────────────
	//
	// 入网路径**不用**绑定（此时还没有密钥可签），但走一遍是必需的：
	// 只有它能给出后面两步要用的长期凭据，而那正是绑定生效的那条路径。
	_, ctrl1, binding1 := rig.dial()
	res1, err := agent.Handshake(ctrl1, agent.Credential{}, enrolToken, binding1, ident)
	if err != nil {
		t.Fatalf("首次入网失败：%v", err)
	}
	if res1.IssuedKey == "" {
		t.Fatal("首次入网应当下发密钥")
	}
	if got := rig.relayResult(); got.err != nil {
		t.Fatalf("中继侧首次入网失败：%v", got.err)
	}
	cred := agent.Credential{AgentID: res1.AgentID, Key: res1.IssuedKey}

	// ── 连接 2：带凭据重连（正向）──────────────────────────────────────────
	_, ctrl2, binding2 := rig.dial()
	res2, err := agent.Handshake(ctrl2, cred, "", binding2, ident)
	if err != nil {
		t.Fatalf("带凭据重连失败：%v —— 两端导出的信道绑定材料不一致，"+
			"现象会是「首次入网正常、之后每一次重连都失败」", err)
	}
	if res2.AgentID != cred.AgentID {
		t.Errorf("重连后 agent 身份变了：%q → %q", cred.AgentID, res2.AgentID)
	}
	got2 := rig.relayResult()
	if got2.err != nil {
		t.Fatalf("中继侧带凭据握手失败：%v", got2.err)
	}

	// 顺带把「两侧确实拿到同一份材料」直接钉住 —— 上面那次成功已经蕴含它，
	// 但显式对比能在将来失败时立刻指出是哪一层坏了。
	if hex.EncodeToString(got2.binding) != hex.EncodeToString(binding2) {
		t.Fatalf("两侧材料不同：\n中继 %x\nagent %x", got2.binding, binding2)
	}
	if len(binding2) == 0 {
		t.Fatal("材料为空 —— 那等于没有绑定，而所有握手照常成功")
	}
	if hex.EncodeToString(binding1) == hex.EncodeToString(binding2) {
		t.Fatal("两条连接给出同一份材料 —— 绑定退化成常量，下面那步的拒绝将失去意义")
	}

	// ── 连接 3：拿连接 2 的材料签，在连接 3 上出示（反向）──────────────────
	//
	// 这一步模拟的是「Hello 被偷走并搬到另一条连接上重放」。nonce 是新鲜的，
	// 时间戳是当下的 —— 重放守卫与时钟窗都不会拒它。
	_, ctrl3, binding3 := rig.dial()
	if hex.EncodeToString(binding3) == hex.EncodeToString(binding2) {
		t.Fatal("第三条连接与第二条材料相同，本测试测不到目标")
	}
	_, err = agent.Handshake(ctrl3, cred, "", binding2 /* 故意用错连接的材料 */, ident)
	if err == nil {
		t.Fatal("拿连接 2 的材料在连接 3 上握手**成功**了 —— " +
			"信道绑定没有生效，一份被偷到的 Hello 可以在任意连接上重放")
	}
	got3 := rig.relayResult()
	if got3.err == nil {
		t.Fatal("中继侧接受了搬过来的证明 —— 信道绑定没有生效")
	}
	// 拒因必须落在**鉴权**上，而不是别的什么恰好也拒了它
	//（流被提前关掉、超时、协议版本不合……那些都会让上面两条断言假成立）。
	//
	// agent 侧拿到的是线上的 proto.Error，它的 code 是规格里的稳定契约；
	// 中继侧那份是内部错误，只能看文案。两侧都查：前者证明「客户端看到的是
	// 鉴权失败」，后者证明「拒的是 MAC 不匹配」——只有后者能排除
	// 「令牌无效」「nonce 已用」这两个同样回 auth_failed 的分支。
	var pe *proto.Error
	if !errors.As(err, &pe) {
		t.Fatalf("agent 侧收到的不是协议错误（%v）—— 无法确认它是因为绑定被拒", err)
	}
	if pe.Code != proto.ErrCodeAuthFailed {
		t.Errorf("agent 侧收到的 code 是 %q，期望 %q", pe.Code, proto.ErrCodeAuthFailed)
	}
	if !strings.Contains(got3.err.Error(), "MAC 校验失败") {
		t.Errorf("中继侧的拒因是 %q，期望是 MAC 校验失败 —— "+
			"若拒因换成了别的（超时、nonce 已用、令牌无效），"+
			"上面那两条断言就不再证明「绑定生效」", got3.err)
	}

	// ── 最后：正常凭据在**自己的**连接上仍然可用 ──────────────────────────
	//
	// 少了这一步，一个「握手全拒」的实现也能让上面每一条断言通过。
	_, ctrl4, binding4 := rig.dial()
	if _, err := agent.Handshake(ctrl4, cred, "", binding4, ident); err != nil {
		t.Fatalf("失败一次之后正常重连也不通了（%v）—— "+
			"上面的拒绝可能来自「什么都拒」而不是绑定", err)
	}
	if got := rig.relayResult(); got.err != nil {
		t.Fatalf("中继侧拒绝了正常重连：%v", got.err)
	}
}
