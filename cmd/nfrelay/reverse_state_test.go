package main

import (
	"strings"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/relay"
	"github.com/nomifun/nomifun-net-infra/internal/tunnel"
)

// mkTunnel 造一条最简可用的隧道。
//
// ListenPort 必须非 0：为 0 时会命中 refreshStates 里更早的一条
// 「未能分配入口端口」分支，于是本文件想测的两条判据一条都走不到
// （这是设计复审点名的一个陷阱）。
func mkTunnel(slug string, kind tunnel.Kind, agentID string) *tunnel.Tunnel {
	t := &tunnel.Tunnel{
		ID: "t-" + slug, Slug: slug, Kind: kind, AgentID: agentID,
		Exposure: tunnel.ExposurePort, ListenPort: 29000, L4: tunnel.L4TCP,
		Backend: tunnel.Backend{Kind: tunnel.BackendAddr, Addr: "127.0.0.1:8080"},
	}
	t.Complete()
	return t
}

// TestEveryKindReportsAMissingAgentTruthfully 是本文件存在的全部理由。
//
// # 修之前的行为（实测过）
//
// refreshStates 里两条 agent 存活判据都带 `t.Kind == KindService &&` 前置，
// 而 switch 的初值是 StateActive。于是**任何** kind=reverse 隧道恒报 active，
// 与 agent 是空、是错的、还是对的但离线全都无关。
//
// 三条隧道挂同一个不存在的 agent：reverse 报 active、service 报 degraded，
// 而两者 curl 过去都是 connection reset。
//
// # 为什么那条前置是错的
//
// 它的理由是「reverse 走中继自己拨号，不需要 agent」。而那条路径**在数据面
// 根本不存在**：三个入口（internal/relay/entry.go、internal/gateway/gateway.go、
// internal/relay/udpentry.go）全都调 SessionFor(t.AgentID)，返回 false 就直接
// 放弃，没有任何一处回落；而 SessionFor("") 无条件返回 false。
//
// 所以一条无 agent 的 reverse 隧道不是「另一种形态」，
// 而是一条每个连接都被静默关掉、却在控制台上显示绿点的坏隧道。
func TestEveryKindReportsAMissingAgentTruthfully(t *testing.T) {
	for _, kind := range []tunnel.Kind{tunnel.KindService, tunnel.KindReverse} {
		t.Run(string(kind), func(t *testing.T) {
			// ── 无 agent ──
			rt := newTestRuntime(t)
			noAgent := mkTunnel("no-agent", kind, "")
			if err := rt.db.PutTunnel(rt.ctx, noAgent); err != nil {
				t.Fatal(err)
			}
			rt.refreshStates([]*tunnel.Tunnel{noAgent})

			got, err := rt.db.GetTunnel(rt.ctx, noAgent.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.State == tunnel.StateActive {
				t.Errorf("kind=%s 且无 agent 却报 active —— 数据面会静默关掉每一个连接，"+
					"而运维看到的是绿点，拿不到任何故障信号", kind)
			}
			if got.State != tunnel.StatePending {
				t.Errorf("kind=%s 且无 agent 应当报 pending，实际 %q（%q）",
					kind, got.State, got.StateReason)
			}

			// ── agent 指定了但不在线 ──
			rt2 := newTestRuntime(t)
			offline := mkTunnel("offline", kind, "agent-deadbeefcafe")
			if err := rt2.db.PutTunnel(rt2.ctx, offline); err != nil {
				t.Fatal(err)
			}
			rt2.refreshStates([]*tunnel.Tunnel{offline})

			got2, err := rt2.db.GetTunnel(rt2.ctx, offline.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got2.State == tunnel.StateActive {
				t.Errorf("kind=%s 的 agent 不在线却报 active —— 同上，绿点撒谎", kind)
			}
			if got2.State != tunnel.StateDegraded {
				t.Errorf("kind=%s 的 agent 不在线应当报 degraded，实际 %q（%q）",
					kind, got2.State, got2.StateReason)
			}
			if got2.StateReason == "" {
				t.Error("必须给出原因 —— 一个不解释的红点让运维无从下手")
			}
		})
	}
}

// TestUnassignedTunnelsOfEveryKindCanAutoBind 钉住第二半。
//
// bindUnassigned 原本跳过 reverse，注释写的是「kind=reverse 且无 agent 是
// 合法且有意的形态（中继自己拨号），不要去动它」—— 而那条路径不存在。
//
// 跳过它的后果是它连**自愈的机会**都没有：service 隧道在唯一 agent 上线时会被
// 自动绑上，而 reverse 永远停在那里。这也让 probe.go 那句
// 「等代理端上线后会自动绑定」对 reverse 一直是假话。
func TestUnassignedTunnelsOfEveryKindCanAutoBind(t *testing.T) {
	for _, kind := range []tunnel.Kind{tunnel.KindService, tunnel.KindReverse} {
		t.Run(string(kind), func(t *testing.T) {
			rt := newTestRuntime(t)
			tn := mkTunnel("unbound", kind, "")
			if err := rt.db.PutTunnel(rt.ctx, tn); err != nil {
				t.Fatal(err)
			}

			// 没有 agent 在线：不该动它（也不该 panic）。
			rt.bindUnassigned([]*tunnel.Tunnel{tn})
			if tn.AgentID != "" {
				t.Fatalf("没有 agent 在线时不该绑定，实际绑到了 %q", tn.AgentID)
			}

			// 恰好一个在线：必须绑上，且回写库。
			rt.sessions.Add(&relay.Session{
				AgentID: "agent-solo01020304", Carrier: newIdleCarrier(t),
				ConnectedAt: time.Now(),
			})
			rt.bindUnassigned([]*tunnel.Tunnel{tn})
			if tn.AgentID != "agent-solo01020304" {
				t.Fatalf("kind=%s 恰好一个 agent 在线时应当自动绑上，实际 %q —— "+
					"跳过它意味着这条隧道连自愈的机会都没有，"+
					"而 probe.go 还在说「等代理端上线后会自动绑定」", kind, tn.AgentID)
			}
			got, err := rt.db.GetTunnel(rt.ctx, tn.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.AgentID != tn.AgentID {
				t.Errorf("绑定没回写库（读到 %q）—— 重启后又变成未绑定", got.AgentID)
			}
		})
	}
}

// TestTwoOnlineAgentsDoNotProduceAPromiseThatCanNeverBeKept 钉住第三种形态。
//
// # 修之前的行为
//
// bindUnassigned 的 default 分支（≥2 个 agent 在线）会往库里写
// 「error：有 N 个代理端在线，请在隧道配置里显式指定一个」—— 一条**可行动**
// 的原因。然后同一次 ApplyTunnels 里的 refreshStates 看到 t.AgentID 仍为空，
// 落到 `pending：端口已监听，等待代理端上线`，把它盖掉。
//
// 用户于是看到一条永远停在 pending 的隧道，配着一句**假话**：agent 已经在线，
// 只是有两个；而界面给的下一步动作（等）永远不会奏效。
//
// 这比「没有提示」更坏 —— 它把人引向一个不可能成功的等待。
// bindUnassigned 里 case 0 的注释早就点出过这个覆盖陷阱，default 落进了同一个坑。
//
// # 为什么两条路径都要测
//
// 单测 refreshStates 不够：那样一个「bindUnassigned 写 error、refreshStates
// 再写回 error」的实现也能过，而那个实现在真实的 ApplyTunnels 顺序下
// 仍然是对的 —— 但只要有人调换顺序就又坏了。所以按真实顺序连着跑两步。
func TestTwoOnlineAgentsDoNotProduceAPromiseThatCanNeverBeKept(t *testing.T) {
	rt := newTestRuntime(t)
	tn := mkTunnel("ambiguous", tunnel.KindService, "")
	if err := rt.db.PutTunnel(rt.ctx, tn); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"agent-aaaa11112222", "agent-bbbb33334444"} {
		rt.sessions.Add(&relay.Session{
			AgentID: id, Carrier: newIdleCarrier(t), ConnectedAt: time.Now(),
		})
	}

	// 真实顺序：ApplyTunnels 先 bindUnassigned，再 refreshStates。
	rt.bindUnassigned([]*tunnel.Tunnel{tn})
	if tn.AgentID != "" {
		t.Fatalf("两个 agent 在线时不该猜一个绑上，实际绑到了 %q", tn.AgentID)
	}
	rt.refreshStates([]*tunnel.Tunnel{tn})

	got, err := rt.db.GetTunnel(rt.ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State == tunnel.StatePending {
		t.Fatalf("报了 pending「%s」—— 而 agent 已经在线（两个）。"+
			"这条隧道会永远停在这里，而界面给的下一步动作（等）永远不会奏效",
			got.StateReason)
	}
	if got.State != tunnel.StateError {
		t.Errorf("状态 = %q（%q），期望 error —— 这需要人去做一个选择，"+
			"不是一个会自愈的过渡态", got.State, got.StateReason)
	}
	// 文案必须说清「有几个」与「去哪里改」，否则运维只知道出错了。
	for _, want := range []string{"2", "显式指定"} {
		if !strings.Contains(got.StateReason, want) {
			t.Errorf("原因 %q 里应当出现 %q —— 否则运维不知道下一步做什么",
				got.StateReason, want)
		}
	}

	// 收敛：显式绑定之后必须恢复正常判定，否则这个 error 就成了死结。
	tn.AgentID = "agent-aaaa11112222"
	if err := rt.db.PutTunnel(rt.ctx, tn); err != nil {
		t.Fatal(err)
	}
	rt.refreshStates([]*tunnel.Tunnel{tn})
	fixed, err := rt.db.GetTunnel(rt.ctx, tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fixed.State != tunnel.StateActive {
		t.Errorf("显式指定 agent 之后状态 = %q（%q），期望 active —— "+
			"否则那条 error 是个解不开的死结", fixed.State, fixed.StateReason)
	}
}
