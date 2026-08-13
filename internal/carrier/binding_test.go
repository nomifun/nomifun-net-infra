package carrier

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestChannelBindingIsSymmetricAndPerConnection 钉住信道绑定的三条性质。
//
// # 为什么这三条缺一不可
//
// 绑定的用途是让握手证明**只在生成它的那条 TLS 连接上有效**：偷到一份
// Hello（旁路日志、被攻陷的中间盒、内存转储）也没法把它搬到另一条连接上重放。
// 这层防护由三条性质共同支撑，少任何一条它都会**静默**失效：
//
//  1. **两侧一致**。两端各自算 MAC，材料不同则每次握手都失败 ——
//     这一条错了是「全线不通」，最响的失败，但也最容易在只有一侧接线时发生。
//  2. **非空且足够长**。ProofCanonical 用长度前缀拼字段，空材料拼进去
//     等于**没有绑定**：所有握手照常成功，防护整层消失且**没有任何迹象**。
//     这正是它此前的形态 —— 两侧都传 nil，README 却把它列在「已实现并验证」。
//  3. **逐连接不同**。相同才是这层防护的全部意义所在；如果两条连接给出
//     同一份材料，证明就可以在它们之间搬来搬去，绑定退化成一个常量。
func TestChannelBindingIsSymmetricAndPerConnection(t *testing.T) {
	relayA, agentA := pair(t)

	rb, err := relayA.ChannelBinding()
	if err != nil {
		t.Fatalf("中继侧取绑定材料失败：%v", err)
	}
	ab, err := agentA.ChannelBinding()
	if err != nil {
		t.Fatalf("agent 侧取绑定材料失败：%v", err)
	}

	// 1. 两侧一致。
	if !bytes.Equal(rb, ab) {
		t.Fatalf("两侧材料不同 —— 每次握手都会 MAC 不匹配：\n中继 %x\nagent %x", rb, ab)
	}

	// 2. 非空且长度符合约定。
	if len(rb) != channelBindingLen {
		t.Fatalf("材料长 %d 字节，期望 %d —— 空/短材料等于**没有绑定**，"+
			"而所有握手仍会成功，整层防护静默消失", len(rb), channelBindingLen)
	}
	if bytes.Equal(rb, make([]byte, channelBindingLen)) {
		t.Fatal("材料全为零字节 —— 那与常量无异，证明可以在连接之间搬运")
	}

	// 3. 另一条连接必须给出不同的材料。
	relayB, _ := pair(t)
	other, err := relayB.ChannelBinding()
	if err != nil {
		t.Fatalf("第二条连接取绑定材料失败：%v", err)
	}
	if bytes.Equal(rb, other) {
		t.Fatalf("两条不同连接给出同一份材料（%x）—— 绑定退化成常量，"+
			"一份被偷到的 Hello 可以搬到另一条连接上重放", rb)
	}
}

// TestBothHandshakeCallSitesFeedTheBinding 是一条**接线门禁**。
//
// # 为什么需要读源码
//
// 上面那条测试证明的是「材料算得对」，它对**有没有被用上**一无所知。
// 而这一层防护此前的真实状态恰恰是：ProofCanonical 里的字段在、
// 单元测试里换掉材料确实会验签失败、README 把它列在「已实现并验证」——
// 唯独两个生产调用点都传的是字面量 `nil`。
//
// 这种失效形态没有任何测试抓得住：agent 与中继传的都是 nil，
// 两侧照样一致，握手全部成功，e2e 全绿。它只在**攻击发生时**才暴露。
//
// 所以门禁只能落在「调用点长什么样」上。传 nil 会让这条测试红，
// 而写一个假的非 nil 变量骗过它需要**刻意**为之 ——
// 门禁挡的是手滑与遗忘，不是内部人作恶。
func TestBothHandshakeCallSitesFeedTheBinding(t *testing.T) {
	// 调用点在两个 main 包里，测试无法 import 它们（也不该 import）。
	sites := []struct {
		path string
		call string // 握手函数在源码里的字面写法
	}{
		{filepath.Join("..", "..", "cmd", "nfagent", "main.go"), "agent.Handshake("},
		{filepath.Join("..", "..", "cmd", "nfrelay", "main.go"), "relay.Handshake("},
	}

	for _, s := range sites {
		src, err := os.ReadFile(s.path)
		if err != nil {
			t.Fatalf("读 %s 失败：%v", s.path, err)
		}
		text := string(src)

		if !regexp.MustCompile(regexp.QuoteMeta(s.call)).MatchString(text) {
			t.Fatalf("%s 里找不到 %s —— 它被改名或挪走了？"+
				"那这条门禁已经失效，必须跟着改", s.path, s.call)
		}

		// ChannelBinding 必须真的被调用。
		if !regexp.MustCompile(`\bChannelBinding\(\)`).MatchString(text) {
			t.Errorf("%s 从不调用 ChannelBinding() —— 握手证明没有绑到具体连接上，"+
				"一份被偷到的 Hello 可以在任意连接上重放", s.path)
		}

		// 握手的实参列表里不能出现字面量 nil。
		//
		// 两个调用点里 exporter 的位次不同（agent 是第 4 个、中继是第 2 个），
		// 所以不去数位次，而是断言**整个实参列表里没有 nil**——
		// 两处当前也确实没有任何一个实参该是 nil，这个更粗的判据同样精确，
		// 而且不会在将来加参数时悄悄看错位置。
		//
		// 只看紧跟调用之后到第一个 `)` 之前的一段（跨行调用里实参可能在下一行）。
		idx := regexp.MustCompile(regexp.QuoteMeta(s.call)).FindStringIndex(text)
		tail := text[idx[1]:min(idx[1]+200, len(text))]
		if regexp.MustCompile(`(?s)^[^)]*\bnil\b`).MatchString(tail) {
			t.Errorf("%s 的 %s 实参列表里出现了 nil —— 若那是绑定材料，"+
				"这一层防护在生产路径上就是关着的，而所有测试都会通过", s.path, s.call)
		}
	}
}
