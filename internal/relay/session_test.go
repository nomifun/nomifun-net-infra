package relay

import "testing"

func TestHasDatagramSenderDoesNotConsumeTheOnce(t *testing.T) {
	// 用 senderOnce.Do(func(){}) 去「探测有没有建过」会把 Once 消耗掉，
	// 于是之后 DatagramSender 再也不会创建发送器 —— 一旦控制台渲染过
	// 一次 agent 列表，这台 agent 上**所有** UDP 隧道就永久哑掉，
	// 而且没有任何错误、没有任何计数。
	//
	// Close 里那处 Do(func(){}) 是刻意的（它就是要阻止之后再创建），
	// 语义正好相反 —— 所以这两处不能共用一个机制。
	sess, _ := dgramSession(t, "agent-1")

	if sess.HasDatagramSender() {
		t.Fatal("还没用过就不该说建过")
	}
	// 探测若干次：如果它消耗 Once，下面的创建就会失败。
	for range 3 {
		_ = sess.HasDatagramSender()
	}

	if snd := sess.DatagramSender(); snd == nil {
		t.Fatal("探测过之后 DatagramSender 返回了 nil —— " +
			"探测把 senderOnce 消耗掉了，这条承载上所有 UDP 隧道会永久哑掉")
	}
	if !sess.HasDatagramSender() {
		t.Fatal("建过之后应当报 true")
	}
}
