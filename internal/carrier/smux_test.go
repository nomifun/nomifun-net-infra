package carrier

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/nomifun/nomifun-net-infra/internal/proto"
)

// muxPair 建立一对已连通的 L2 承载（中继侧、agent 侧）。
func muxPair(t *testing.T) (relaySide, agentSide Carrier) {
	t.Helper()

	cert, leaf := selfSigned(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	srvCfg := ServerTLSConfig(cert)
	type res struct {
		c   Carrier
		err error
	}
	accepted := make(chan res, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			accepted <- res{nil, err}
			return
		}
		tc := tls.Server(raw, srvCfg)
		if err := tc.HandshakeContext(context.Background()); err != nil {
			accepted <- res{nil, err}
			return
		}
		c, err := AdoptTLSMux(tc)
		accepted <- res{c, err}
	}()

	cliCfg, err := ClientTLSConfig("nomirelay-test", nil, SPKIPin(leaf))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	agentSide, err = DialTLSMux(ctx, ln.Addr().String(), cliCfg)
	if err != nil {
		t.Fatalf("拨 L2 失败：%v", err)
	}
	t.Cleanup(func() { agentSide.CloseWithError(0, "测试结束") })

	r := <-accepted
	if r.err != nil {
		t.Fatalf("中继侧建立 L2 失败：%v", r.err)
	}
	t.Cleanup(func() { r.c.CloseWithError(0, "测试结束") })
	return r.c, agentSide
}

// TestL2RelayCanOpenStreamToAgent 是这个梯级存在的**前提条件**。
//
// 换承载不能改变数据面的任何一行，而数据面要求**中继也能主动开流** ——
// 那是 0 额外 RTT 的全部来源。裸 TCP 做不到（一条 TCP 只有一条流），
// 所以规格挑了 smux：它的流在两侧都能开（client 用奇数 ID、server 用偶数）。
//
// 这一条错了，L2 就退化成 frp 那种「中继要请求 agent 再拨一次」的形态，
// 而那正是本仓花了最大篇幅去掉的三次往返。
func TestL2RelayCanOpenStreamToAgent(t *testing.T) {
	relaySide, agentSide := muxPair(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type got struct {
		b   []byte
		err error
	}
	ch := make(chan got, 1)
	go func() {
		st, err := agentSide.AcceptStream(ctx)
		if err != nil {
			ch <- got{nil, err}
			return
		}
		buf := make([]byte, 5)
		_, err = io.ReadFull(st, buf)
		ch <- got{buf, err}
	}()

	st, err := relaySide.OpenStream(ctx)
	if err != nil {
		t.Fatalf("中继侧开流失败：%v —— L2 于是无法承载数据面", err)
	}
	if _, err := st.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	select {
	case g := <-ch:
		if g.err != nil {
			t.Fatalf("agent 侧收流失败：%v", g.err)
		}
		if !bytes.Equal(g.b, []byte("hello")) {
			t.Errorf("收到 %q，期望 \"hello\"", g.b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("超时：中继开的流没到 agent")
	}
}

// TestL2StreamsWorkInBothDirections 钉住反向也能开。
//
// agent 侧开流是握手（控制流）走的路。少了它连不上，而这与上面那条
// 是两个独立的 smux 方向。
func TestL2StreamsWorkInBothDirections(t *testing.T) {
	relaySide, agentSide := muxPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		st, err := relaySide.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(st, buf); err != nil {
			done <- err
			return
		}
		_, err = st.Write([]byte("pong"))
		done <- err
	}()

	st, err := agentSide.OpenStream(ctx)
	if err != nil {
		t.Fatalf("agent 侧开流失败：%v —— 握手的控制流走的正是这条路", err)
	}
	if _, err := st.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("读回应失败：%v", err)
	}
	if string(buf) != "pong" {
		t.Errorf("收到 %q，期望 \"pong\"", buf)
	}
	if err := <-done; err != nil {
		t.Fatalf("中继侧出错：%v", err)
	}
}

// TestL2RefusesDatagramsInsteadOfFakingThem 是这个梯级最要紧的一条**诚实性**测试。
//
// smux 只有可靠有序流。最糟的实现是把数据报塞进一条流让它「看起来能用」——
// frp 就是那样做的（全部 UDP 塞进一条 TCP workConn），而语义错配导致的
// 队头阻塞是调不掉的，用户却以为自己拿到了低延迟通道。
//
// 正确行为是明确拒绝，让上层把那条 UDP 隧道标成 degraded 并说明原因。
func TestL2RefusesDatagramsInsteadOfFakingThem(t *testing.T) {
	relaySide, agentSide := muxPair(t)

	for name, c := range map[string]Carrier{"中继侧": relaySide, "agent 侧": agentSide} {
		if c.SupportsDatagrams() {
			t.Errorf("%s 声称支持数据报 —— smux 只有可靠流，"+
				"谎报会让 UDP 隧道显示成可用而实际队头阻塞", name)
		}
		if got := c.MaxDatagramPayload(); got != 0 {
			t.Errorf("%s 报了一个数据报上限 %d —— 这一级没有数据报", name, got)
		}
		if err := c.SendDatagram([]byte("x")); !errors.Is(err, ErrDatagramUnsupported) {
			t.Errorf("%s 的 SendDatagram 回了 %v，期望 ErrDatagramUnsupported —— "+
				"上层靠这个哨兵错误安静降级，别的错误会被当成故障刷日志", name, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := c.ReceiveDatagram(ctx)
		cancel()
		if !errors.Is(err, ErrDatagramUnsupported) {
			t.Errorf("%s 的 ReceiveDatagram 回了 %v，期望 ErrDatagramUnsupported", name, err)
		}
	}
}

// TestL2ChannelBindingMatchesTheQUICContract 钉住绑定材料的**跨梯级一致性**。
//
// 绑定材料的定义属于协议，不属于承载梯级：同一个 label、同一个长度。
// 换梯级让算法变一遍的话，第三方实现就要按梯级分叉 —— 而分叉是漂移的开始。
//
// 三条性质与 QUIC 那边逐条对应（见 binding_test.go）。
func TestL2ChannelBindingMatchesTheQUICContract(t *testing.T) {
	relayA, agentA := muxPair(t)

	rb, err := relayA.ChannelBinding()
	if err != nil {
		t.Fatalf("中继侧取绑定材料失败：%v", err)
	}
	ab, err := agentA.ChannelBinding()
	if err != nil {
		t.Fatalf("agent 侧取绑定材料失败：%v", err)
	}
	if !bytes.Equal(rb, ab) {
		t.Fatalf("两侧材料不同 —— 每次重连都会 MAC 不匹配：\n中继 %x\nagent %x", rb, ab)
	}
	if len(rb) != channelBindingLen {
		t.Fatalf("材料长 %d 字节，期望 %d（与 QUIC 梯级同一个约定）", len(rb), channelBindingLen)
	}
	relayB, _ := muxPair(t)
	other, err := relayB.ChannelBinding()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rb, other) {
		t.Fatal("两条不同连接给出同一份材料 —— 绑定退化成常量")
	}
}

// TestL2ReportsItsRungSoTheConsoleCanShowIt 钉住梯级标识。
//
// 运维必须能看出「这个 agent 现在走的是降级路径」：L2 上 UDP 隧道不可用，
// 而那是一个需要解释的现象。梯级报错了就没人能把两件事联系起来。
func TestL2ReportsItsRungSoTheConsoleCanShowIt(t *testing.T) {
	relaySide, agentSide := muxPair(t)
	for name, c := range map[string]Carrier{"中继侧": relaySide, "agent 侧": agentSide} {
		if got := c.Rung(); got != RungTLS443 {
			t.Errorf("%s 报的梯级是 %v，期望 L2/TLS443", name, got)
		}
		if !c.Rung().Reliable() {
			t.Errorf("%s 的梯级没被标成「可靠承载」—— 上层靠这一位决定"+
				"要不要提供数据报路径", name)
		}
	}
}

// TestL2ContextIsCancelledWhenTheSessionDies 钉住看门狗。
//
// 上层到处依赖 Carrier.Context()：会话结束时它必须被取消，
// 否则那些 goroutine 永不退出 —— 一条已死的承载会留下一整套活着的协程，
// 而 agent 每次重连都再留一套。
func TestL2ContextIsCancelledWhenTheSessionDies(t *testing.T) {
	relaySide, agentSide := muxPair(t)

	if relaySide.Context().Err() != nil {
		t.Fatal("刚建好的承载 context 就已经被取消了")
	}
	_ = agentSide.CloseWithError(0, "模拟 agent 掉线")

	select {
	case <-relaySide.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("对端关闭之后中继侧的 context 没被取消 —— " +
			"每次重连都会漏一整套协程")
	}
}

// TestL2RefusesAPeerThatDidNotNegotiateOurALPN 钉住拨号侧的自检。
//
// 443/tcp 同时服务共享入口的业务流量。拨到一台**不是**承载入口的服务器上时
// （或者被一个中间盒接管时），继续跑 smux 只会得到一堆无从解释的解析错误。
// 按 ALPN 早失败，错误信息才指向真正的原因。
func TestL2RefusesAPeerThatDidNotNegotiateOurALPN(t *testing.T) {
	cert, leaf := selfSigned(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// 一台只说 http/1.1 的服务器（就像共享入口的网关分支）。
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		// **不设 NextProtos**：这才是要测的形态。
		//
		// 第一版给了 {"http/1.1"}，而 TLS 1.3 下 ALPN 不匹配是**致命告警** ——
		// 握手直接失败，我们那道自检压根没跑到。真正需要自检的是「对端不做
		// ALPN」：那时握手成功、NegotiatedProtocol 为空串，
		// 然后 smux 会在一堆无从解释的解析错误里挣扎。
		cfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
		tc := tls.Server(raw, cfg)
		_ = tc.HandshakeContext(context.Background())
		time.Sleep(time.Second)
		_ = tc.Close()
	}()

	cliCfg, err := ClientTLSConfig("nomirelay-test", nil, SPKIPin(leaf))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := DialTLSMux(ctx, ln.Addr().String(), cliCfg)
	if err == nil {
		c.CloseWithError(0, "")
		t.Fatal("对端没有协商我们的 ALPN，却建出了承载 —— " +
			"后面会是一堆无从解释的 smux 解析错误")
	}
	if !contains(err.Error(), proto.ALPN) {
		t.Errorf("错误信息里应当出现期望的 ALPN %q，实际 %v", proto.ALPN, err)
	}
}

func contains(hay, needle string) bool {
	return len(needle) <= len(hay) && bytes.Contains([]byte(hay), []byte(needle))
}

// TestL2StreamsFromBothSidesOnOneSessionDoNotCollide 钉住 smux 的角色分配。
//
// # 为什么单向的测试不够
//
// 生产上这两件事发生在**同一条会话**上：agent 开控制流（握手、Pong、计量），
// 中继开数据流（每条被代理连接一条）。smux 靠角色分配避免撞号 ——
// client 用奇数流 ID、server 用偶数。
//
// 两端若都用同一个角色，双方分配出的 ID 会撞：一条流的数据被送进另一条流。
// 而**单向**测试抓不到它 —— 一个方向只开一条流时永远不会撞。
// 这条测试是变异验证逼出来的：把 DialTLSMux 里的 server 参数从 false 改成
// true，上面那些测试全部照过。
//
// 症状会是数据串台（隧道 A 的字节出现在隧道 B 的连接上），
// 而不是一个干脆的错误 —— 那是最坏的一类故障。
func TestL2StreamsFromBothSidesOnOneSessionDoNotCollide(t *testing.T) {
	relaySide, agentSide := muxPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const n = 8

	// agent 侧：开 n 条流，每条写自己的编号；同时接中继开来的 n 条流并回显。
	agentDone := make(chan error, 1)
	go func() {
		agentDone <- func() error {
			for i := range n {
				st, err := agentSide.OpenStream(ctx)
				if err != nil {
					return fmt.Errorf("agent 开第 %d 条流失败：%w", i, err)
				}
				if _, err := st.Write([]byte{'a', byte('0' + i)}); err != nil {
					return err
				}
			}
			for range n {
				st, err := agentSide.AcceptStream(ctx)
				if err != nil {
					return err
				}
				buf := make([]byte, 2)
				if _, err := io.ReadFull(st, buf); err != nil {
					return err
				}
				if buf[0] != 'r' {
					return fmt.Errorf("agent 侧收到的流首字节是 %q，期望 'r' —— 数据串台了", buf[0])
				}
			}
			return nil
		}()
	}()

	// 中继侧：同样开 n 条流并接 n 条。
	for i := range n {
		st, err := relaySide.OpenStream(ctx)
		if err != nil {
			t.Fatalf("中继开第 %d 条流失败：%v", i, err)
		}
		if _, err := st.Write([]byte{'r', byte('0' + i)}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[byte]bool{}
	for range n {
		st, err := relaySide.AcceptStream(ctx)
		if err != nil {
			t.Fatalf("中继侧收流失败：%v", err)
		}
		buf := make([]byte, 2)
		if _, err := io.ReadFull(st, buf); err != nil {
			t.Fatalf("中继侧读流失败：%v", err)
		}
		if buf[0] != 'a' {
			t.Fatalf("中继侧收到的流首字节是 %q，期望 'a' —— "+
				"两端的流 ID 撞号了，一条流的数据被送进了另一条", buf[0])
		}
		if seen[buf[1]] {
			t.Fatalf("编号 %q 收到了两次 —— 撞号", buf[1])
		}
		seen[buf[1]] = true
	}
	if len(seen) != n {
		t.Errorf("只收到 %d 条流，期望 %d", len(seen), n)
	}
	if err := <-agentDone; err != nil {
		t.Fatalf("agent 侧出错：%v", err)
	}
}
