package gateway

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"
)

// PROXY protocol 的两个版本前缀。
//
// v1 是文本行：`PROXY TCP4 1.2.3.4 5.6.7.8 1111 443\r\n`，整行不超过 107 字节。
// v2 是二进制，前 12 字节是一个不可能出现在任何明文协议里的签名。
var (
	proxyV1Prefix = []byte("PROXY ")
	proxyV2Magic  = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
)

// proxyV1MaxLen 是 v1 头的最大长度（含 CRLF），由规范给定。
const proxyV1MaxLen = 107

// ErrBadProxyHeader 表示 PROXY 头存在但解析失败。
//
// 这种情况**必须拒连**而不是当作没有头：监听器被标记为可信，说明前面确实有
// 我们自己的负载均衡器；解析失败意味着我们对这条连接的真实来源一无所知，
// 而下游会把 X-Forwarded-For 当权威值用。
var ErrBadProxyHeader = errors.New("gateway: PROXY protocol 头非法")

// proxyHeader 是解析出来的 PROXY 头。
type proxyHeader struct {
	// Src / Dst 是头里声明的地址。LOCAL 命令（健康检查）不带地址，此时两者无效。
	Src netip.AddrPort
	Dst netip.AddrPort
	// Len 是头在字节流里占用的长度，调用方据此 Discard。
	Len int
	// Version 是 1 或 2，用于指标标签。
	Version int
}

// readProxyHeader 惰性判别并解析 PROXY protocol v1/v2 头。
//
// # 只在监听器被显式标记可信时才调用
//
// PROXY 头是一个**源 IP 伪造原语**：任何能连上这个端口的人都能声称自己是
// 任意地址。所以判别顺序第 1 步的前提是「监听器被标记 trustProxyProtocol」，
// 即前面确实是我们自己的负载均衡器。对不可信来源解析它等于把 §12 的
// 「X-Forwarded-For 先删再设」那道防线拱手让出。
//
// 返回 (nil, nil) 表示这条连接上没有 PROXY 头，判别继续往下走。
//
// 实现刻意是**逐级 peek**：先只看 1 个字节，只有它可能是 v1('P') 或 v2(0x0D)
// 才继续看更多。这样「首包只有 3 个字节」的连接不会为了凑够 12 字节签名而等待。
func readProxyHeader(c *PeekConn, step time.Duration) (*proxyHeader, error) {
	first, err := c.Peek(1, step)
	if err != nil {
		return nil, err
	}
	switch first[0] {
	case 'P':
		return readProxyV1(c, step)
	case proxyV2Magic[0]:
		return readProxyV2(c, step)
	default:
		return nil, nil
	}
}

// peekPrefix 逐字节确认一个固定前缀，一旦出现不匹配就立刻否决。
//
// 这一点很重要：`POST / HTTP/1.1` 与 `PROXY ` 都以 'P' 开头，
// 若直接 Peek(6) 去比，一个只发了 "PO" 就等服务端的客户端会被白等一整步。
// 逐字节确认让否决在第 2 个字节就发生。
func peekPrefix(c *PeekConn, prefix []byte, step time.Duration) (bool, error) {
	for n := 2; n <= len(prefix); n++ {
		b, err := c.Peek(n, step)
		if err != nil {
			return false, err
		}
		if !bytes.HasPrefix(prefix, b) {
			return false, nil
		}
	}
	return true, nil
}

func readProxyV1(c *PeekConn, step time.Duration) (*proxyHeader, error) {
	ok, err := peekPrefix(c, proxyV1Prefix, step)
	if err != nil {
		return nil, err
	}
	if !ok {
		// 首字节是 'P' 但不是 "PROXY " —— 可能是一个 POST/PUT 请求，交给后面的步骤。
		return nil, nil
	}

	// 逐级找行尾：先吃掉当前缓冲里的，不够再多要一个字节。
	// 绝不一次性要 107 字节 —— 那正是 frp 的 io.ReadFull 会挂死的形状。
	need := len(proxyV1Prefix) + 1
	for {
		line, err := c.Peek(need, step)
		if err != nil {
			return nil, err
		}
		if i := bytes.Index(line, []byte("\r\n")); i >= 0 {
			h, err := parseProxyV1(line[:i])
			if err != nil {
				return nil, err
			}
			h.Len = i + 2
			return h, nil
		}
		if avail := c.Buffered(); avail > need {
			// 缓冲里已经有更多字节了，先把它们全看完再回到 socket。
			need = avail
			continue
		}
		if need >= proxyV1MaxLen {
			return nil, fmt.Errorf("%w：v1 头超过 %d 字节仍无 CRLF", ErrBadProxyHeader, proxyV1MaxLen)
		}
		need++
	}
}

func parseProxyV1(line []byte) (*proxyHeader, error) {
	fields := bytes.Split(line, []byte(" "))
	if len(fields) < 2 {
		return nil, fmt.Errorf("%w：v1 头字段不足", ErrBadProxyHeader)
	}
	proto := string(fields[1])
	if proto == "UNKNOWN" {
		// 规范允许 UNKNOWN（前置代理自己也不知道来源），此时不带地址。
		// 头仍然要消费掉，但真实客户端保持「不知道」——绝不编一个出来。
		return &proxyHeader{Version: 1}, nil
	}
	if len(fields) != 6 {
		return nil, fmt.Errorf("%w：v1 %s 头应有 6 个字段，实际 %d", ErrBadProxyHeader, proto, len(fields))
	}
	if proto != "TCP4" && proto != "TCP6" {
		return nil, fmt.Errorf("%w：v1 不支持的协议 %q", ErrBadProxyHeader, proto)
	}

	srcPort, err1 := strconv.ParseUint(string(fields[4]), 10, 16)
	dstPort, err2 := strconv.ParseUint(string(fields[5]), 10, 16)
	srcAddr, err3 := netip.ParseAddr(string(fields[2]))
	dstAddr, err4 := netip.ParseAddr(string(fields[3]))
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return nil, fmt.Errorf("%w：%w", ErrBadProxyHeader, err)
	}
	if (proto == "TCP4") != srcAddr.Is4() || srcAddr.Is4() != dstAddr.Is4() {
		return nil, fmt.Errorf("%w：v1 声明 %s 但地址族不符", ErrBadProxyHeader, proto)
	}
	return &proxyHeader{
		Src:     netip.AddrPortFrom(srcAddr, uint16(srcPort)),
		Dst:     netip.AddrPortFrom(dstAddr, uint16(dstPort)),
		Version: 1,
	}, nil
}

// v2 头固定 16 字节，其后是 len 字节的地址块。
const proxyV2FixedLen = 16

func readProxyV2(c *PeekConn, step time.Duration) (*proxyHeader, error) {
	ok, err := peekPrefix(c, proxyV2Magic, step)
	if err != nil {
		return nil, err
	}
	if !ok {
		// 0x0D 开头但不是 v2 签名。既然首字节不可打印，后面的步骤会按端口默认处理。
		return nil, nil
	}

	hdr, err := c.Peek(proxyV2FixedLen, step)
	if err != nil {
		return nil, err
	}
	if hdr[12]>>4 != 0x2 {
		return nil, fmt.Errorf("%w：v2 版本号应为 2，实际 %d", ErrBadProxyHeader, hdr[12]>>4)
	}
	cmd := hdr[12] & 0x0F
	fam := hdr[13]
	addrLen := int(binary.BigEndian.Uint16(hdr[14:16]))
	total := proxyV2FixedLen + addrLen

	full, err := c.Peek(total, step)
	if err != nil {
		return nil, err
	}
	h := &proxyHeader{Len: total, Version: 2}

	// cmd 0x0 = LOCAL（前置代理自身的健康检查），不带有意义的地址。
	if cmd == 0x0 {
		return h, nil
	}
	if cmd != 0x1 {
		return nil, fmt.Errorf("%w：v2 未知命令 0x%x", ErrBadProxyHeader, cmd)
	}
	body := full[proxyV2FixedLen:]

	switch fam {
	case 0x11, 0x12: // TCP/UDP over IPv4
		if len(body) < 12 {
			return nil, fmt.Errorf("%w：v2 IPv4 地址块不足 12 字节", ErrBadProxyHeader)
		}
		src, _ := netip.AddrFromSlice(body[0:4])
		dst, _ := netip.AddrFromSlice(body[4:8])
		h.Src = netip.AddrPortFrom(src, binary.BigEndian.Uint16(body[8:10]))
		h.Dst = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(body[10:12]))
	case 0x21, 0x22: // TCP/UDP over IPv6
		if len(body) < 36 {
			return nil, fmt.Errorf("%w：v2 IPv6 地址块不足 36 字节", ErrBadProxyHeader)
		}
		src, _ := netip.AddrFromSlice(body[0:16])
		dst, _ := netip.AddrFromSlice(body[16:32])
		h.Src = netip.AddrPortFrom(src, binary.BigEndian.Uint16(body[32:34]))
		h.Dst = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(body[34:36]))
	default:
		// AF_UNIX（0x31/0x32）与 UNSPEC（0x00）不带可用的 IP 地址：
		// 头照样消费，但来源保持「不知道」。
		return h, nil
	}
	return h, nil
}
