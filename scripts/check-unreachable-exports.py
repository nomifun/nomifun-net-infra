#!/usr/bin/env python3
"""找出「实现了但生产代码从不调用」的导出标识符。

# 为什么需要这道门禁

本仓库两次踩到同一个坑：一个包实现完整、测试齐全，但**生产路径上一个调用点
都没有**。internal/udpflow 是这样（帧格式与会话表全实现，UDP 隧道却被标成
「入口尚未接线」），internal/gateway 也是这样（14 个文件、全套测试，
而 grep 生产代码只匹配到一句注释）。两次都是 README 已经把它列进「已实现」
之后才发现的。

测试全绿证明不了「它被接上了」。一个只被测试引用的导出标识符，
要么是死代码，要么是一条**断了的产品路径** —— 后者更贵：
gateway 的 BindDefault 从未被调用，意味着场景二的设备在共享端口上
匹配不到任何路由，而那是一条明确的场景需求。

# 判据与豁免

判据：一个在 internal/ 下声明的导出函数/方法/类型，在**所有**非测试 .go 文件里
（声明那一行本身、以及整行注释除外）零引用。

**连测试都不引用的也要报。** 第一版只报「只被测试引用」的，理由是
「测试引用说明有人真的写过它」。那条理由站不住：零引用比只被测试引用
**更严重** —— 它连「有人验证过一次」都不成立。而 internal/ 下不存在
外部消费者，所以零引用没有任何正当理由（真要预留就写进 ALLOW 表，
那样至少有一句为什么）。放宽之后立刻多报出 5 条。

同包引用算可达 —— 第一版排除了「声明所在的整个文件」，于是
Dispatch → Deliver 这类同文件内的真实装配被误判成不可达。
判据宁可窄一点：漏掉一条不可达比每次跑出二十条误报好，
因为后者会让人开始习惯性忽略这道门禁。

剩下的误报有两类，都靠豁免表处理而不是放宽判据：
  * 刻意为将来预留的 API
  * **常量与变量不在扫描范围内** —— 只收集 func 与 type。这是刻意的：
    常量数量大、且大量常量本来就只在一处使用，扫进来会淹没真发现。
    代价是「定义了但从没人用」的常量抓不到，而那确实发生过：
    console.CSRFCookieName 定义了、前端也有 readCookie 兜底，
    可服务端从来没下发过那个 Cookie —— 一个看起来存在的安全网其实是空的。
    这类要靠人看，或者靠一条针对性的测试（那条现在有了）。
  * **通过接口被调用**的方法 —— 本脚本按名字匹配，不做类型解析，
    所以 net.Addr.Network() 这种「实现了标准接口、由 stdlib 内部调用」
    的方法看起来像不可达。这是判据的固有盲区，不是可以修掉的 bug：
    要修就得做完整的类型与调用图分析，而那已经是 go/analysis 的活了。

豁免必须写理由。一条没有理由的豁免会在下一次审查时被当成「已确认无害」，
而它可能恰好是又一条断路。

用法：
    python3 scripts/check-unreachable-exports.py
退出码非 0 即发现新的不可达导出。
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 豁免表：名字 → 理由。**每一条都必须有理由。**
ALLOW = {
    # store.Backup **刻意不接**进支持包。
    #
    # 原来这条豁免写的是「支持包会用它导出数据库快照」—— 那是错的，
    # 而且是危险的错：库里有 agent 密钥的**明文**（HMAC 校验需要密钥本身，
    # 见 migrations/00001_init.sql 里 secret 列的注释）、argon2id 口令哈希、
    # 会话与 CSRF 令牌、入网令牌哈希、TURN 长期密钥。
    # 一份 DB 快照就是这台中继的完整沦陷，而支持包的用途恰恰是发给别人看。
    #
    # 留着 Backup 是因为「运维自己备份数据库」是一个真实需求，
    # 只是它不该走支持包那条路（那条路的产物要外发）。
    "Backup": "运维自备份数据库用；**刻意不接**进支持包 —— 库里有 agent 密钥明文与各类令牌，"
              "一份快照就是完整沦陷，而支持包是要外发的",
    # 承载梯级 L2/L3 还没做，Reliable 是给那时的控制台提示用的。
    "Reliable": "L2/L3 承载梯级（README 已列为缺口）落地后，控制台要据此提示「UDP 走可靠流承载」",
    # PROXY protocol：判别器实现了解析，但「信任前置负载均衡」是个部署决定，
    # 目前没有配置入口。这条是**真缺口**，记在 README 里。
    "SetTrustProxyProtocol": "PROXY protocol 的信任开关还没有配置入口（README 已列为缺口）",
    # 场景二独占端口走各自的监听器，共享端口上的「整端口交给一条隧道」
    # 目前没有配置表达（catch_all 覆盖的是「默认落点」，不是「独占」）。
    "BindDedicated": "共享端口上的整端口独占还没有配置表达；独占端口走 exposure=port 的独立监听器",
    # 这些是给测试与将来的其他承载用的构造口子。
    "NewPeekConnSize": "peek 缓冲大小的注入口，生产用 NewPeekConn 的默认值",
    "PortRange": "policy 的端口范围过滤，配置层还没暴露（默认不限端口）",
    "SPKIPin": "从证书算指纹的口子；生产走 SPKIPinBase64",
    "ProofCanonical": "握手证明的规范化输入，由 Auth.Verify 内部使用；导出是为了让测试能逐字节核对",
    "AgentExists": "控制台的 agent 存在性预检，那一屏还没做",
    # 协议层的帧分派器：控制流目前用 switch 直接分派，Dispatcher 是给
    # 将来「按类型注册处理器」用的。它现在是死代码。
    "Dispatcher": "帧分派器目前是死代码 —— 控制流用 switch 直接分派。留着是因为场景三的能力型后端会需要它",
    "NewDispatcher": "同 Dispatcher",
    "UnsupportedPayload": "同 Dispatcher",
    "Delete": "udpflow 表的显式删除；生产靠空闲回收与容量淘汰，删除口子留给将来的「踢掉某条流」",
    "LastFragment": "末片标志的读取器；发送侧写它、接收侧靠 got==TotalLen 判完成，所以读取器暂时只被测试用",
    # 响应位的读取器。写侧 11 处在写它；读侧不需要，因为**每次请求/响应独占
    # 一条流**、且每个响应类型与它的请求类型不同号（HelloOK≠Hello、
    # StreamOK≠StreamOpen、Pong≠Ping），三条请求/响应路径全靠 Header.Type
    # 分派。全仓也没有 corrID→waiter 的等待表，即没有多路复用需要靠响应位消歧。
    "IsResponse": "响应位的读取器；关联靠「一请求一条流 + 响应类型独立编号」而不是这个位，"
                  "所以读取器只被线协议契约测试用（形状同 LastFragment）",
    # 重组缓冲的字节账本唯一的观测窗口。它守的是「重组完成 / 重叠作废 /
    # 超时回收」三条释放路径都要把字节数还回去 —— 不还的后果是
    # 「明明没积压却报缓冲已满」，那才是用户可观察的 bug。
    # 生产遥测走 DatagramEntry.ReassemblyStats（已接线）。
    "Pending": "重组缓冲字节账本的观测窗口，测试靠它守住三条释放路径的字节归还；"
               "生产遥测走 ReassemblyStats 的分项计数",
    # 通过接口被调用，名字扫描看不到（见文件头「固有盲区」）。
    "Network": "net.Addr 接口的实现，由 stdlib 内部调用；名字扫描看不到接口分派",
    # turn.RelayAddressGenerator 的两个方法。我们**主动拒绝** RFC 6062 的
    # TCP 中继分配（pion 给那条路径加了 SO_REUSEPORT，两个客户端的分配会共用
    # 中继端口），所以方法体里连 g.inner 都不再提及 —— 于是名字扫描看不到
    # 它们，而 pion 每次收到 Allocate 请求都会调它们。
    "AllocateListener": "turn.RelayAddressGenerator 接口的实现（拒绝 TCP 分配），由 pion 内部调用",
    "AllocateConn": "同 AllocateListener",
}


def collect_declarations():
    """收集 internal/ 下所有导出的函数、方法与类型。"""
    decls = {}
    for root, _dirs, files in os.walk(os.path.join(REPO, "internal")):
        for f in files:
            if not f.endswith(".go") or f.endswith("_test.go"):
                continue
            path = os.path.join(root, f)
            rel = os.path.relpath(path, REPO)
            for i, line in enumerate(open(path, encoding="utf-8"), 1):
                m = re.match(r"func (?:\([^)]*\) )?([A-Z]\w{3,})\(", line)
                if not m:
                    m = re.match(r"type ([A-Z]\w{3,}) ", line)
                if m:
                    decls.setdefault(m.group(1), []).append((rel, i))
    return decls


# 行首的 // 注释。**必须剔掉**，否则每个导出标识符都因为自己的文档注释
# 而「可达」——「// NoteFailure 记录一次签发失败」这一行就足以让一个
# 零生产调用点的方法通过门禁。
#
# 这个盲区是本脚本第一版的真 bug：它让 acmecert.NoteFailure（失败负缓存的
# 唯一入口，没有它第 ③ 道闸门在生产里根本不会触发）静默通过。
# 判据只排除了「声明那一行」，却没想到文档注释就在声明**上面**一行。
COMMENT = re.compile(r"^\s*//")


def strip_comments(body):
    """把整行注释换成空行（保持行号不变，声明行的定位要用）。"""
    out = []
    for line in body.split("\n"):
        out.append("" if COMMENT.match(line) else line)
    return out


def read_sources():
    """一次读完所有 .go 文件，分成生产与测试两组。"""
    prod, test = {}, {}
    for root, _dirs, files in os.walk(REPO):
        if any(p in root for p in ("/web/node_modules", "/.git", "/bin", "/dist")):
            continue
        for f in files:
            if not f.endswith(".go"):
                continue
            path = os.path.join(root, f)
            rel = os.path.relpath(path, REPO)
            body = open(path, encoding="utf-8", errors="replace").read()
            (test if f.endswith("_test.go") else prod)[rel] = body
    return prod, test


def main():
    decls = collect_declarations()
    prod, test = read_sources()
    # 注释不算调用点。理由见 COMMENT 上面那段。
    prod = {rel: strip_comments(body) for rel, body in prod.items()}

    # 预编译每个名字的词边界正则，然后一次过所有文件。
    findings = []
    for name, locs in sorted(decls.items()):
        if name in ALLOW:
            continue
        pat = re.compile(r"\b" + re.escape(name) + r"\b")
        declines = {(f, ln) for f, ln in locs}
        reachable = False
        for rel, lines in prod.items():
            for i, line in enumerate(lines, 1):
                if (rel, i) in declines:
                    # 只跳过声明那一行本身。同包的其他行算可达 ——
                    # 那是真实的内部装配（Dispatch 调 Deliver 就在同一个文件里）。
                    continue
                if pat.search(line):
                    reachable = True
                    break
            if reachable:
                break

        if reachable:
            continue

        test_hits = sum(1 for body in test.values() if pat.search(body))
        findings.append((name, locs[0], test_hits))

    if not findings:
        print(f"✓ 无不可达导出（扫了 {len(decls)} 个导出标识符，"
              f"{len(ALLOW)} 条显式豁免）")
        return 0

    print("✗ 下面这些导出标识符在生产代码里没有任何调用点：")
    print()
    for name, (f, line), n in findings:
        print(f"  {name}")
        where = f"测试引用 {n} 次" if n else "**连测试都没引用**"
        print(f"      {f}:{line}（{where}）")
    print()
    print("每一条要么是死代码，要么是一条**断了的产品路径**。后者更贵 ——")
    print("gateway 的 BindDefault 就是这样被发现的：它从未被调用，意味着")
    print("场景二的设备在共享端口上匹配不到任何路由。")
    print()
    print("处理方式：接上它，删掉它，或在本脚本的 ALLOW 表里加一条**带理由**的豁免。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
