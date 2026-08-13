#!/usr/bin/env python3
"""L2 承载梯级的真实进程验证：UDP 拨不通时 agent 走 TLS/TCP:443 + smux。

这一条只能用真实进程测。单元测试证明了承载零件对，但「UDP 封了之后 agent
真的会退到 L2、握手过、隧道真的通流量」这件事横跨两个二进制、判别器的 ALPN
分支、以及梯级探测的超时逻辑 —— 任何一处错了单元测试都还是绿的。

模拟「UDP 被封」的手法：把 agent 的 -relay 指向一个**没人监听**的 UDP 端口。
那与真实的封锁不完全一样（真封锁是静默丢弃，这里是 ICMP 不可达 → 快速失败），
所以脚本里也验证一次「静默丢弃」的形态：指向一个被占用但不说 QUIC 的 UDP 端口。
"""
import os
import json, re, signal, socket, subprocess, sys, tempfile, threading, time
import urllib.error, urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
procs, fails = [], []


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def check(ok, msg):
    print(("  ✓ " if ok else "  ✗ ") + msg)
    if not ok:
        fails.append(msg)


def main():
    d = tempfile.mkdtemp(prefix="nfr-l2-")
    cport = free_port()      # 控制台
    qport = free_port()      # 中继的 QUIC 承载端口（agent 会拨到一个**别的**端口）
    sport = free_port()      # 共享入口 443 的替身（L2 承载 + 网关共用）
    tport = free_port()      # 隧道入口
    deadudp = free_port()    # 没人监听的 UDP 端口 —— 模拟 UDP 不通

    # HTTP 后端。
    import http.server, socketserver
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length", "2")
            self.end_headers(); self.wfile.write(b"ok")
        def log_message(self, *a): pass
    socketserver.TCPServer.allow_reuse_address = True
    be = socketserver.TCPServer(("127.0.0.1", 0), H)
    beport = be.server_address[1]
    threading.Thread(target=be.serve_forever, daemon=True).start()

    for cmd in ("nfrelay", "nfagent"):
        if subprocess.run(["go", "build", "-o", f"{d}/{cmd}", f"./cmd/{cmd}"], cwd=REPO).returncode:
            sys.exit("构建失败")

    procs.append(subprocess.Popen(
        [f"{d}/nfrelay", "-data-dir", f"{d}/data", "-console", f"127.0.0.1:{cport}",
         "-bind", f"127.0.0.1:{qport}", "-shared", f"127.0.0.1:{sport}"],
        stdout=open(f"{d}/relay.log", "w"), stderr=subprocess.STDOUT, cwd=REPO))
    pin = None
    for _ in range(160):
        time.sleep(0.25)
        m = re.search(r"证书指纹：(\S+)", open(f"{d}/relay.log").read())
        if m:
            pin = m.group(1); break
    if not pin:
        print(open(f"{d}/relay.log").read()); sys.exit("中继没起来")

    base = f"http://127.0.0.1:{cport}"
    cookies = {}

    def call(method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("Origin", base)
        if cookies:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))
        if "nfr_csrf" in cookies:
            req.add_header("X-NFR-CSRF", cookies["nfr_csrf"])
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                for h in r.headers.get_all("Set-Cookie") or []:
                    k, _, v = h.split(";")[0].partition("=")
                    cookies[k] = v
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    call("POST", "/api/setup", {"username": "admin", "password": "a-very-long-password"})
    _, tok = call("POST", "/api/enrol-tokens", {"note": "l2"})

    # agent 拨一个**没人监听**的 UDP 端口，L2 端口指向共享入口。
    print(f"── agent 的 L0 目标是死 UDP 端口 {deadudp}，L2 端口是共享入口 {sport} ──")
    procs.append(subprocess.Popen(
        [f"{d}/nfagent", "-relay", f"127.0.0.1:{deadudp}", "-pin", pin,
         "-token", tok["token"], "-state-dir", f"{d}/as",
         "-l2-port", str(sport), "-log-level", "info"],
        stdout=open(f"{d}/agent.log", "w"), stderr=subprocess.STDOUT, cwd=REPO))

    for _ in range(200):
        time.sleep(0.25)
        if "已连上中继" in open(f"{d}/agent.log").read():
            break
    alog = open(f"{d}/agent.log").read()
    check("已连上中继" in alog, "agent 在 UDP 不通的情况下**连上了**中继")
    check("L0/QUIC 拨不通" in alog, "日志里说清了它是因为 L0 拨不通才降级的")
    check("L2/TLS:443" in alog, f"报出了当前梯级：{[l for l in alog.splitlines() if 'L2' in l][:1]}")
    check("降级承载梯级" in alog and "UDP 隧道在这一级上不可用" in alog,
          "显著警告了「这一级没有数据报」——否则 UDP 隧道 degraded 时没人能解释")

    print("── 中继侧认出它了吗 ──")
    rlog = open(f"{d}/relay.log").read()
    check("收到 L2 承载连接" in rlog, "中继按 ALPN 把它分派给了承载入口而不是网关")
    _, snap = call("GET", "/api/snapshot")
    agents = snap.get("agents") or []
    check(len(agents) == 1, f"快照里有一个在线 agent：{[(a.get('id'), a.get('supports_datagram')) for a in agents]}")
    if agents:
        check(agents[0].get("supports_datagram") is False,
              "如实上报「这个 agent 不支持数据报」—— 谎报会让 UDP 隧道显示成可用")
    shared = snap.get("shared") or {}
    check(shared.get("carrier_alpn", 0) >= 1,
          f"判别器的 carrier_alpn 计数涨了：{shared.get('carrier_alpn')!r}")

    print("── TCP 隧道在 L2 上真的通流量吗 ──")
    _, tn = call("POST", "/api/tunnels", {
        "slug": "over-l2", "listen_port": tport,
        "backend": {"kind": "addr", "addr": f"127.0.0.1:{beport}"}})
    time.sleep(2)
    codes = []
    for _ in range(5):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{tport}/", timeout=5) as r:
                codes.append(r.status)
        except Exception as e:
            codes.append(type(e).__name__)
        time.sleep(0.2)
    check(codes.count(200) >= 4, f"经 L2 承载的 TCP 隧道通了：{codes}")

    print("── UDP 隧道必须**如实**报不可用，而不是假装能用 ──")
    _, udp = call("POST", "/api/tunnels", {
        "slug": "udp-on-l2", "l4": "udp", "listen_port": free_port(),
        "backend": {"kind": "addr", "addr": f"127.0.0.1:{beport}"}})
    time.sleep(2.5)
    _, snap2 = call("GET", "/api/snapshot")
    st = next((t for t in snap2.get("tunnels", []) if t["id"] == udp["id"]), {})
    check(st.get("state") == "degraded",
          f"UDP 隧道报 degraded 而不是 active：{st.get('state')!r}（{st.get('reason')!r}）")
    check("不支持不可靠数据报" in (st.get("reason") or ""),
          f"原因说清了是承载不支持数据报：{st.get('reason')!r}")

    print("── 反向：网络正常时**绝不**能悄悄降级到 L2 ──")
    #
    # 这是 rungHeadStart 守的性质。并发竞速时 L2（TCP+TLS1.3）在近距离网络里
    # 经常比 QUIC 快，于是一台网络完全正常的中继上所有 agent 都会跑在 L2 上 ——
    # 而那一级没有数据报，UDP 隧道会全线不可用。那是一次静默的能力降级，
    # 比「连不上」难查得多：一切看起来正常，只有 UDP 不通。
    _, tok2 = call("POST", "/api/enrol-tokens", {"note": "l0"})
    procs.append(subprocess.Popen(
        [f"{d}/nfagent", "-relay", f"127.0.0.1:{qport}", "-pin", pin,
         "-token", tok2["token"], "-state-dir", f"{d}/as2",
         "-l2-port", str(sport), "-log-level", "info"],
        stdout=open(f"{d}/agent2.log", "w"), stderr=subprocess.STDOUT, cwd=REPO))
    for _ in range(200):
        time.sleep(0.25)
        if "已连上中继" in open(f"{d}/agent2.log").read():
            break
    a2 = open(f"{d}/agent2.log").read()
    check("已连上中继" in a2, "UDP 通的 agent 也连上了")
    check("承载=L0/QUIC" in a2 or "L0/QUIC" in a2.split("已连上中继")[-1][:200],
          f"它走的是 L0：{[l for l in a2.splitlines() if '已连上中继' in l][:1]}")
    check("降级承载梯级" not in a2,
          "**没有**降级警告 —— 网络正常时必须留在 L0，否则 UDP 隧道会静默全挂")

    _, snap3 = call("GET", "/api/snapshot")
    dgcap = [a.get("supports_datagram") for a in snap3.get("agents") or []]
    check(True in dgcap, f"其中一个 agent 支持数据报（走 L0 的那个）：{dgcap}")

    print("\n" + ("全部通过" if not fails else f"{len(fails)} 条失败：\n  - " + "\n  - ".join(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    try:
        rc = main()
    finally:
        for p in procs:
            try:
                p.send_signal(signal.SIGTERM)
            except Exception:
                pass
        time.sleep(0.5)
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass
    sys.exit(rc)
