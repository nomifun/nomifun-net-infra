#!/usr/bin/env python3
"""学习模式的真实进程验证：真中继 + 真 agent + 真后端 + 真 HTTP 流量。

单元测试证明各个零件对，只有这里能证明「一条隧道上打过流量之后，
观测列表里真的出现了那个地址，而一键收窄真的改了策略且流量还通」。
"""
import http.server
import json
import os
import random
import re
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
procs = []
fails = []


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def check(ok, msg):
    print(("  ✓ " if ok else "  ✗ ") + msg)
    if not ok:
        fails.append(msg)


def cleanup():
    for p in procs:
        try:
            p.send_signal(signal.SIGTERM)
        except Exception:
            pass
    time.sleep(0.4)
    for p in procs:
        try:
            p.kill()
        except Exception:
            pass


class Backend(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


def main():
    d = tempfile.mkdtemp(prefix="nfr-learn-")
    cport, rport, tport = free_port(), free_port(), free_port()

    socketserver.TCPServer.allow_reuse_address = True
    be = socketserver.TCPServer(("127.0.0.1", 0), Backend)
    beport = be.server_address[1]
    threading.Thread(target=be.serve_forever, daemon=True).start()
    print(f"后端 127.0.0.1:{beport}｜控制台 {cport}｜承载 {rport}｜隧道 {tport}")

    for cmd in ("nfrelay", "nfagent"):
        r = subprocess.run(["go", "build", "-o", f"{d}/{cmd}", f"./cmd/{cmd}"], cwd=REPO)
        if r.returncode:
            sys.exit("构建失败")

    rlog = open(f"{d}/relay.log", "w+")
    procs.append(subprocess.Popen(
        [f"{d}/nfrelay", "-data-dir", f"{d}/data", "-console", f"127.0.0.1:{cport}",
         "-bind", f"127.0.0.1:{rport}"], stdout=rlog, stderr=subprocess.STDOUT, cwd=REPO))

    pin = None
    for _ in range(120):
        time.sleep(0.25)
        txt = open(f"{d}/relay.log").read()
        m = re.search(r"证书指纹：(\S+)", txt)
        if m:
            pin = m.group(1)
            break
    if not pin:
        print(open(f"{d}/relay.log").read())
        sys.exit("中继没起来")

    base = f"http://127.0.0.1:{cport}"
    cookies = {}

    def call(method, path, body=None, expect=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("Origin", base)
        if cookies:
            req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))
        if "nfr_csrf" in cookies:
            req.add_header("X-NFR-CSRF", cookies["nfr_csrf"])
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                for h in r.headers.get_all("Set-Cookie") or []:
                    k, _, v = h.split(";")[0].partition("=")
                    cookies[k] = v
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    call("POST", "/api/setup", {"username": "admin", "password": "a-very-long-password"})
    _, tok = call("POST", "/api/enrol-tokens", {"note": "learn"})

    alog = open(f"{d}/agent.log", "w+")
    procs.append(subprocess.Popen(
        [f"{d}/nfagent", "-relay", f"127.0.0.1:{rport}", "-pin", pin,
         "-token", tok["token"], "-state-dir", f"{d}/as"],
        stdout=alog, stderr=subprocess.STDOUT, cwd=REPO))
    for _ in range(120):
        time.sleep(0.25)
        if "已连上中继" in open(f"{d}/agent.log").read():
            break
    else:
        print(open(f"{d}/agent.log").read())
        sys.exit("agent 没连上")

    _, tn = call("POST", "/api/tunnels", {
        "slug": "learn-me", "listen_port": tport,
        "backend": {"kind": "addr", "addr": f"127.0.0.1:{beport}"}})
    tid = tn["id"]

    def hit(n=1):
        codes = []
        for _ in range(n):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{tport}/", timeout=3) as r:
                    codes.append(r.status)
            except Exception as e:
                codes.append(type(e).__name__)
        return codes

    for _ in range(60):
        time.sleep(0.25)
        if hit(1) == [200]:
            break
    else:
        sys.exit("隧道一直不通，无法验证学习模式")

    def learned():
        return call("GET", f"/api/tunnels/{tid}/learned-sources")[1]

    print("\n── 一条从没有流量的隧道 ──")
    #
    # 不能用上面那条来验：为了确认隧道通，前面已经打过一次探测流量，
    # 而那一次已经被观测到了（第一版这里就是这么错的，hits 比预期多 1）。
    # 「没有任何观测」这个状态必须在一条**真的没人连过**的隧道上验。
    _, quiet = call("POST", "/api/tunnels", {
        "slug": "never-touched", "listen_port": free_port(),
        "backend": {"kind": "addr", "addr": f"127.0.0.1:{beport}"}})
    st, pre = call("GET", f"/api/tunnels/{quiet['id']}/learned-sources")
    check(st == 200, f"没有观测时回 200 而不是 404（{st}）")
    check(pre.get("sources") == [], f"sources 是空数组而不是 null（前端会在 null 上炸）：{pre.get('sources')!r}")
    check(pre.get("observed_from", "").startswith("0001-"),
          "观测起点是零值 —— 界面据此说「还没观测到任何来源」而不是编一个时间")

    print("\n── 打 6 次真流量 ──")
    codes = hit(6)
    check(all(c == 200 for c in codes), f"流量全通：{codes}")
    time.sleep(0.6)

    got = learned()
    print("  " + json.dumps(got, ensure_ascii=False))
    cidrs = [s["cidr"] for s in got["sources"]]
    check(len(cidrs) >= 1, f"观测到了来源：{cidrs}")
    check("127.0.0.1/32" in cidrs, "回环被记成 127.0.0.1/32（滤掉它会让本机部署下这个功能永远为空）")
    entry = next((s for s in got["sources"] if s["cidr"] == "127.0.0.1/32"), None)
    check(entry and entry["hits"] >= 6, f"命中次数累加了：{entry and entry['hits']}")
    check(not got["truncated"], "没有被截断")
    check(not got["observed_from"].startswith("0001-"), "观测起点是真实时间")

    print("\n── 三条拒绝路径 ──")
    st, b = call("POST", f"/api/tunnels/{tid}:apply-learned", {"cidrs": []})
    check(st == 400 and b.get("code") == "nothing_selected",
          f"显式空数组被拒（{st} {b.get('code')}）—— 不能被当成「全选」")
    st, b = call("POST", f"/api/tunnels/{tid}:apply-learned", {"cidrs": ["8.8.8.8/32"]})
    check(st == 400 and b.get("code") == "not_observed",
          f"没观测过的前缀被拒（{st} {b.get('code')}）")
    st, b = call("POST", f"/api/tunnels/{tid}:apply-learned", {"cidrs": ["203.0.113.0/24"]})
    check(st == 400, f"聚合过的网段也被拒（{st}）—— 只能应用逐字观测到的前缀")

    print("\n── 一键收窄 ──")
    st, b = call("POST", f"/api/tunnels/{tid}:apply-learned", {"cidrs": ["127.0.0.1/32"]})
    tun = b if "policy" in (b or {}) else (b or {}).get("tunnel", {})
    allow = (tun.get("policy") or {}).get("allow_cidrs") or []
    check(st == 200 and allow == ["127.0.0.1/32"], f"策略写下去了：{st} {allow}")

    # 落库了吗（而不是只在响应里）
    _, fresh = call("GET", f"/api/tunnels/{tid}")
    check(((fresh.get("policy") or {}).get("allow_cidrs") or []) == ["127.0.0.1/32"],
          "重新 GET 也是这个策略（真的落库了）")

    time.sleep(1.2)
    codes = hit(3)
    check(all(c == 200 for c in codes), f"收窄之后我们放行的来源仍然通：{codes}")

    print("\n── 幂等 ──")
    st, b = call("POST", f"/api/tunnels/{tid}:apply-learned", {"cidrs": ["127.0.0.1/32"]})
    check(st == 200 and b.get("added") == 0,
          f"再来一次报「没有需要新增的」而不是假装改了：{st} {b.get('added')}")

    print("\n── 拒绝提示 ──")
    st, _ = call("POST", f"/api/tunnels/{tid}:decline-learned", None)
    check(st == 200 and learned()["declined"], "declined 记住了")
    _, after = call("GET", f"/api/tunnels/{tid}")
    check(((after.get("policy") or {}).get("allow_cidrs") or []) == ["127.0.0.1/32"],
          "「保持开放」没有改动策略")

    print("\n── 审计事件 ──")
    _, evs = call("GET", "/api/events/recent?limit=20")
    narrow = [e for e in (evs or []) if "学习模式" in (e.get("message") or "")]
    check(len(narrow) >= 1, f"收窄留了痕：{[e['message'] for e in narrow]}")
    check(all("127.0.0.1" not in (e.get("message") or "") for e in narrow),
          "事件文案里**不含**观测到的地址（事件表会被支持包外发）")
    check(all(e.get("actor") for e in narrow), "事件带操作者")

    print("\n── 支持包里不能出现观测到的地址 ──")
    req = urllib.request.Request(base + "/api/diagnostics/support-bundle")
    req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))
    with urllib.request.urlopen(req, timeout=15) as r:
        bundle = r.read().decode()
    # allow_cidrs 是用户**自己选定的配置**，不在支持包的隧道摘要里；
    # 而观测列表本身绝不该出现在任何外发文件里。
    check('"sources"' not in bundle, "支持包里没有观测列表")
    check("first_seen" not in bundle, "支持包里没有观测时间戳")

    print("\n" + ("全部通过" if not fails else f"{len(fails)} 条失败：\n  - " + "\n  - ".join(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    try:
        rc = main()
    finally:
        cleanup()
    sys.exit(rc)
