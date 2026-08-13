#!/usr/bin/env python3
"""验证数据报 MTU 真的从承载走到了 /api/snapshot。

这个值是**反应式**学到的：只有在一次 SendDatagram 超限之后 quic-go 才会
把真实上限带回来。所以这条验证必须真的发一个超大的 UDP 报文过去 ——
只起隧道不打流量的话它恒为 0，而那与「没接线」长得一模一样。
"""
import os
import json, os, re, signal, socket, subprocess, sys, tempfile, time
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
    d = tempfile.mkdtemp(prefix="nfr-mtu-")
    cport, rport, tport = free_port(), free_port(), free_port()

    # UDP 回声后端。
    be = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    be.bind(("127.0.0.1", 0))
    beport = be.getsockname()[1]

    def echo():
        while True:
            try:
                data, addr = be.recvfrom(70000)
                be.sendto(data[:16], addr)
            except OSError:
                return

    import threading
    threading.Thread(target=echo, daemon=True).start()

    for cmd in ("nfrelay", "nfagent"):
        if subprocess.run(["go", "build", "-o", f"{d}/{cmd}", f"./cmd/{cmd}"], cwd=REPO).returncode:
            sys.exit("构建失败")

    procs.append(subprocess.Popen(
        [f"{d}/nfrelay", "-data-dir", f"{d}/data", "-console", f"127.0.0.1:{cport}",
         "-bind", f"127.0.0.1:{rport}"],
        stdout=open(f"{d}/relay.log", "w"), stderr=subprocess.STDOUT, cwd=REPO))
    pin = None
    for _ in range(120):
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
            with urllib.request.urlopen(req, timeout=10) as r:
                for h in r.headers.get_all("Set-Cookie") or []:
                    k, _, v = h.split(";")[0].partition("=")
                    cookies[k] = v
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    call("POST", "/api/setup", {"username": "admin", "password": "a-very-long-password"})
    _, tok = call("POST", "/api/enrol-tokens", {"note": "mtu"})
    procs.append(subprocess.Popen(
        [f"{d}/nfagent", "-relay", f"127.0.0.1:{rport}", "-pin", pin,
         "-token", tok["token"], "-state-dir", f"{d}/as"],
        stdout=open(f"{d}/agent.log", "w"), stderr=subprocess.STDOUT, cwd=REPO))
    for _ in range(120):
        time.sleep(0.25)
        if "已连上中继" in open(f"{d}/agent.log").read():
            break
    else:
        print(open(f"{d}/agent.log").read()); sys.exit("agent 没连上")

    _, tn = call("POST", "/api/tunnels", {
        "slug": "udp-mtu", "l4": "udp", "listen_port": tport,
        "backend": {"kind": "addr", "addr": f"127.0.0.1:{beport}"}})
    tid = tn["id"]
    time.sleep(1.5)

    def mtu_of():
        _, snap = call("GET", "/api/snapshot")
        for t in snap.get("tunnels", []):
            if t["id"] == tid:
                return t.get("dgram_mtu")
        return None

    print("── 还没发过超限报文时 ──")
    before = mtu_of()
    check(before in (None, 0),
          f"MTU 还没学到，如实缺席（{before!r}）—— 0/缺席与「学到了是 0」不需要区分，"
          "载荷上限为 0 不存在")

    print("── 发一个 60000 字节的 UDP 报文（必然超过数据报载荷上限）──")
    cl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cl.settimeout(2)
    for _ in range(4):
        try:
            cl.sendto(b"x" * 60000, ("127.0.0.1", tport))
        except OSError as e:
            print("   （本机 socket 就拒了：", e, "）")
        time.sleep(0.4)

    got = None
    for _ in range(20):
        time.sleep(0.4)
        got = mtu_of()
        if got:
            break
    check(bool(got), f"快照里出现了学到的 MTU：{got!r}")
    if got:
        check(200 < got < 65536, f"取值落在合理区间：{got}")

    print("\n" + ("全部通过" if not fails else f"{len(fails)} 条失败"))
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
        time.sleep(0.4)
        for p in procs:
            try:
                p.kill()
            except Exception:
                pass
    sys.exit(rc)
