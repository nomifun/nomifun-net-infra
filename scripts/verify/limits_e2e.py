#!/usr/bin/env python3
"""共享入口每隧道限额的真实进程验证。

单元测试证明零件对，只有这里能证明「用户在控制台上给一条共享入口隧道配了
限速，它真的被限住了」—— 那正是这个缺口的原始现象（配了 1 Mbps 照样跑满）。

三件事分别验：
  1. 共享入口（网关路径）上 bytes_per_second 真的生效；
  2. max_conns 真的拒；
  3. **改一条已上线隧道的带宽，不重启就生效** —— 这一条此前是假话
     （entry.go 的注释声称走重建入口，而 ApplyTunnels 对已存在的入口直接跳过）。
"""
import os
import json, re, signal, socket, subprocess, sys, tempfile, threading, time
import http.server, socketserver
import urllib.error, urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
procs, fails = [], []


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def check(ok, msg):
    print(("  ✓ " if ok else "  ✗ ") + msg)
    if not ok:
        fails.append(msg)


class Bulk(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        n = 768 * 1024
        self.send_response(200)
        self.send_header("Content-Length", str(n))
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        chunk = b"x" * (32 * 1024)
        left = n
        try:
            while left > 0:
                k = min(left, len(chunk))
                self.wfile.write(chunk[:k])
                left -= k
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *a):
        pass


def main():
    d = tempfile.mkdtemp(prefix="nfr-lim-")
    cport, rport, sport, pport = free_port(), free_port(), free_port(), free_port()

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    be = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Bulk)
    beport = be.server_address[1]
    threading.Thread(target=be.serve_forever, daemon=True).start()

    for cmd in ("nfrelay", "nfagent"):
        if subprocess.run(["go", "build", "-o", f"{d}/{cmd}", f"./cmd/{cmd}"], cwd=REPO).returncode:
            sys.exit("构建失败")

    procs.append(subprocess.Popen(
        [f"{d}/nfrelay", "-data-dir", f"{d}/data", "-console", f"127.0.0.1:{cport}",
         "-bind", f"127.0.0.1:{rport}", "-shared", f"127.0.0.1:{sport}"],
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
            with urllib.request.urlopen(req, timeout=30) as r:
                for h in r.headers.get_all("Set-Cookie") or []:
                    k, _, v = h.split(";")[0].partition("=")
                    cookies[k] = v
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    call("POST", "/api/setup", {"username": "admin", "password": "a-very-long-password"})
    _, tok = call("POST", "/api/enrol-tokens", {"note": "lim"})
    procs.append(subprocess.Popen(
        [f"{d}/nfagent", "-relay", f"127.0.0.1:{rport}", "-pin", pin,
         "-token", tok["token"], "-state-dir", f"{d}/as"],
        stdout=open(f"{d}/agent.log", "w"), stderr=subprocess.STDOUT, cwd=REPO))
    for _ in range(160):
        time.sleep(0.25)
        if "已连上中继" in open(f"{d}/agent.log").read():
            break
    else:
        print(open(f"{d}/agent.log").read()); sys.exit("agent 没连上")

    RATE = 256 * 1024
    _, shared = call("POST", "/api/tunnels", {
        "slug": "shared-lim", "exposure": "shared", "tls": "gateway",
        "router": {"kind": "http", "domains": ["lim.example.com"]},
        "backend": {"kind": "addr", "addr": f"127.0.0.1:{beport}"},
        "policy": {"bytes_per_second": RATE}})
    _, plain = call("POST", "/api/tunnels", {
        "slug": "shared-free", "exposure": "shared", "tls": "gateway",
        "router": {"kind": "http", "domains": ["free.example.com"]},
        "backend": {"kind": "addr", "addr": f"127.0.0.1:{beport}"}})
    # 独立端口隧道，用来验「改带宽不重启就生效」。
    _, port_tn = call("POST", "/api/tunnels", {
        "slug": "port-lim", "listen_port": pport,
        "backend": {"kind": "addr", "addr": f"127.0.0.1:{beport}"},
        "policy": {"bytes_per_second": 8 * 1024 * 1024}})
    time.sleep(2)

    def fetch_shared(host):
        req = urllib.request.Request(f"http://127.0.0.1:{sport}/big")
        req.add_header("Host", host)
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=120) as r:
            n = 0
            while True:
                b = r.read(65536)
                if not b:
                    break
                n += len(b)
        return n, time.time() - t0

    print("\n── ① 共享入口上 bytes_per_second 真的生效吗 ──")
    nf, tf = fetch_shared("free.example.com")
    check(nf == 768 * 1024, f"不限速的那条隧道通了 {nf} 字节，耗时 {tf:.2f}s")
    nl, tl = fetch_shared("lim.example.com")
    check(nl == 768 * 1024, f"限速的那条隧道**一个字节都不少**：{nl}")
    check(tl >= 1.0, f"768 KiB 过 256 KiB/s 耗时 {tl:.2f}s（不限速 {tf:.2f}s）—— "
                     "共享入口上的限速真的生效了")

    print("\n── ② max_conns 真的拒吗 ──")
    call("PUT", f"/api/tunnels/{shared['id']}", {
        "slug": "shared-lim", "exposure": "shared", "tls": "gateway",
        "router": {"kind": "http", "domains": ["lim.example.com"]},
        "backend": {"kind": "addr", "addr": f"127.0.0.1:{beport}"},
        "policy": {"bytes_per_second": RATE, "max_conns": 1}})
    time.sleep(1.5)
    codes, lock = [], threading.Lock()

    def hit():
        req = urllib.request.Request(f"http://127.0.0.1:{sport}/big")
        req.add_header("Host", "lim.example.com")
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                r.read()
                with lock:
                    codes.append(200)
        except urllib.error.HTTPError as e:
            with lock:
                codes.append(e.code)
        except Exception:
            with lock:
                codes.append(-1)

    ts = [threading.Thread(target=hit) for _ in range(4)]
    for x in ts:
        x.start()
    for x in ts:
        x.join()
    check(503 in codes, f"并发 4 个请求、上限 1，有请求被拒：{codes}")
    _, snap = call("GET", "/api/snapshot")
    sh = snap.get("shared") or {}
    check(sh.get("gateway_denied_max_conns", 0) >= 1,
          f"快照里的 gateway_denied_max_conns = {sh.get('gateway_denied_max_conns')!r}")

    print("\n── ③ 改一条已上线独立端口隧道的带宽，不重启就生效吗 ──")
    def fetch_port():
        t0 = time.time()
        with urllib.request.urlopen(f"http://127.0.0.1:{pport}/big", timeout=120) as r:
            n = 0
            while True:
                b = r.read(65536)
                if not b:
                    break
                n += len(b)
        return n, time.time() - t0

    n0, t0 = fetch_port()
    check(n0 == 768 * 1024, f"8 Mbps 下通了 {n0} 字节，耗时 {t0:.2f}s")
    call("PUT", f"/api/tunnels/{port_tn['id']}", {
        "slug": "port-lim", "listen_port": pport,
        "backend": {"kind": "addr", "addr": f"127.0.0.1:{beport}"},
        "policy": {"bytes_per_second": RATE}})
    time.sleep(1.5)
    n1, t1 = fetch_port()
    check(n1 == 768 * 1024, f"改带宽之后仍然一个字节都不少：{n1}")
    check(t1 >= 1.0, f"改成 256 KiB/s 之后耗时 {t1:.2f}s（改之前 {t0:.2f}s）—— "
                     "**不重启就生效**（此前这需要重启，而界面显示「已设置」）")

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
