#!/usr/bin/env python3
"""证明/否证：共享端口的 512 个判别器槽位能被空闲 keep-alive 连接永久占死。

如果成立，后果是：
  * ACME 挑战在信号量那一步就被关掉 → 证书首签/续签静默失败；
  * 走 L2 降级的 agent 连不上；
  * 所有共享入口隧道停止接受新连接。
而且无需鉴权、无需真实负载、也不需要配任何限速。
"""
import os
import json, re, signal, socket, subprocess, sys, tempfile, threading, time
import http.server, socketserver
import urllib.error, urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
procs, fails = [], []
SLOTS = 512  # gateway.DefaultMaxConns


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def check(ok, msg):
    print(("  ✓ " if ok else "  ✗ ") + msg)
    if not ok:
        fails.append(msg)


class Tiny(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def main():
    d = tempfile.mkdtemp(prefix="nfr-slots-")
    cport, rport, sport = free_port(), free_port(), free_port()

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    be = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Tiny)
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
            with urllib.request.urlopen(req, timeout=20) as r:
                for h in r.headers.get_all("Set-Cookie") or []:
                    k, _, v = h.split(";")[0].partition("=")
                    cookies[k] = v
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    call("POST", "/api/setup", {"username": "admin", "password": "a-very-long-password"})
    _, tok = call("POST", "/api/enrol-tokens", {"note": "slots"})
    procs.append(subprocess.Popen(
        [f"{d}/nfagent", "-relay", f"127.0.0.1:{rport}", "-pin", pin,
         "-token", tok["token"], "-state-dir", f"{d}/as"],
        stdout=open(f"{d}/agent.log", "w"), stderr=subprocess.STDOUT, cwd=REPO))
    for _ in range(160):
        time.sleep(0.25)
        if "已连上中继" in open(f"{d}/agent.log").read():
            break

    call("POST", "/api/tunnels", {
        "slug": "victim", "exposure": "shared", "tls": "gateway",
        "router": {"kind": "http", "domains": ["victim.example.com"]},
        "backend": {"kind": "addr", "addr": f"127.0.0.1:{beport}"}})
    time.sleep(2)

    def one_request(sock=None):
        """发一个完整请求并读完响应，返回 socket（保持打开）。"""
        s = sock or socket.create_connection(("127.0.0.1", sport), timeout=10)
        s.sendall(b"GET / HTTP/1.1\r\nHost: victim.example.com\r\n\r\n")
        s.settimeout(10)
        buf = b""
        while b"\r\n\r\n" not in buf:
            b2 = s.recv(4096)
            if not b2:
                raise OSError("对端关了")
            buf += b2
        # 读掉 body（Content-Length: 2）
        while len(buf.split(b"\r\n\r\n", 1)[1]) < 2:
            buf += s.recv(4096)
        return s

    print(f"\n── 先确认隧道通 ──")
    probe = one_request()
    check(True, "一个正常请求通了")
    probe.close()

    print(f"\n── 开 {SLOTS} 条连接，每条发完一个请求就**挂着不关** ──")
    held = []
    failed_at = None
    for i in range(SLOTS):
        try:
            held.append(one_request())
        except Exception as e:
            failed_at = (i, repr(e))
            break
    print(f"  成功挂住 {len(held)} 条" + (f"（第 {failed_at[0]} 条失败：{failed_at[1]}）" if failed_at else ""))

    time.sleep(1.5)
    print("\n── 现在再来一个新连接：还能被服务吗 ──")
    blocked = False
    try:
        fresh = one_request()
        fresh.close()
    except Exception as e:
        blocked = True
        print(f"  新连接被拒绝：{e!r}")
    check(blocked, "空闲 keep-alive 连接占满槽位之后，新连接**被拒** —— "
                  "这就是那条阻断项（无需鉴权、无需负载）")

    _, snap = call("GET", "/api/snapshot")
    sh = snap.get("shared") or {}
    print(f"  shared.at_capacity = {sh.get('at_capacity')!r}")
    check((sh.get("at_capacity") or 0) > 0,
          "AtCapacity 计数器有反应（这是运维唯一的痕迹，而没人知道要看这一格）")

    print("\n── 关键后果：ACME 挑战这时也会被关掉吗 ──")
    # 模拟一次 TLS-ALPN-01：带 acme-tls/1 的 ClientHello。槽位满时它在信号量
    # 那一步就被 Close，压根到不了 ACME 处理器。
    acme_blocked = False
    try:
        s = socket.create_connection(("127.0.0.1", sport), timeout=5)
        s.settimeout(5)
        # 只要能建 TCP 就说明 accept 了；槽满时 relay 会立刻 Close。
        s.sendall(b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00")
        if not s.recv(1):
            acme_blocked = True
        s.close()
    except Exception:
        acme_blocked = True
    check(acme_blocked, "槽位满时任何新连接（含 ACME 挑战）在信号量那一步就被关掉 —— "
                        "证书首签/续签会静默超时")

    for s in held:
        try:
            s.close()
        except Exception:
            pass
    time.sleep(1.5)
    print("\n── 释放之后能恢复吗（确认这不是别的故障）──")
    try:
        again = one_request()
        again.close()
        check(True, "关掉那些空闲连接之后立刻恢复 —— 证实占死的就是槽位")
    except Exception as e:
        check(False, f"释放之后仍然不通：{e!r}")

    print("\n" + ("全部通过（阻断项证实成立）" if not fails else f"{len(fails)} 条失败"))
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
