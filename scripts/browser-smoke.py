#!/usr/bin/env python3
"""控制台的真实浏览器冒烟测试。

# 为什么需要它

严格的 TypeScript 类型检查证明不了「首屏真的渲染出来了」：hook 顺序错误、
一个 undefined 的默认导出、CSP 挡掉的脚本、Arco 的 Provider 缺失 ——
这些都只在浏览器里执行时才暴露，而它们的表现是一个**白屏**。

本环境的 `firefox --headless --screenshot` 会挂死（snap 沙箱所致），
但 `firefox.geckodriver` + WebDriver 协议是另一条代码路径，可用。

用法：
    python3 scripts/browser-smoke.py http://127.0.0.1:19470 [截图目录]

退出码非 0 即失败，并打印页面上的控制台错误与 DOM 概要。
"""

import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

DRIVER_PORT = 4455
DRIVER_URL = f"http://127.0.0.1:{DRIVER_PORT}"


def rq(method, path, body=None, timeout=30):
    """向 geckodriver 发一个请求。"""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        DRIVER_URL + path, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"WebDriver {method} {path} 失败：{e.read().decode()[:500]}") from e


def start_driver():
    env = dict(os.environ)
    # snap 版 firefox 需要一个可写的 HOME，否则 profile 创建失败。
    env["HOME"] = "/tmp/ffhome"
    os.makedirs("/tmp/ffhome", exist_ok=True)
    p = subprocess.Popen(
        ["firefox.geckodriver", "--port", str(DRIVER_PORT), "--host", "127.0.0.1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
    )
    for _ in range(50):
        try:
            if rq("GET", "/status", timeout=2)["value"]["ready"]:
                return p
        except Exception:
            time.sleep(0.2)
    p.kill()
    raise RuntimeError("geckodriver 未就绪")


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:19470"
    shots = sys.argv[2] if len(sys.argv) > 2 else "/tmp/console-shots"
    os.makedirs(shots, exist_ok=True)

    driver = start_driver()
    session = None
    failures = []

    def check(name, ok, detail=""):
        mark = "✓" if ok else "✗"
        print(f"  {mark} {name}" + (f" — {detail}" if detail else ""))
        if not ok:
            failures.append(f"{name}: {detail}")

    try:
        session = rq("POST", "/session", {
            "capabilities": {"alwaysMatch": {
                "moz:firefoxOptions": {"args": ["-headless", "-width=1440", "-height=900"]},
                # 页面加载策略用 normal：我们要等资源真的加载完，
                # 否则截图可能拍到一个还没执行 JS 的空壳。
                "pageLoadStrategy": "normal",
            }}
        }, timeout=60)["value"]["sessionId"]
        sid = f"/session/{session}"

        rq("POST", sid + "/window/rect", {"width": 1440, "height": 900, "x": 0, "y": 0})

        def goto(url):
            rq("POST", sid + "/url", {"url": url}, timeout=45)

        def js(script, args=None):
            return rq("POST", sid + "/execute/sync",
                      {"script": script, "args": args or []}, timeout=30)["value"]

        # 浏览器自己的脚本超时默认 30 秒，且与 HTTP 客户端的 timeout 无关 ——
        # 只调后者会让请求先被浏览器判超时，报出一个与真实原因无关的
        # "script timeout"。两个都要设。
        rq("POST", sid + "/timeouts", {"script": 20000}, timeout=15)

        def js_async(script, args=None):
            """跑一段以 done(...) 结束的异步脚本（fetch 之类要用它）。"""
            return rq("POST", sid + "/execute/async",
                      {"script": script, "args": args or []}, timeout=45)["value"]

        def shot(name):
            b64 = rq("GET", sid + "/screenshot", timeout=30)["value"]
            path = os.path.join(shots, name + ".png")
            with open(path, "wb") as f:
                f.write(base64.b64decode(b64))
            return path

        # 在导航前装一个错误收集器，这样首屏的异常也能被抓到。
        # 注意：execute/sync 在导航后会丢失，所以每次导航后重装。
        collector = """
            window.__errs = window.__errs || [];
            if (!window.__hooked) {
              window.__hooked = true;
              window.addEventListener('error', e =>
                window.__errs.push('error: ' + (e.message || String(e.error))));
              window.addEventListener('unhandledrejection', e =>
                window.__errs.push('unhandled: ' + String(e.reason)));
              const ce = console.error;
              console.error = function (...a) {
                window.__errs.push('console.error: ' + a.map(String).join(' '));
                ce.apply(console, a);
              };
            }
            return true;
        """

        print("\n【1】首屏渲染")
        goto(base + "/")
        js(collector)
        # 等 React 挂载：轮询根节点是否有子元素。
        mounted = False
        for _ in range(60):
            n = js("const r=document.getElementById('root');return r?r.children.length:0")
            if n and n > 0:
                mounted = True
                break
            time.sleep(0.25)
        check("React 挂载（#root 有子节点）", mounted,
              "" if mounted else "根节点始终为空 —— 这就是白屏")

        title = js("return document.title")
        check("页面标题", title == "NomiRelay", f"title={title!r}")

        text = js("return document.body.innerText.slice(0, 4000)") or ""
        check("页面有可见文字", len(text.strip()) > 20, f"{len(text.strip())} 字符")

        # 首启未完成时应当落到 /setup。
        url_now = js("return location.pathname")
        check("首启引导重定向到 /setup", url_now.startswith("/setup"), f"path={url_now}")

        errs = js("return window.__errs || []") or []
        check("首屏无 JS 错误", len(errs) == 0, "; ".join(errs[:3]))
        print(f"     截图 → {shot('01-setup')}")

        # ── CSP 必须真的落在 index.html 上，而且必须真的在拦 ────────────
        #
        # 这一段抓的是一个曾经存在过的洞：安全头只包在控制台 API 那层
        # （cons.Handler()），而 `/` 是在它外面的 web.AssetHandler。
        # 结果 CSP 与 frame-ancestors 'none' 只装饰 JSON 响应，
        # 而**唯一真的加载脚本、唯一能被 iframe 套的** index.html
        # 一个安全头都没有。
        #
        # 为什么不靠「收集 CSP 违规事件」来判：securitypolicyviolation 要在
        # 资源被拦之前就注册好监听器，而 WebDriver 只能在导航之后注入脚本 ——
        # 首屏那次拦截根本收不到。所以这里改成**主动探一次**：
        # 自己塞一个内联 <script> 进去，它必须被拦下来。
        # 这条判据同时否掉两种坏改法：头没下发（内联脚本会执行），
        # 以及有人往 script-src 加了 'unsafe-inline'（同样会执行）。
        hdr = js_async("""
            const done = arguments[0];
            fetch('/', {cache: 'no-store'}).then(r => done({
              csp: r.headers.get('content-security-policy') || '',
              xfo: r.headers.get('x-frame-options') || '',
              nosniff: r.headers.get('x-content-type-options') || '',
            })).catch(e => done({csp: 'ERR ' + e, xfo: '', nosniff: ''}));
        """) or {}
        check("index.html 自己带 CSP（不只是 JSON 带）",
              "frame-ancestors 'none'" in (hdr.get("csp") or ""),
              f"CSP={hdr.get('csp')!r}")
        check("index.html 带 X-Frame-Options: DENY",
              hdr.get("xfo") == "DENY", f"XFO={hdr.get('xfo')!r}")
        check("index.html 带 nosniff",
              hdr.get("nosniff") == "nosniff", f"={hdr.get('nosniff')!r}")

        blocked = js("""
            window.__cspHit = [];
            document.addEventListener('securitypolicyviolation',
              e => window.__cspHit.push(e.violatedDirective || e.effectiveDirective));
            window.__inlineRan = false;
            const s = document.createElement('script');
            s.textContent = 'window.__inlineRan = true';
            document.head.appendChild(s);
            s.remove();
            return {ran: window.__inlineRan, hits: window.__cspHit};
        """) or {}
        check("内联脚本被 CSP 拦掉（说明 CSP 真的在这一页生效）",
              blocked.get("ran") is False,
              "" if blocked.get("ran") is False else
              "内联脚本执行了 —— 这一页没有 CSP，或 script-src 放开了 'unsafe-inline'"
              f"（收到的违规指令：{blocked.get('hits')}）")

        # 反过来也要测：CSP **不能**严到把控制台自己拦死。
        # index.html 里有一段内联 <style> 把 html/body/#root 撑满高度，
        # 它需要 style-src 的 'unsafe-inline'。少了它页面不会白屏、
        # 不会报错，只会**布局塌掉** —— 高度归零、底色没了。
        # 这种「不报错的坏」只有量一次实际盒子才看得见。
        layout = js("""
            const r = document.getElementById('root');
            return {
              rootH: r ? r.getBoundingClientRect().height : 0,
              bodyH: document.body.getBoundingClientRect().height,
            };
        """) or {}
        check("index.html 的内联 <style> 生效（style-src 没被收死）",
              (layout.get("rootH") or 0) > 100,
              f"#root 高 {layout.get('rootH')}px，body 高 {layout.get('bodyH')}px")

        print("\n【2】中文渲染与主题")
        has_cjk = js(r"return /[一-鿿]/.test(document.body.innerText)")
        check("界面渲染中文（zh-CN 为源语言）", bool(has_cjk))
        theme = js("return document.documentElement.getAttribute('data-theme')")
        check("主题属性已在首帧前落定", theme in ("light", "dark"), f"data-theme={theme!r}")
        arco = js("return !!document.querySelector('[class*=arco-]')")
        check("Arco 组件已挂载", bool(arco))

        print("\n【3】走完首启表单")
        # 先确认这台中继**确实**还没首启过。
        #
        # 不确认的话本节全是假阳性：判据是 needs_setup === false，
        # 而在一台已完成首启的中继上这个条件本来就成立 —— 即使表单
        # 什么都没做也会绿。我拿一个复用过的数据目录跑时就这样被骗了一次，
        # 还顺着假信号去查了半天产品。
        needs_setup = None
        try:
            with urllib.request.urlopen(base + "/api/setup", timeout=5) as r:
                needs_setup = json.loads(r.read()).get("needs_setup")
        except Exception as e:
            check("能读到首启状态", False, str(e))
        check("这台中继确实还没首启（否则本节的判据不成立）", needs_setup is True,
              f"needs_setup={needs_setup}")
        inputs = js("""
            return Array.from(document.querySelectorAll('input')).map(function (el) {
              return {type: el.type, name: el.name || '', ph: el.placeholder || ''};
            });
        """) or []
        check("首启表单有输入框", len(inputs) >= 2, f"{len(inputs)} 个：{inputs}")

        if len(inputs) >= 2:
            # 直接用 JS 填值并派发 input 事件（React 受控组件需要它）。
            filled = js("""
                function setVal(el, v) {
                  const d = Object.getOwnPropertyDescriptor(
                    window.HTMLInputElement.prototype, 'value');
                  d.set.call(el, v);
                  el.dispatchEvent(new Event('input', {bubbles: true}));
                }
                const els = Array.from(document.querySelectorAll('input'));
                const pw = els.filter(e => e.type === 'password');
                const tx = els.filter(e => e.type !== 'password');
                if (tx.length) setVal(tx[0], 'admin');
                pw.forEach(e => setVal(e, 'browser-verified-pw'));
                // 断言密码框真的是 type=password：普通 Input 会让密码
                // 明文显示在屏幕上。这是本测试抓出的第一个真缺陷。
                return {text: tx.length, pass: pw.length};
            """)
            check("表单可填写", bool(filled), str(filled))
            # 密码必须是 type=password，否则明文显示在屏幕上。
            check("密码框已遮蔽（type=password）",
                  bool(filled) and filled.get("pass", 0) >= 1,
                  f"发现 {filled.get('pass', 0) if filled else 0} 个密码框")
            print(f"     截图 → {shot('02-setup-filled')}")

            # 按语义挑提交按钮：type="primary" 且不是「生成密码」那个。
            # 第一版盲取第一个可用按钮，结果点的是「生成 24 位密码」，
            # 表单自然没提交 —— 那是测试自己的缺陷，不是产品的。
            submitted = js("""
                const btns = Array.from(document.querySelectorAll('button'));
                const primary = btns.filter(b =>
                  !b.disabled && b.className.includes('arco-btn-primary'));
                const b = primary[primary.length - 1] || null;
                if (!b) return null;
                b.click();
                return b.innerText.trim();
            """)
            check("提交按钮可点击", submitted is not None, f"按钮文字={submitted!r}")

            # 首启是 /setup 内的**多步向导**（创建管理员 → 确认公网地址 →
            # 挂载目标 → 完成），所以判据不是「离开 /setup」而是
            # 「后端确认管理员已创建」。第一版我用路径变化做判据，
            # 那是测试自己的错 —— 产品当时是对的。
            created = False
            for _ in range(60):
                try:
                    with urllib.request.urlopen(base + "/api/setup", timeout=5) as r:
                        if json.loads(r.read()).get("needs_setup") is False:
                            created = True
                            break
                except Exception:
                    pass
                time.sleep(0.25)
            check("管理员已创建（后端确认）", created)

            advanced = js("""
                const t = document.body.innerText;
                return !/Username/.test(t) && !/用户名/.test(t);
            """)
            check("向导已推进到下一步", bool(advanced),
                  "" if advanced else "仍停在创建管理员这一步")
            print(f"     截图 → {shot('03-after-setup')}")

            errs = js("return window.__errs || []") or []
            check("首启流程无 JS 错误", len(errs) == 0, "; ".join(errs[:3]))

        # 等页面上的数据真的到位，而不是只等第一帧。
        #
        # 只等 #root 有子节点测的是「渲染出了东西」，而一个永久转圈的页面
        # 也满足那个条件 —— 设置页曾经在这里被记成「64 字符」，
        # 而它实际有四组配置几十行内容，只是 SWR 还没取回来。
        # 一个把加载态当成功的判据，等于没有判据。
        def wait_for_content(min_chars=80, tries=40):
            last = 0
            for _ in range(tries):
                n = js("return (document.body.innerText || '').trim().length") or 0
                # 连续两次一样且够长 = 稳定了。只看「够长」会在渲染中途误判。
                if n >= min_chars and n == last:
                    return n
                last = n
                time.sleep(0.25)
            return last

        # ── 先建一条隧道，再走页面 ───────────────────────────────────────
        #
        # 这一步是本脚本之前最大的盲区：它只测过**空**控制台。
        # 概览页 67 个字符是「还没有隧道」的空态，隧道详情页压根没被打开过 ——
        # 而所有分阶段丢弃计数、限速、分片率、共享入口那几屏都只在
        # 「有一条隧道」时才渲染。于是任何一处 undefined 解引用、
        # 任何一个新加字段的渲染崩溃，都在这个测试里完全隐身。
        #
        # 用 API 建而不是走向导：向导本身有独立的交互测试价值，
        # 而这里要的只是「让详情页有东西可渲染」。
        print("\n【4】建一条隧道，让数据页有东西可渲染")
        created = js_async("""
            const done = arguments[0];
            fetch('/api/tunnels', {
                method: 'POST',
                // CSRF 令牌由前端镜像进一个可读 Cookie（client.ts 的
                // CSRF_COOKIE），所以浏览器里能拿到它 —— 应用把它存在
                // 模块变量里，从外面是读不到的。
                headers: {'Content-Type': 'application/json',
                          'X-NFR-CSRF': (document.cookie.match(
                              /(?:^|; )nfr_csrf=([^;]*)/) || [,''])[1]},
                body: JSON.stringify({
                    slug: 'smoke-udp',
                    kind: 'service', tls: 'passthrough',
                    exposure: 'port', l4: 'udp',
                    listen_port: 20450,
                    backend: {kind: 'addr', addr: '127.0.0.1:5004'},
                    policy: {bytes_per_second: 1048576, packets_per_second: 5000},
                }),
            }).then(r => r.text().then(t => done(r.status + ' ' + t.slice(0, 200))))
              .catch(e => done('ERR ' + e));
        """)
        if not str(created).startswith("20"):
            # 出错时把浏览器实际看到的 Cookie 打出来 —— 「403 缺少 CSRF 令牌」
            # 有两种可能（Cookie 没下发 / 正则没匹配上），不区分就只能猜。
            ck = js("return document.cookie")
            print(f"     document.cookie = {ck!r}")
        check("经 API 建出一条 UDP 隧道", str(created).startswith("20"), str(created)[:160])

        # ── 向导不许卖一个不存在的能力 ────────────────────────────────
        #
        # 「中继直接拨号」在数据面**不存在**（三个入口都要求一个在线 agent），
        # 而这个单选项此前是可选的：选中后隧道会一直停在「等待代理端上线」，
        # 或者在恰好一个 agent 在线时被静默绑到那个 agent 上 —— 与所选相反。
        #
        # 它现在被禁用并给出理由（禁用而不隐藏，是本仓的口径）。
        # 这条断言守住「它不会又变成可选的」——那是一次静默回归：
        # 页面照常渲染、测试照常绿，只是用户又能选一个不存在的东西了。
        print("\n【4b】向导：未实现的选项必须是禁用的")
        goto(base + "/tunnels/new")
        js(collector)
        wait_for_content(min_chars=100)
        radio = js_async("""
            const done = arguments[0];
            // 走到「目标」那一步：向导是分步的，先把能点的「下一步」点掉。
            let guard = 0;
            const tick = () => {
                const txt = document.body.innerText || '';
                if (txt.indexOf('谁来抵达目标') >= 0) {
                    const labels = Array.from(document.querySelectorAll('label'));
                    const hit = labels.find(l =>
                        (l.innerText || '').indexOf('中继直接拨号') >= 0);
                    if (!hit) { done({found: false}); return; }
                    const input = hit.querySelector('input');
                    done({
                        found: true,
                        disabled: !!(input && input.disabled) ||
                                  hit.className.indexOf('disabled') >= 0,
                        label: (hit.innerText || '').trim().slice(0, 40),
                    });
                    return;
                }
                if (guard++ > 12) { done({found: false, gaveUp: true}); return; }
                const next = Array.from(document.querySelectorAll('button')).find(b =>
                    !b.disabled && /下一步|继续/.test(b.innerText || ''));
                if (next) next.click();
                setTimeout(tick, 250);
            };
            tick();
        """) or {}
        if not radio.get("found"):
            check("在向导里找到「中继直接拨号」这一项", False,
                  f"没走到那一步或选项不见了：{radio}")
        else:
            check("「中继直接拨号」是禁用的", bool(radio.get("disabled")),
                  radio.get("label") or "可选 —— 用户能选一个数据面不存在的路径")
            body4b = js("return document.body.innerText") or ""
            check("并且说清了为什么", "v1" in body4b or "未实现" in body4b,
                  "有理由" if ("v1" in body4b or "未实现" in body4b)
                  else "只禁用不解释，用户会以为自己找错了地方")
        print(f"     截图 → {shot('04b-wizard-disabled')}")

        print("\n【5】主要界面逐个渲染")
        for path, name in [
            ("/", "概览"), ("/tunnels", "隧道"), ("/agents", "代理端"),
            ("/media", "媒体中继"), ("/diagnostics", "诊断"), ("/settings", "设置"),
        ]:
            goto(base + path)
            js(collector)
            ok = False
            for _ in range(40):
                n = js("const r=document.getElementById('root');return r?r.children.length:0")
                if n and n > 0:
                    ok = True
                    break
                time.sleep(0.25)
            # 等数据落地再量，否则量到的是加载态。
            wait_for_content()
            body = (js("return document.body.innerText.slice(0,3000)") or "").strip()
            errs = js("return window.__errs || []") or []
            # 过滤掉「后端端点不存在」造成的预期 404 —— README 已如实记录。
            real = [e for e in errs if "404" not in e and "notImplemented" not in e]
            # 不能只判「有文字」：一个永久转圈的页面也有文字（「加载中」）。
            # 所以还要断言页面上**没有停留的加载态**。
            spinning = js("""
                const t = document.body.innerText || '';
                const hasSpinner = !!document.querySelector('[class*=arco-spin-loading]');
                const loadingText = /加载中|Loading/.test(t) && t.trim().length < 60;
                return hasSpinner || loadingText;
            """)
            check(f"{name}（{path}）渲染", ok and len(body) > 10 and not spinning,
                  f"{len(body)} 字符"
                  + ("，仍在加载" if spinning else "")
                  + (f"，错误：{real[:2]}" if real else ""))
            if real:
                failures.append(f"{name} JS 错误：{real[:2]}")
            print(f"     截图 → {shot('page-' + path.strip('/').replace('/', '-') or 'overview')}")

        # ── 隧道详情页：所有新加的计数格都在这里渲染 ──────────────────
        #
        # 这一屏是本脚本之前完全没打开过的。它渲染分阶段拒绝的十来个计数、
        # 分片率、限速、以及「发包代理端不符 / 分片范围重叠」两个安全格。
        # 任何一个字段名写错、任何一处 `status?.x ?? 0` 漏了问号，
        # 都只在这里执行时才崩 —— 而崩的表现是这一屏白屏。
        print("\n【6】隧道详情页（新加的计数格都在这一屏）")
        # 路由用 **slug** 而不是 ID（TunnelDetail 里 useParams 取的是 slug）。
        # 我第一版用 ID 导航，页面于是永久转圈 —— 那反而抓出一个真缺陷：
        # slug 不存在时详情页不区分「还在加载」与「加载完了但没有这条隧道」。
        tid = js_async("""
            const done = arguments[0];
            fetch('/api/tunnels').then(r => r.json())
              .then(j => done((j.tunnels || j || []).map(x => x.slug)[0] || ''))
              .catch(() => done(''));
        """)
        if not tid:
            failures.append("拿不到隧道 ID，详情页没测到")
            check("拿到隧道 ID", False, "列表接口没返回")
        else:
            goto(base + "/tunnels/" + str(tid))
            js(collector)
            wait_for_content(min_chars=120)
            body = (js("return document.body.innerText.slice(0,4000)") or "").strip()
            errs = js("return window.__errs || []") or []
            real = [e for e in errs if "404" not in e and "notImplemented" not in e]
            # 逐个断言那些格子真的渲染出来了。少一个就说明字段名对不上，
            # 而那种错在 tsc 里是看不见的（后端字段是运行时才有的）。
            want = [
                "分阶段拒绝", "会话表已满", "回包无对应会话",
                "分片重组失败", "发包代理端不符", "分片范围重叠",
                "超限速被丢弃", "会话被挤出",
            ]
            missing = [w for w in want if w not in body]
            check("详情页渲染出全部分项计数", not missing and not real,
                  f"{len(body)} 字符"
                  + (f"，缺：{missing}" if missing else "")
                  + (f"，错误：{real[:2]}" if real else ""))
            if real:
                failures.append(f"详情页 JS 错误：{real[:2]}")
            print(f"     截图 → {shot('06-tunnel-detail')}")

            # 逐跳探测那一屏也要打开：它现在会显示「没测」的中性行，
            # 而那个渲染分支是这次新加的。
            probe = js_async("""
                // WebDriver 把回调**追加**在参数最后，所以带参数时它不是
                // arguments[0] —— 我第一版搞反了，表现是脚本超时。
                const slug = arguments[0], done = arguments[1];
                const csrf = (document.cookie.match(
                    /(?:^|; )nfr_csrf=([^;]*)/) || [,''])[1];
                fetch('/api/tunnels').then(r => r.json()).then(j => {
                    const list = j.tunnels || j || [];
                    const hit = list.find(x => x.slug === slug);
                    if (!hit) { done('NO_TUNNEL'); return; }
                    return fetch('/api/tunnels/' + hit.id + ':test', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json',
                                  'X-NFR-CSRF': csrf},
                        body: '{}',
                    }).then(r => r.text().then(t => done(r.status + ' ' + t)));
                }).catch(e => done('ERR ' + e));
            """, [str(tid)])
            # 这里 agent 还没上线，所以探测会在 agent_reachable 停下 ——
            # 那时 UDP 那条分支根本走不到，unverified 自然是空的。
            # 能在浏览器里断言的是**另一半**：ok=false 时必须有一步 ok=false，
            # 否则界面会把失败点退化显示成第一跳
            #（ProbeModal 的 `find(!ok)?.hop ?? 'listener_bound'`）。
            #
            # 「UDP 不许给 target_dialable 画绿勾」那条要有 agent 才测得到，
            # 归 cmd/nfrelay 的单元测试（TestUDPProbeReportsUnverifiedHops）。
            try:
                pr = json.loads(str(probe).split(" ", 1)[1])
            except Exception as e:
                pr = None
                print(f"     探测响应解析失败：{e}")
            ok_probe = bool(pr) and (
                pr.get("ok") is True or any(not st.get("ok") for st in pr.get("steps", []))
            )
            check("探测报失败时必须指名是哪一跳失败", ok_probe, str(probe)[:200])
            # 而且**绝不**能在 UDP 隧道上给 target_dialable 画一个绿勾。
            faked = bool(pr) and any(
                st.get("hop") == "target_dialable" and st.get("ok")
                for st in pr.get("steps", [])
            )
            check("UDP 隧道的 target_dialable 不许被编成通过", not faked,
                  "编造了一个绿勾" if faked else "如实缺席")

            # ── 学习模式面板 ──────────────────────────────────────
            #
            # 这一屏此前**不存在**：locale 键与 client 方法都在，而后端两个
            # 端点一行都没有，所以面板一旦渲染出来只会 404。现在它是真的，
            # 但它的两条关键判据只在浏览器里才成立：
            #
            #   1. 面板**默认一个都不勾**。默认全勾会让「点两下就完事」变成
            #      最省力的路径，而学习窗口里扫描器与真客户端混在一起 ——
            #      那一下就是把撞门的人一键请进允许列表。
            #   2. 「当前不限来源」那条警告要真的显示出来。它是运维判断
            #      「我到底该不该收窄」的唯一依据。
            #
            # 面板在**配置**页签里（它写的是 allow_cidrs，是配置动作）。
            switched = js("""
                const tabs = Array.from(
                    document.querySelectorAll('[role="tab"], .arco-tabs-header-title'));
                const t = tabs.find(x => (x.innerText || '').trim().indexOf('配置') >= 0);
                if (!t) return 'NO_TAB';
                t.click();
                return 'OK';
            """)
            if switched != 'OK':
                check("找到配置页签", False, str(switched))
            else:
                time.sleep(1.2)
                cbody = (js("return document.body.innerText.slice(0,8000)") or "")
                learnShown = "学习模式" in cbody
                check("配置页渲染出学习模式面板", learnShown,
                      "面板缺席 —— 这个承诺又只交付了一半" if not learnShown else "在")
                if learnShown:
                    # 这套冒烟环境里**没有 agent**，所以隧道上不会有任何会话，
                    # 观测列表必然是空的。那不是缺陷，恰好是这里能验的东西：
                    #
                    #   * 空态必须渲染成一句话，而不是白屏。后端 sources 回
                    #     null（而不是 []）时前端会在 .map 上炸，
                    #     而那正是这一屏最可能坏掉的方式。
                    #   * 「当前不限来源」那条警告要真的显示 —— 它是运维判断
                    #     「该不该收窄」的唯一依据，而它挂在 policy 上，
                    #     与观测列表是否为空无关。
                    #
                    # 有观测时的形态（勾选框、默认零勾选、命中次数）由
                    # 真实进程验证覆盖：那需要一个在线 agent 与真实流量，
                    # 而这套冒烟脚本刻意不起 agent。
                    # detail 在成功时**也会**打出来（check 的约定），
                    # 所以它得写「看到了什么」而不是「失败意味着什么」——
                    # 第一版把失败解释放这里，于是一行全绿的输出后面跟着
                    # 一句「空态没有文案」，读起来像是失败了。
                    emptyOK = "还没观测到任何来源" in cbody
                    check("空态渲染成一句话而不是白屏", emptyOK,
                          "有空态文案" if emptyOK
                          else "缺文案 —— sources 回 null 时前端会在 .map 上炸")
                    openOK = "不限来源" in cbody
                    check("说清了当前不限来源", openOK,
                          "警告在" if openOK
                          else "缺「当前放行一切」的提示，运维无从判断该不该收窄")
                    errs2 = js("return window.__errs || []") or []
                    real2 = [e for e in errs2 if "404" not in e and "notImplemented" not in e]
                    check("学习模式面板无 JS 错误", not real2, f"{real2[:2]}")
                    if real2:
                        failures.append(f"学习模式面板 JS 错误：{real2[:2]}")
                print(f"     截图 → {shot('06b-learn-mode')}")

        # ── 设置页的声明式配置编辑器 ────────────────────────────────
        #
        # 这一屏是「按一个按钮就能删掉全部隧道」的地方，所以它有两条
        # 只在浏览器里才成立的判据：
        #   1. 干跑的 diff 里**逐条列出** slug，而不是只给一个条数；
        #   2. 真要删东西时挡一次确认。
        # 后端的单元测试管不到这两条 —— 它们是渲染与交互。
        print("\n【7】设置页：声明式配置编辑器")
        goto(base + "/settings")
        js(collector)
        wait_for_content(min_chars=120)

        # 「填入模板」把当前隧道导出成一份文档。这是编辑一份声明式文档
        # 唯一安全的起点 —— 手写会漏掉现存隧道，而漏掉就等于删掉。
        clicked = js("""
            const b = Array.from(document.querySelectorAll('button'))
              .find(x => /填入模板|Insert template/.test(x.innerText));
            if (!b) return 'NO_BUTTON';
            b.click();
            return 'OK';
        """)
        check("设置页有「填入模板」按钮", clicked == "OK", str(clicked))

        time.sleep(0.5)
        doc = js("""
            const ta = document.querySelector('textarea');
            return ta ? ta.value : '';
        """) or ""
        # 模板里必须有现存隧道的 slug，且**不能**含 id / short_id / state
        # —— 那三个字段放进一份会被手改的文档里只会引出
        # 「我改了它为什么没用」，而 state 更是运行时观测。
        check("模板含现存隧道且不含 id/short_id/state",
              "smoke" in doc and '"id"' not in doc
              and '"short_id"' not in doc and '"state"' not in doc,
              doc[:160].replace("\n", " "))

        # 校验：一份从当前状态导出的文档，diff 必须全是「未变」。
        js("""
            const b = Array.from(document.querySelectorAll('button'))
              .find(x => /^(校验|Validate)$/.test(x.innerText.trim()));
            if (b) b.click();
        """)
        time.sleep(1.5)
        # 只量编辑器那张卡片，不量整页 —— 量 document.body.innerText 会让
        # 判据被设置表格里的字撞上，那种「过」是假的。
        card = (js("""
            const cs = Array.from(document.querySelectorAll('.arco-card'));
            const c = cs[cs.length - 1];
            return c ? c.innerText : '';
        """) or "")
        check("导出的模板原样校验 = 全部未变",
              ("未变" in card or "Unchanged" in card)
              and ("完全一致" in card or "changes nothing" in card),
              card.replace("\n", " | ")[:300])
        print(f"     截图 → {shot('07-settings-nochange')}")

        # Arco 的命令式 API（Message / Notification / Modal.confirm）不在
        # React 树里，各自造一个容器再单独渲染。那条渲染路径读的是
        # `ReactDOM.createRoot`，而 React 19 的 react-dom **不再导出**它 ——
        # 于是兼容层退回已被删除的 ReactDOM.render，**彻底静默**：
        # 容器 div 照样挂上 body，里面永远是空的。
        #
        # 表现是「点了按钮什么都没发生」，而 tsc / oxlint / locale 对齐
        # 一个都看不见。本仓有 32 处 Message.*，修好之前一个都没显示过。
        # 修法是在 main.tsx 里 setCreateRoot(createRoot)。
        # 这条判据只有在真浏览器里点一下才成立，所以它必须留在这里。
        toast = js("""
            return {
              msgs: document.querySelectorAll('[class*=arco-message]').length,
              emptyContainers: Array.from(document.querySelectorAll('body > div'))
                .filter(d => d.id !== 'root' && d.innerHTML === '').length,
            };
        """) or {}
        check("Arco 命令式提示真的渲染出来了（React 19 兼容层）",
              (toast.get("msgs") or 0) > 0,
              f"提示元素 {toast.get('msgs')} 个，空容器 {toast.get('emptyContainers')} 个"
              + ("——setCreateRoot 没接上，全部 Message 都是静默的"
                 if not toast.get("msgs") else ""))

        # 现在把文档换成一份**空**清单：那意味着删掉全部。
        # 这是最危险的输入，所以它的两条判据也最要紧。
        js("""
            const ta = document.querySelector('textarea');
            // React 受控组件必须走原生 setter + input 事件，
            // 直接改 .value 不会触发 onChange，界面状态不会更新。
            const setter = Object.getOwnPropertyDescriptor(
                window.HTMLTextAreaElement.prototype, 'value').set;
            setter.call(ta, '{"version":1,"tunnels":[]}');
            ta.dispatchEvent(new Event('input', {bubbles: true}));
        """)
        time.sleep(0.4)
        js("""
            const b = Array.from(document.querySelectorAll('button'))
              .find(x => /^(校验|Validate)$/.test(x.innerText.trim()));
            if (b) b.click();
        """)
        time.sleep(1.5)
        # 同样只量编辑器卡片：量整页会被设置表格里的字撞上，
        # 那种「过」是假的（这条判据第一版就是那样假过的）。
        card = (js("""
            const cs = Array.from(document.querySelectorAll('.arco-card'));
            const c = cs[cs.length - 1];
            return c ? c.innerText : '';
        """) or "")
        # 判据一：逐条列出要删的 slug。只显示「删除 2」看起来像一个统计，
        # 而它其实是一次不可逆的操作。
        check("干跑逐条列出将被删除的 slug",
              "smoke-udp" in card and ("删除" in card or "Delete" in card),
              card.replace("\n", " | ")[:320])
        print(f"     截图 → {shot('07-settings-delete-preview')}")

        # 判据二：按下「应用」必须先弹一次确认，而且文案里要有 slug。
        js("""
            const b = Array.from(document.querySelectorAll('button'))
              .find(x => /^(应用|Apply)$/.test(x.innerText.trim()));
            if (b) b.click();
        """)
        time.sleep(1.0)
        modal = js("""
            // 命令式 confirm 渲染在 body 直属的独立容器里，不在 #root 下。
            // 匹配到的第一个元素常常是遮罩层（innerText 为空），
            // 所以取文本最长的那个 —— 第一版没这么做，判据于是假红。
            const els = Array.from(document.querySelectorAll('[class*=arco-modal]'));
            if (els.length === 0) return {open: false, text: ''};
            const texts = els.map(e => e.innerText || '')
              .sort((a, b) => b.length - a.length);
            return {open: true, text: texts[0].slice(0, 400)};
        """) or {}
        check("要删隧道时必须弹确认，且文案里列出 slug",
              modal.get("open") and "smoke" in (modal.get("text") or ""),
              f"弹窗={modal.get('open')}，文案={(modal.get('text') or '')[:160]}")
        print(f"     截图 → {shot('07-settings-confirm')}")

        # 取消。这一屏的最后一条判据是**取消真的什么都没做** ——
        # 一个「取消」却已经把请求发出去了的确认框比没有确认框更糟。
        js("""
            const btns = Array.from(
              document.querySelectorAll('[class*=arco-modal] button'));
            const cancel = btns.find(x => /取消|Cancel/.test(x.innerText));
            if (cancel) cancel.click();
        """)
        time.sleep(0.8)
        left = js_async("""
            const done = arguments[0];
            fetch('/api/tunnels').then(r => r.json())
              .then(j => done((j.tunnels || j || []).length))
              .catch(() => done(-1));
        """)
        check("取消确认后一条隧道都没被删", left is not None and int(left) > 0,
              f"剩 {left} 条")

        print("\n【8】样式与可访问性")
        # 这一节是从截图里长出来的。功能判据全绿的同时，导航链接却挂着浏览器
        # 默认下划线 —— 因为项目没引入 CSS reset，而 UnoCSS 的 presetWind3
        # preflight 不含 Tailwind 那条 `a { text-decoration: inherit }`。
        # tsc / oxlint / locale 对齐都看不见这种事，只有渲染后量计算样式才行。
        goto(base + "/")
        js(collector)
        for _ in range(40):
            if (js("const r=document.getElementById('root');return r?r.children.length:0") or 0) > 0:
                break
            time.sleep(0.25)

        styled = js("""
            const as = Array.from(document.querySelectorAll('a'));
            const underlined = as.filter(a =>
              getComputedStyle(a).textDecorationLine.includes('underline'))
              .map(a => a.innerText.trim().slice(0, 12));
            // 没有 href 又不带 role 的 <a> 是「假链接」：键盘 tab 不到，
            // 读屏软件当普通文本念。该用按钮。
            const fake = as.filter(a => !a.getAttribute('href') && !a.getAttribute('role'))
              .map(a => a.innerText.trim().slice(0, 12));
            return {total: as.length, underlined, fake};
        """) or {}
        check("链接无浏览器默认下划线", not styled.get("underlined"),
              f"{styled.get('total')} 个链接，带下划线的：{styled.get('underlined')}")
        check("没有无 href 的假链接", not styled.get("fake"),
              f"假链接：{styled.get('fake')}")

        # 键盘可达性：Tab 应当能走到导航里。
        focusable = js("""
            const sel = 'a[href], button:not([disabled]), input, select, textarea, [tabindex]';
            return document.querySelectorAll(sel).length;
        """)
        check("存在可聚焦元素（键盘可达）", (focusable or 0) >= 6, f"{focusable} 个")
        print(f"     截图 → {shot('05-styling')}")

    finally:
        if session:
            try:
                rq("DELETE", f"/session/{session}", timeout=10)
            except Exception:
                pass
        driver.kill()

    print()
    if failures:
        print(f"✗ {len(failures)} 项失败：")
        for f in failures:
            print("   - " + f)
        return 1
    print("✓ 浏览器冒烟全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
