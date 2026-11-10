#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""qwb-capture.py —— 零消耗抓「提交 flag」的真实请求

为什么要抓：
  本场提交接口的必填字段赛前探不出来（`red/submit` 恒回「缺少参数」、
  `flag/submit` / `against/submit` 恒回「请求错误」，见 platform-qwb §6.2）。
  唯一可靠办法是**看前端自己发出的那个请求**。

为什么是「零消耗」：
  用 Playwright 的请求拦截把它**截在浏览器里**，抓到 (URL, headers, body) 后
  **abort**，请求根本不出网 —— 服务器不会记账，**不消耗任何一次提交机会**。
  （人工 F12 点一次提交则必然要送一个 `flag{...}` 形状的错串上去 = 花掉 1 次。）

用法（★ 开赛后、有题目了才有意义）：
  pwpython scripts/qwb-capture.py --probe                    # 只验证登录态+看页面结构
  pwpython scripts/qwb-capture.py --probe --dump-dom          # 额外把候选选择器打出来
  pwpython scripts/qwb-capture.py --capture <题号>            # 真抓（拦截后 abort）
  pwpython scripts/qwb-capture.py --capture <题号> --live     # 不拦截，真发给服务器（会消耗 1 次）

产物：
  evidence/qwb-submit-capture.json    抓到的请求（可直接喂 qwb.py --body）
  屏幕上打印一条 ready-to-run 的 qwb.py submit 命令
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime
from pathlib import Path

WS = Path(__file__).resolve().parent.parent
OUT = WS / "evidence"

SUBMIT_HINTS = ("/match/red/submit", "/match/flag/submit", "/match/against/submit",
                "/submit")

# 注入到页面的兜底 hook：即使路由拦截没匹配上，也能把 body 记到 console
INIT_HOOK = r"""
(() => {
  if (window.__QWB_HOOKED) return; window.__QWB_HOOKED = true;
  const hit = (u) => String(u || '').includes('/match/') && String(u || '').includes('submit');
  const oOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (m, u) { this.__qwb = u; return oOpen.apply(this, arguments); };
  const oSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function (b) {
    if (hit(this.__qwb)) {
      try { window.__QWB_CAPTURED = window.__QWB_CAPTURED || [];
            window.__QWB_CAPTURED.push({url: this.__qwb, body: b}); } catch (e) {}
      console.log('[QWB-CAPTURED]', this.__qwb, b);
    }
    return oSend.apply(this, arguments);
  };
  const oFetch = window.fetch;
  window.fetch = function (input, init) {
    const u = (typeof input === 'string') ? input : (input && input.url);
    if (hit(u)) {
      try { window.__QWB_CAPTURED = window.__QWB_CAPTURED || [];
            window.__QWB_CAPTURED.push({url: u, body: init && init.body}); } catch (e) {}
      console.log('[QWB-CAPTURED]', u, init && init.body);
    }
    return oFetch.apply(this, arguments);
  };
})();
"""


def load_client():
    spec = importlib.util.spec_from_file_location("qwb", WS / "scripts" / "qwb.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--probe", action="store_true", help="只验证登录态 + 看页面结构")
    ap.add_argument("--dump-dom", action="store_true", help="打印候选选择器（输入框/按钮/题目卡片）")
    ap.add_argument("--capture", default="", metavar="题号", help="抓该题的提交请求")
    ap.add_argument("--live", action="store_true", help="*** 放行请求（真提交，消耗次数）")
    ap.add_argument("--headed", action="store_true", help="显示浏览器窗口（调试用）")
    ap.add_argument("--timeout", type=int, default=45)
    ap.add_argument("--user-id", default="", help="注入用的 user_id（默认自动从 /match/team/users 取）")
    args = ap.parse_args(argv)

    from playwright.sync_api import sync_playwright

    q = load_client()
    cf = q.conf()
    creds = q.load_creds()
    if not cf.get("token"):
        raise SystemExit("[!] creds.env 里没有 QWB_TOKEN")
    ss = cf["jsluid"]
    origin = "https://match.ichunqiu.com"
    entry = f"{origin}/index?k={cf['k']}"

    captured: list[dict] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not args.headed,
                                    args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx = browser.new_context(
            user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/<target> Safari/537.36 Edg/<target>"),
            viewport={"width": 1440, "height": 900}, locale="zh-CN")

        # ① 反爬 cookie（有就带）
        if ss:
            ctx.add_cookies([{"name": "__jsluid_s", "value": ss,
                              "domain": ".ichunqiu.com", "path": "/"}])
        # ② ★ 登录态：必须在页面脚本之前写进 localStorage（键 = 本场 s_source_id）
        #    坑（2026-10-31 实测）：只写 {token} 会被路由守卫打回登录页 ——
        #    守卫条件是 `r.user.user_id ? … : 去登录`，所以 user_id 必须有真值。
        #    user_id 取值不影响鉴权：请求带的仍是我们的 token，服务端按 token 认人。
        # 优先用 creds.env 里的**真实身份**（QWB_USERID/USERNAME 由人类从浏览器粘贴确认），
        # 缺失才退回从 /match/team/users 借一个 user_id（仅供抓包，身份不准确）
        uid = args.user_id or creds.get("QWB_USERID", "")
        uname = creds.get("QWB_USERNAME", "")
        try:
            admin = int(creds.get("QWB_ISADMIN", "0") or 0)
        except ValueError:
            admin = 0
        src = "creds.env"
        if not uid:
            js = q.http("/match/team/users", {}, cf=cf)
            for u in ((js.get("data") or {}).get("lists") or []):
                if u.get("user_id"):
                    uid, uname = u["user_id"], u.get("user_name") or ""
                    src = "/match/team/users（借用，身份不准）"
                    break
        print(f"[i] 注入身份：{uname or '?'} / {uid} / is_admin={admin}  来源={src}")
        user_obj = {"token": cf["token"], "user_id": uid or "anon",
                    "user_name": uname, "is_admin": admin,
                    "face_status": 0, "user_type": 0}
        ctx.add_init_script(
            f'localStorage.setItem({json.dumps("9FZ4dGtRk0I")}, '
            f'{json.dumps(json.dumps(user_obj, ensure_ascii=False))});'
        )
        ctx.add_init_script(INIT_HOOK)

        page = ctx.new_page()
        logs: list[str] = []
        page.on("console", lambda m: logs.append(m.text))

        # ③ 拦截提交请求：抓到就 abort（零消耗）
        def on_route(route):
            req = route.request
            url = req.url
            if any(h in url for h in SUBMIT_HINTS):
                rec = {"time": datetime.now().astimezone().isoformat(timespec="seconds"),
                       "url": url, "method": req.method,
                       "headers": dict(req.headers), "body": req.post_data,
                       "aborted": not args.live}
                captured.append(rec)
                print(f"\n[★ 抓到提交请求] {rec['method']} {url}")
                print(f"  body: {rec['body']}")
                if args.live:
                    route.continue_()
                else:
                    route.abort()          # ← 关键：不出网，不消耗次数
                return
            route.continue_()

        ctx.route("**/apiterminator.ichunqiu.com/**", on_route)

        print(f"[1] 打开 {entry}")
        page.goto(entry, wait_until="domcontentloaded", timeout=args.timeout * 1000)
        page.wait_for_timeout(6000)

        body_text = page.inner_text("body")[:400].replace("\n", " ")
        print(f"[2] 页面片段：{body_text}")
        if "登录" in body_text and "<team>" not in body_text:
            print("[!] 疑似没注入成功（页面出现登录提示）。检查 localStorage 键名 / token 是否过期")

        # 队伍信息是否渲染出来（= 登录态真的生效）
        for probe_txt in ("<team>", "题目", "退出", "头像"):
            if probe_txt in body_text:
                print(f"[i] 页面出现「{probe_txt}」→ 登录态生效迹象")

        shot = WS / "work" / "qwb-capture" / "page.png"
        shot.parent.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(shot), full_page=False)
        print(f"[3] 截图：{shot}")

        if args.dump_dom:
            info = page.evaluate("""() => {
              const pick = (el) => ({
                tag: el.tagName.toLowerCase(),
                cls: (el.className || '').toString().slice(0, 60),
                txt: (el.innerText || '').slice(0, 40).replace(/\\n/g, ' '),
                ph: el.placeholder || undefined
              });
              return {
                inputs: [...document.querySelectorAll('input')].map(pick).slice(0, 25),
                buttons: [...document.querySelectorAll('button')].map(pick).slice(0, 30),
                cards: [...document.querySelectorAll('[class*=item],[class*=card],[class*=question]')]
                         .map(pick).slice(0, 25),
                title: document.title
              };
            }""")
            dom = WS / "work" / "qwb-capture" / "dom.json"
            dom.write_text(json.dumps(info, ensure_ascii=False, indent=1), encoding="utf-8")
            print(f"[4] DOM 候选：{dom}")
            print(json.dumps(info, ensure_ascii=False)[:1200])

        if args.capture:
            print(f"\n[5] 尝试进入题目 {args.capture} 并触发提交（拦截模式={not args.live}）")
            # 前端用的是 Element Plus；先尽量点题目标题，再找 flag 输入框与提交按钮
            clicked = False
            for sel in (f"text={args.capture}", "[class*=question-item]", "[class*=q-item]",
                        ".item", ".card"):
                try:
                    loc = page.locator(sel).first
                    if loc.count() and loc.is_visible():
                        loc.click(timeout=3000)
                        clicked = True
                        print(f"    点到了：{sel}")
                        page.wait_for_timeout(2500)
                        break
                except Exception:                      # noqa: BLE001
                    continue
            if not clicked:
                print("    [!] 没点到题目卡片 —— 用 --dump-dom 先看选择器，或直接人工在浏览器抓")

            for sel in ("input[placeholder*=flag]", "input[placeholder*=Flag]",
                        "input[type=text]", "textarea"):
                try:
                    loc = page.locator(sel).first
                    if loc.count() and loc.is_visible():
                        loc.fill("flag{CAPTURE_TEST_00000000}")
                        print(f"    填了输入框：{sel}")
                        break
                except Exception:                      # noqa: BLE001
                    continue
            for sel in ("text=提交", "button:has-text('提交')", ".el-button--primary"):
                try:
                    loc = page.locator(sel).first
                    if loc.count() and loc.is_visible():
                        loc.click(timeout=3000)
                        print(f"    点了提交：{sel}")
                        page.wait_for_timeout(3000)
                        break
                except Exception:                      # noqa: BLE001
                    continue

        # 兜底：页内 hook 记录到的
        try:
            hooked = page.evaluate("() => window.__QWB_CAPTURED || []")
        except Exception:                              # noqa: BLE001
            hooked = []
        for h in hooked:
            if h.get("url") and all(h["url"] != c["url"] or h.get("body") != c.get("body")
                                    for c in captured):
                captured.append({"time": datetime.now().astimezone().isoformat(timespec="seconds"),
                                 "url": h["url"], "method": "POST",
                                 "body": h.get("body"), "aborted": True, "source": "page-hook"})

        if logs:
            print("\n[console 摘要]")
            for t in logs[:12]:
                if "QWB-CAPTURED" in t or "error" in t.lower():
                    print("   ", t[:200])

        browser.close()

    if captured:
        OUT.mkdir(parents=True, exist_ok=True)
        f = OUT / "qwb-submit-capture.json"
        f.write_text(json.dumps(captured, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"\n[✓] 抓到 {len(captured)} 个提交请求 → {f}")
        c = captured[0]
        path = c["url"].split("apiterminator.ichunqiu.com", 1)[-1]
        print("\n--- 可直接用的重放命令（把 __FLAG__ 模板存下来）---")
        try:
            body = json.dumps(json.loads(c["body"]), ensure_ascii=False)
        except (TypeError, json.JSONDecodeError):
            body = str(c["body"])
        print(f"python3 scripts/qwb.py submit <题号> 'flag{{...}}' "
              f"--path '{path}' --body '{body}'")
        return 0

    print("\n[--] 这次没抓到提交请求（未开赛/没有题目/选择器没命中都正常）")
    print("     开赛后重跑：pwpython scripts/qwb-capture.py --dump-dom  先看结构")
    return 4


if __name__ == "__main__":
    sys.exit(main())
