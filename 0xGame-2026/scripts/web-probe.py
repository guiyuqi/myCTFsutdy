#!/usr/bin/env python3
"""
web-probe.py —— 用真实浏览器侦察一个 web 靶机

专为 CTF web 题设计：把"人在浏览器里点一遍"变成一条命令。
抓取标题/正文/截图/console/网络请求/cookie/localStorage，
其中**网络请求列表**最有用 —— 能直接暴露前端调用的隐藏 API。

用法（先 source scripts/tools-env.sh）:
    pwpython scripts/web-probe.py <url> [-o 输出目录] [--wait 毫秒] [--header K:V ...]

例:
    pwpython scripts/web-probe.py http://10.0.0.5:8080/
    pwpython scripts/web-probe.py http://target/ --wait 3000 -o evidence/host1
"""
import argparse, json, os, sys, time
from playwright.sync_api import sync_playwright

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("-o", "--out", default=None, help="证据输出目录")
    ap.add_argument("--wait", type=int, default=1500, help="页面加载后额外等待毫秒（SPA 用）")
    ap.add_argument("--header", action="append", default=[], help="额外请求头 K:V，可重复")
    ap.add_argument("--full", action="store_true", help="整页截图")
    a = ap.parse_args()

    out = a.out or os.path.join("evidence", "webprobe-" + time.strftime("%H%M%S"))
    os.makedirs(out, exist_ok=True)

    console, requests, responses = [], [], []

    with sync_playwright() as p:
        b = p.chromium.launch(args=["--no-sandbox", "--ignore-certificate-errors"])
        ctx = b.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 900})
        if a.header:
            h = {}
            for kv in a.header:
                k, _, v = kv.partition(":")
                h[k.strip()] = v.strip()
            ctx.set_extra_http_headers(h)
        pg = ctx.new_page()
        pg.on("console", lambda m: console.append(f"[{m.type}] {m.text}"))
        pg.on("request", lambda r: requests.append(f"{r.method} {r.url}"))
        pg.on("response", lambda r: responses.append(f"{r.status} {r.url}"))

        resp = pg.goto(a.url, wait_until="domcontentloaded", timeout=45000)
        pg.wait_for_timeout(a.wait)

        print(f"=== URL   : {pg.url}")
        print(f"=== 状态  : {resp.status if resp else '?'}")
        print(f"=== 标题  : {pg.title()}")
        try:
            body = pg.inner_text("body")[:2000]
        except Exception:
            body = "(取不到正文)"
        print(f"=== 正文(前2000字) ===\n{body}\n")

        pg.screenshot(path=os.path.join(out, "screenshot.png"), full_page=a.full)
        ctx.storage_state(path=os.path.join(out, "storage.json"))

        cookies = ctx.cookies()
        ls = pg.evaluate("() => { try { return JSON.stringify(localStorage) } catch(e) { return '{}' } }")

        print(f"=== 网络请求 ({len(requests)}) —— 找隐藏 API 看这里 ===")
        for r in requests[:60]:
            print("   ", r)
        print(f"=== console ({len(console)}) ===")
        for c in console[:40]:
            print("   ", c)
        print(f"=== cookie ({len(cookies)}) ===")
        for c in cookies:
            print(f"    {c['name']} = {c['value'][:80]}")
        print(f"=== localStorage ===\n   {ls[:800]}")

        json.dump({"url": pg.url, "title": pg.title(), "status": resp.status if resp else None,
                   "requests": requests, "responses": responses,
                   "console": console, "cookies": cookies, "localStorage": ls, "body": body},
                  open(os.path.join(out, "probe.json"), "w"), indent=2, ensure_ascii=False)
        b.close()

    print(f"\n[+] 证据已存: {out}/  (screenshot.png, storage.json, probe.json)")

if __name__ == "__main__":
    main()
