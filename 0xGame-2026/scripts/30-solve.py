#!/usr/bin/env python3
"""题目 30 · ATP代码实验  (Web, 639 分)

思路
----
平台是一个「C 代码在线评测」Web 应用（gunicorn）。前端 /static/submit.js 直接
POST JSON {"code": "..."} 到 /submit，后端把 code 交给 gcc 编译并回显结果。

页面自己把「官方参考代码」放在 <pre id="ref-code"> 里，并且明说
「提交下方的官方参考代码即可通过」「要求提交的代码与参考代码完全一致」。

所以本题的"漏洞"（更准确地说是设计意图）就是：
  * 前端 protect.js 的「禁止粘贴 / 禁用右键 / 禁用 F12 / 反调试」全是纯客户端限制，
    用 curl 直接 POST /submit 完全绕过；
  * 后端不做「必须人类逐字输入」的任何校验，只比对提交内容与参考代码是否一致；
  * 于是把页面里的参考代码原样 POST 回去即得 flag。

注意：后端返回的是 JSON，字段 ok / message / flag，flag 由服务端在评测通过时下发，
并不是从编译器报错或文件读取里泄露出来的。题目描述里「为你提供了参考答案~」
就是字面意义的提示 —— 抄下来交上去。

用法
----
    python3 scripts/30-solve.py                      # 用 brief 里的固定地址
    python3 scripts/30-solve.py http://host/         # 指定地址
    python3 scripts/30-solve.py --code path/to.c     # 用本地已有的 .c 文件
"""
import argparse
import html
import json
import re
import sys
import urllib.request

DEFAULT_URL = ("http://5000-e088ee42-da25-4089-8949-f93a138d04a5"
               ".challenge.ctfplus.cn/")


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def extract_ref_code(page_html: str) -> str:
    """从 <pre id="ref-code">...</pre> 里抽出官方参考代码。

    页面里 < > " & 都是 HTML 实体编码的（&lt; &gt; &#34; &amp;），
    必须 html.unescape 还原成真正的 C 源码再提交，否则后端比对不通过。
    """
    m = re.search(r'<pre id="ref-code">(.*?)</pre>', page_html, re.S)
    if not m:
        sys.exit("[-] 页面上没找到 <pre id=\"ref-code\">，页面结构可能变了")
    code = html.unescape(m.group(1))
    if code.startswith("\n"):
        code = code[1:]
    return code


def submit(url: str, code: str) -> dict:
    body = json.dumps({"code": code}).encode()
    req = urllib.request.Request(
        url.rstrip("/") + "/submit",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:          # 非 2xx 也尽量把 body 读出来
        raw = e.read().decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"ok": False, "message": f"HTTP {e.code}: {raw[:500]}"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="?", default=DEFAULT_URL)
    ap.add_argument("--code", help="直接用这个 .c 文件，跳过抓取页面")
    args = ap.parse_args()

    if args.code:
        code = open(args.code, encoding="utf-8").read()
        print(f"[*] 从 {args.code} 读取代码（{len(code)} 字节）")
    else:
        page = fetch(args.url)
        code = extract_ref_code(page)
        print(f"[*] 从 {args.url} 抓到官方参考代码（{len(code)} 字节）")

    resp = submit(args.url, code)
    print("[*] /submit 响应:", json.dumps(resp, ensure_ascii=False))

    if resp.get("flag"):
        print("[+] FLAG:", resp["flag"])
        print("[*] 提交: python3 scripts/ctfplus.py submit 30 '%s'" % resp["flag"])
        return 0
    print("[-] 没拿到 flag，检查是不是地址变了或页面结构变了")
    return 1


if __name__ == "__main__":
    sys.exit(main())
