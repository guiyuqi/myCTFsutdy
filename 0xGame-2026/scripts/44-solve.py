#!/usr/bin/env python3
"""44 · 粗心的小x —— git 历史泄露 API KEY → 逐段 base64 拼 flag

思路:
  1. AI-chat-project.zip 内含完整 .git/ 目录（小x 不懂 git，把 .env 提交进了仓库）
  2. 仓库里有 3 个 "API KEY"，每个都形如 sk-<base64>，解出来是 "partN:<flag 片段>"
     - .env 工作树/HEAD       : sk-W9kDcGFydDM6X3RoMW5nc190MF9nMXR9   -> part3
     - .env 的所有历史版本   : 同上（.env 自 initial commit 起未变）
     - chat.py 历史 commit 79edd41（被 refactor 删掉）:
                              sk-m2PzcGFydDI6dXBsT0BkX3ByMXY0dDM   -> part2
     - 另有 chat_export.json（对话导出）里小x 贴出的:
                              sk-T7xQcGFydDE6MHhHYW1le0QwX24wdF8   -> part1
     sk- 后 4 个字符是随机填充字节（非 UTF-8），真正的 base64 从 'part' 处开始。

用法: python3 scripts/44-solve.py [--json]
"""
import base64
import glob
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FW = os.path.join(ROOT, "firmware", "44_粗心的小x")
WORK = os.path.join(ROOT, "work", "44_git_leak")

KEY_RE = re.compile(r"sk-[A-Za-z0-9_+/=@-]{8,}")
B64CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


def extract_keys():
    """从 zip 的 .git 对象库 + 对话导出里收集所有 sk- 串。"""
    keys = set()

    # A) 对话导出 JSON（含小x 手贴的 key）
    export = os.path.join(FW, "chat_export.json")
    if os.path.exists(export):
        keys.update(KEY_RE.findall(open(export, encoding="utf-8").read()))

    # B) 解压 zip，遍历 .git 对象库中的每个 blob
    proj = os.path.join(WORK, "project", "AI-chat-project")
    if not os.path.isdir(os.path.join(proj, ".git")):
        os.makedirs(WORK, exist_ok=True)
        subprocess.run(["unzip", "-o", "-q", os.path.join(FW, "AI-chat-project.zip"),
                        "-d", os.path.join(WORK, "project")], check=True)
    if os.path.isdir(os.path.join(proj, ".git")):
        out = subprocess.run(
            ["git", f"--git-dir={os.path.join(proj, '.git')}",
             "cat-file", "--batch-all-objects",
             "--batch-check=%(objectname) %(objecttype)"],
            capture_output=True, text=True, check=True).stdout
        for line in out.splitlines():
            sha, otype = line.split()
            if otype != "blob":
                continue
            blob = subprocess.run(
                ["git", f"--git-dir={os.path.join(proj, '.git')}", "cat-file", "blob", sha],
                capture_output=True).stdout
            keys.update(KEY_RE.findall(blob.decode("utf-8", "replace")))
        # 工作树里未提交的改动也一并看
        for f in glob.glob(os.path.join(proj, "**", "*"), recursive=True):
            if os.path.isfile(f) and "/.git/" not in f:
                try:
                    keys.update(KEY_RE.findall(open(f, encoding="utf-8").read()))
                except (UnicodeDecodeError, OSError):
                    pass
    return keys


def decode_key(key):
    """返回 (part_name, fragment) 或 None。

    sk- 之后紧跟 4 个随机字符，是出题人给 base64 加的"盐"：整串 base64 解出来的
    明文前 3 字节是垃圾（如 b'O\\xbcP'），从第 4 字节起才是 'partN:<片段>'。
    另有部分 key 把 '+' 写成 '@'（防止 ChatGPT 顺手解码），需要还原。
    """
    body = key[3:]
    for cand in (body, body.replace("@", "+")):   # 原样 / 还原 '+'
        cand = re.sub(r"[^A-Za-z0-9+/=]", "", cand)
        try:
            raw = base64.b64decode(cand + "=" * (-len(cand) % 4))
        except Exception:
            continue
        txt = raw.decode("utf-8", "replace")
        m = re.search(r"part(\d+)\s*:\s*", txt, re.I)
        if m:
            return f"part{m.group(1)}", txt[m.end():]
    return None


def main():
    fragments = {}
    for k in sorted(extract_keys()):
        d = decode_key(k)
        if d:
            fragments.setdefault(d[0], set()).add(d[1])
    if not fragments:
        print("[-] 未找到任何 part 片段", file=sys.stderr)
        return 1

    ordered = []
    for name in sorted(fragments):
        vals = fragments[name]
        if len(vals) > 1:
            print(f"[!] {name} 有多份不同片段: {vals}", file=sys.stderr)
        ordered.append(sorted(vals)[0])
    flag = "".join(ordered)

    print("[*] 片段:")
    for name in sorted(fragments):
        print(f"    {name}: {sorted(fragments[name])[0]}")
    print(f"[+] FLAG: {flag}")
    if "--json" in sys.argv:
        print(json.dumps({"flag": flag, "fragments": {k: sorted(v)[0] for k, v in fragments.items()}},
                         ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
