#!/usr/bin/env python3
"""题目 17 · ！？数学基础？！ —— "Scripting 101" 速算题（成品脚本）

服务协议（手工探测，见 evidence/17-banner.txt）：

    ==================================================
                       (Scripting 101)
    ==================================================
    系统提示：连续答对 100 道随机四则运算题，即可获得 Flag！
    [round:1/100 ]
    calculate: 307 一 284 = ?
    Input your answer:

关键坑：**运算符是中文/全角字符**，不是 ASCII！
  - `一` (U+4E00, 汉字"一") 表示减号 `-`  ← NFKC 不会转换，必须手工映射
  - `×` / `x` 表示乘号
  - `÷` 表示除号
  - 可能还有全角 `＋ － ＊ ／ ＝ ？`

策略：先 NFKC 归一化（处理全角→半角），再做汉字算符映射，
然后只按 `[0-9+-*/() ]` 提取表达式，最后安全求值。
每题限时很短（不回答 -> "[!] Timeout ! ! !"），所以必须脚本化。
"""
import os
import re
import sys
import time
import unicodedata

from pwn import context, remote

context.log_level = "error"  # 关掉 pwntools debug，避免每行阻塞/刷屏

HOST = "nc1.ctfplus.cn"
PORT = 24816
ROUNDS = 100

# NFKC 之后仍然残留的 CJK / 全角算符 -> ASCII
CJK_OPS = {
    "\u4e00": "-",  # 一 (U+4E00) 汉字"一" = 减号
    "\u4e8c": "-",  # 二（保险）
    "\u52a0": "+",  # 加
    "\u51cf": "-",  # 减
    "\u4e58": "*",  # 乘
    "\u9664": "/",  # 除
    "\u00d7": "*",  # × multiplication sign
    "\u00f7": "/",  # ÷ division sign
    "\u2212": "-",  # − minus sign
    "\uff0b": "+",  # ＋
    "\uff0d": "-",  # －
    "\uff0a": "*",  # ＊
    "\uff0f": "/",  # ／
    "\uff58": "*",  # ｘ fullwidth x
    "x": "*",
    "X": "*",
    "\u0445": "*",  # х cyrillic (保险)
}

TEXT_EXPR = re.compile(r"calculate:\s*([0-9+\-*/() ]+?)\s*=\s*\?")
SAFE = re.compile(r"^[0-9+\-*/() ]+$")

OPS_SEEN = {}  # 非数字非空格字符 -> 出现次数（用于证据）



def workspace_root() -> str:
    """向上查找含 evidence/ 与 AGENTS.md 的工作区根（work/ 或 scripts/ 下都能跑）。"""
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        if os.path.isdir(os.path.join(d, "evidence")) and \
           os.path.exists(os.path.join(d, "AGENTS.md")):
            return d
        d = os.path.dirname(d)
    return os.getcwd()


def normalize(s: str) -> str:
    s = unicodedata.normalize("NFKC", s)
    return "".join(CJK_OPS.get(ch, ch) for ch in s)


def safe_eval(py: str) -> int:
    """按 C 语言语义求值（整数截断）。

    Python 的 `/` 是浮点真除法，`//` 是向下取整 —— 对负数与 C 的截断不同，
    所以统一先做精确除法再 int() 截断。
    """
    assert SAFE.match(py), f"unsafe expression: {py!r}"
    return int(eval(py, {"__builtins__": {}}, {}))  # noqa: S307


def main() -> int:
    io = remote(HOST, PORT)
    t0 = time.time()
    buf = ""
    full = []  # 完整原始输出（证据用）

    for rnd in range(1, ROUNDS + 1):
        try:
            chunk = io.recvuntil(b"Input your answer:", timeout=8).decode("utf-8", "replace")
        except Exception as e:  # EOF / timeout
            sys.stderr.write(f"[!] round {rnd}: recvuntil failed: {e}\n")
            sys.stderr.write(f"[!] buffer tail: {buf[-800:]!r}\n")
            break
        full.append(chunk)
        buf += chunk

        norm = normalize(buf)
        ms = list(TEXT_EXPR.finditer(norm))
        if not ms:
            sys.stderr.write(f"[!] round {rnd}: no expression in {buf[-400:]!r}\n")
            break
        m = ms[-1]

        # 记录本轮算符的**原始**字符（证据：服务端到底发了哪些 Unicode 算符）
        for line in buf.splitlines():
            if "calculate" in line:
                rhs = line.split("calculate:", 1)[1]
                for ch in rhs:
                    if not ch.isdigit() and ch not in " ()?:=":
                        OPS_SEEN[ch] = OPS_SEEN.get(ch, 0) + 1

        expr = m.group(1).strip()
        ans = safe_eval(expr)
        io.sendline(str(ans).encode())
        buf = ""  # recvuntil 已吃掉整段，多余数据留在 pwntools 内部缓冲区

    elapsed = time.time() - t0

    # 最后一题之后：拿 flag（若给的是 shell 就 cat，否则直接读输出）
    io.sendline(b"cat /home/ctf/flag; cat flag; ls -la /home/ctf 2>/dev/null")
    try:
        rest = io.recvall(timeout=10)
    except Exception:
        rest = b""
    tail = rest.decode("utf-8", "replace")
    full.append(tail)
    out = "".join(full)

    sys.stdout.write(tail)
    sys.stdout.write(f"\n--- elapsed {elapsed:.2f}s  ops_seen={OPS_SEEN} ---\n")
    ev = os.path.join(workspace_root(), "evidence")
    os.makedirs(ev, exist_ok=True)
    with open(os.path.join(ev, "17-transcript.txt"), "w") as f:
        f.write(out)
    with open(os.path.join(ev, "17-ops-seen.txt"), "w") as f:
        for ch, n in sorted(OPS_SEEN.items()):
            f.write(f"{ch!r} U+{ord(ch):04X} count={n} -> ascii {CJK_OPS.get(ch, ch)!r}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# 注：容器槽位全队共享，跑之前确认地址可用（父代理已开好时不要重复 start）。
# 复现：source ~/re-tools/fw-env.sh && python3 scripts/17-solve.py
# 若报 "Could not connect"，说明容器槽位已被 stop，需要先
#   python3 scripts/ctfplus.py start 17
