#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
题目 9 · 约会大作战 (Crypto, 973)  —— 完整 PoC
==============================================
目标: nc1.ctfplus.cn:<port>   (动态容器, 用 scripts/ctfplus.py start 9 取地址)

FLAG: 0xGame{Master_Origami}

------------------------------------------------------------
协议 / 两个阶段
------------------------------------------------------------
【阶段一 · 恢复服务端私钥 a】(DH 后门 + 小群攻击 + CRT)

    p = <大素数>
    g = <生成元>
    A = <服务端公钥 = g^a mod p>
    B = [12 个大整数]      # ord(B[i]) = q_i, 12 个 ~1000 的小素数
    H = [12 个 sha256]     # H[i] = sha256( B[i]^a mod p )
    a = <等待输入>

  后门: p-1 = 2 * q_1 * ... * q_12 * q_big
        其中 q_i ∈ {1019,1021,...,1091} (12 个约 1000 的小素数),
        q_big 是 257bit 大素数, 而私钥 a 被取在光滑子群范围内
        (a < Q = Π q_i, 约 121 bit), 所以 CRT 能唯一确定 a。

  攻击: 因为 ord(B[i]) = q_i, B[i]^a 只取决于 a mod q_i。
        枚举 k ∈ [0, q_i), 计算 sha256(B[i]^k mod p) 与 H[i] 比对,
        得到 a mod q_i; 12 个同余式 CRT 组合即得完整 a。
        用 pow(g, a, p) == A 自校验。

  注: 服务端把共享秘密编码为 sha256(minimal_big_endian_bytes(secret))。

【阶段二 · 中间人 + 多轮选项】

  服务端换参数进入 round 循环, 每轮给出新的 A, B (p, g 不变):
      round = n
      A = <num>
      B = <num>
      请选择中间人指数 m
      程序将计算 M = B^m mod p
      并把 long_to_bytes(M)[-1:] 作为最终给士道的选项字母（大写）
      m =

  要求: M = B^m mod p 的最后一个字节 (M mod 256) 等于我们想选的字母。
        p2-1 = 2 * q (384bit safe prime), 离散对数不可解 —— 但也不需要:
        只要顺序搜索 m, 使 pow(B,m,p) % 256 == ord(letter) 即可,
        期望 ~256 次尝试 (实测 <1200)。

  正确的选项序列 (使折纸好感度降到最低, 否则服务端回 "data over" 并断连):
      round 1 (折纸穿什么):  C = 学校泳装加狗耳，尾巴
      round 2 (折纸的回应):  A = 哈？区区母狗居然敢与人并肩而行，简直是狗胆包天！给我趴下
      round 3 (下一句):      C = 咕嘿嘿嘿，休想去
  三轮正确后服务端输出: 0xGame{Master_Origami}

------------------------------------------------------------
用法
------------------------------------------------------------
    python3 scripts/9-solve.py            # 连真实服务, 端到端拿 flag
    python3 scripts/9-solve.py --stage1   # 只做阶段一, 打印恢复出的私钥
"""

import hashlib
import re
import sys
import time

import sympy
from sympy.ntheory.modular import crt

HOST = "nc1.ctfplus.cn"
PORT = 15273  # 动态端口, 以 ctfplus.py start 9 返回的为准

# 阶段二每轮的正确选项 (由服务端剧情 / 试错确定, 会话间固定)
CORRECT_CHOICES = {1: "C", 2: "A", 3: "C"}


# ----------------------------------------------------------------------
# 阶段一
# ----------------------------------------------------------------------
def parse_params(text):
    """从服务端 banner 提取 p / g / A / B / H。"""
    def grab_int(name):
        m = re.search(rf"^{name}\s*=\s*(\d+)\s*$", text, re.M)
        return int(m.group(1)) if m else None

    def grab_list(name):
        m = re.search(rf"^{name}\s*=\s*\[(.*?)\]", text, re.M | re.S)
        if not m:
            return None
        return [x.strip().strip("'\"") for x in m.group(1).split(",") if x.strip()]

    p = grab_int("p")
    g = grab_int("g")
    A = grab_int("A")
    B = [int(x) for x in (grab_list("B") or [])]
    H = grab_list("H") or []
    return p, g, A, B, H


def element_order(e, p, factors):
    """元素 e mod p 的阶 (p-1 已给出素因子分解 factors)。"""
    o = p - 1
    for q in factors:
        while o % q == 0 and pow(e, o // q, p) == 1:
            o //= q
    return o


def _sha256_int(s):
    """服务端共享秘密的哈希编码: sha256(最小 big-endian 字节串)。"""
    return hashlib.sha256(s.to_bytes(max(1, (s.bit_length() + 7) // 8), "big")).hexdigest()


def recover_private_key(p, g, A, B, H, verbose=True):
    """小群攻击 + CRT: 从公开参数恢复服务端私钥 a。"""
    factors = sympy.factorint(p - 1)
    if verbose:
        small = sorted(q for q in factors if q < 2 ** 20)
        print(f"[*] p = {p.bit_length()} bit, isprime(p) = {sympy.isprime(p)}")
        print(f"[*] p-1 小因子 = {small}")
        print(f"[*] p-1 大因子位宽 = {max(q.bit_length() for q in factors)} bit")

    residues, moduli = [], []
    for i, (b, target) in enumerate(zip(B, H)):
        q = element_order(b, p, factors)
        assert sympy.isprime(q) and q < 2 ** 32, f"B[{i}] 的阶异常: {q}"
        found = None
        for k in range(q):
            if _sha256_int(pow(b, k, p)) == target:
                found = k
                break
        assert found is not None, f"B[{i}] (阶 {q}) 与 H[{i}] 哈希不匹配"
        residues.append(found)
        moduli.append(q)
        if verbose:
            print(f"[+] ord(B[{i}]) = {q:5d}  =>  a ≡ {found} (mod {q})")

    Q = 1
    for q in moduli:
        Q *= q
    a = int(crt(moduli, residues)[0])
    if verbose:
        print(f"[*] Q = {Q} ({Q.bit_length()} bit)")
        print(f"[*] CRT 恢复私钥 a = {a}")

    # 后门自校验: 恢复出的私钥必须能还原公钥
    assert pow(g, a, p) == A, "CRT 结果未通过 pow(g,a,p)==A 校验"
    if verbose:
        print("[+] 校验通过: pow(g, a, p) == A")
    return a


# ----------------------------------------------------------------------
# 阶段二
# ----------------------------------------------------------------------
def find_m(B, p, letter, maxm=5_000_000):
    """找最小 m 使 (B^m mod p) 的最后一个字节 == ord(letter)。"""
    target, x = ord(letter), 1
    for m in range(1, maxm):
        x = x * B % p
        if x % 256 == target:
            return m
    return None


def parse_round(out):
    """取本轮最后一次出现的 A / B；p, g 只在阶段二头部出现一次。"""
    A = int(re.findall(r"^A = (\d+)", out, re.M)[-1])
    B = int(re.findall(r"^B = (\d+)", out, re.M)[-1])
    pg = re.findall(r"^p = (\d+)", out, re.M)
    gg = re.findall(r"^g = (\d+)", out, re.M)
    srnd = re.findall(r"^round = (\d+)", out, re.M)
    return (int(pg[-1]) if pg else None, int(gg[-1]) if gg else None,
            A, B, (int(srnd[-1]) if srnd else None))


def read_until(io, marker=b"m = ", timeout=40):
    """读到 marker 为止；连接关闭时把残余数据一起返回 (避免丢 flag)。"""
    buf, t0 = b"", time.time()
    while time.time() - t0 < timeout:
        try:
            d = io.recv(timeout=2)
        except Exception:
            return buf, True
        if not d:
            if not io.connected():
                return buf, True
            continue
        buf += d
        if buf.endswith(marker):
            return buf, False
    return buf, False


def solve_remote(verbose=True):
    from pwn import remote, context
    context.log_level = "error"

    io = remote(HOST, PORT)

    # ---- 阶段一: 恢复私钥 a ----
    banner = read_until(io, b"a = ", timeout=40)[0].decode(errors="replace")
    p, g, A, B, H = parse_params(banner)
    assert p and g and A and B and H, "阶段一参数解析失败"
    a = recover_private_key(p, g, A, B, H, verbose=verbose)
    io.sendline(str(a).encode())
    if verbose:
        print("[*] 已提交私钥 a, 进入中间人阶段")

    # ---- 阶段二: 多轮选项 ----
    P = G = None
    rnd = 0
    while rnd < 60:
        blk, closed = read_until(io)
        out = blk.decode(errors="replace")
        if verbose:
            print(f"--- server ---\n{out}")
        flag = re.search(r"(0xGame\{[^}]*\}|flag\{[^}]*\})", out)
        if flag:
            io.close()
            return flag.group(1)
        if closed or "data over" in out:
            io.close()
            return None

        p2, g2, A2, B2, srnd = parse_round(out)
        if p2:
            P, G = p2, g2
        rnd += 1
        letter = CORRECT_CHOICES.get(rnd)
        if letter is None:
            if verbose:
                print(f"[!] 第 {rnd} 轮没有预设选项, 停止")
            io.close()
            return None
        m = find_m(B2, P, letter)
        assert m is not None, f"第 {rnd} 轮找不到 m"
        if verbose:
            print(f"[+] round {rnd}: 选 {letter}, m = {m}")
        io.sendline(str(m).encode())
    io.close()
    return None


def stage1_only():
    from pwn import remote, context
    context.log_level = "error"
    io = remote(HOST, PORT)
    banner = read_until(io, b"a = ", timeout=40)[0].decode(errors="replace")
    p, g, A, B, H = parse_params(banner)
    a = recover_private_key(p, g, A, B, H)
    print("a =", a)
    io.close()


if __name__ == "__main__":
    if "--stage1" in sys.argv:
        stage1_only()
    else:
        flag = solve_remote()
        print("\n" + "=" * 60)
        print("FLAG:", flag if flag else "NONE")
        print("=" * 60)
