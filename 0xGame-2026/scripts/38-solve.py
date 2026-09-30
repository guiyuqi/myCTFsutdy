#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
38 · 旧时代的信号  (Reverse, 792 pts)  —— solve script

附件: firmware/38_旧时代的信号/attachment3.zip -> attachment3.EXE (192 bytes)

分析结论
--------
`file` 报 "MS-DOS executable, MZ for MS-DOS"。
MZ 头: header size = 2 paragraphs (0x20 bytes), initial CS:IP = 0000:0000,
        initial SS:SP = 0000:0002
=> 载入镜像 = 文件去掉 0x20 字节头, 入口就是镜像偏移 0。

16 位实模式代码 (镜像偏移 0x00 = 文件偏移 0x20, objdump vma 0x100):

    0e            push cs
    1f            pop  ds
    0e            push cs
    07            pop  es
    fc            cld
    be 5d 00      mov  si, 0x5d        ; 密文源 (镜像偏移 0x5d = 文件 0x7d)
    bf 7e 00      mov  di, 0x7e        ; 明文目标 (镜像偏移 0x7e = 文件 0x9e)
    b9 21 00      mov  cx, 0x21        ; 33 字节
    b3 a7         mov  bl, 0xa7        ; 密钥状态初值
    30 ff         xor  bh, bh          ; 计数器 i = 0
loop:
    ac            lodsb                ; al = *si++
    d0 c8 *3      ror  al, 1  (x3)     ; == ror al,3
    2c 07         sub  al, 7
    28 f8         sub  al, bh          ; al -= i
    30 d8         xor  al, bl
    aa            stosb                ; *di++ = al
    00 c3         add  bl, al          ; ---- 密钥流更新 ----
    d0 c3         rol  bl, 1
    30 fb         xor  bl, bh
    fe c7         inc  bh
    e2 e8         loop loop
    b0 24 / aa    mov  al,'$' ; stosb  ; DOS int 21h/AH=09 需要 '$' 结尾
    ...           int 21h AH=09 打印 "Signal recovered: " + 明文 + CRLF
    b8 00 4c cd 21  int 21h AH=4Ch    ; exit

即: 对 33 字节密文做
    p[i] = ((ror(c[i],3) - 7 - i) ^ k[i]) & 0xff
    k[0]  = 0xa7
    k[i+1] = rol((k[i] + p[i]) & 0xff, 1) ^ i

用法: python3 scripts/38-solve.py [attachment3.EXE]
"""
import sys
import os

DEFAULT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "firmware", "38_旧时代的信号", "attachment3.zip",
)


def load_image(path):
    """读 .EXE 或 .zip, 返回去掉 MZ 头之后的载入镜像。"""
    if path.endswith(".zip"):
        import zipfile
        with zipfile.ZipFile(path) as z:
            name = z.namelist()[0]
            raw = z.read(name)
    else:
        raw = open(path, "rb").read()
    assert raw[:2] == b"MZ", "not an MZ executable"
    hdr_paras = int.from_bytes(raw[0x08:0x0A], "little")
    off = hdr_paras * 16
    return raw, raw[off:]


def decrypt(image, src_off=0x5D, n=0x21):
    k = 0xA7                      # bl
    out = bytearray()
    for i in range(n):
        al = image[src_off + i]
        al = ((al >> 3) | (al << 5)) & 0xFF     # ror al,3
        al = (al - 7) & 0xFF
        al = (al - i) & 0xFF                    # sub bh (bh == i)
        al = (al ^ k) & 0xFF
        out.append(al)
        k = (k + al) & 0xFF                     # add bl,al
        k = ((k << 1) | (k >> 7)) & 0xFF        # rol bl,1
        k = (k ^ i) & 0xFF                      # xor bl,bh
    return bytes(out)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    raw, image = load_image(path)
    print(f"[*] file size      : {len(raw)} bytes, load image {len(image)} bytes")
    print(f"[*] ciphertext     : {image[0x5D:0x5D + 0x21].hex()}")
    plain = decrypt(image)
    print(f"[*] decrypted      : {plain}")
    text = plain.decode("latin1")
    print(f"[*] DOS would print: Signal recovered: {text}")
    # 单独的独立校验: 用 unicorn 16 位实模式真跑一遍那 33 次循环
    try:
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UcError
        from unicorn.x86_const import (
            UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES,
            UC_X86_REG_SS, UC_X86_REG_SP,
        )
        SEG, BASE = 0x1000, 0x1000 << 4
        mu = Uc(UC_ARCH_X86, UC_MODE_16)
        mu.mem_map(BASE, 0x10000)
        mu.mem_write(BASE, image)
        for r in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
            mu.reg_write(r, SEG)
        mu.reg_write(UC_X86_REG_SP, 0x400)
        mu.hook_add(__import__("unicorn").UC_HOOK_INTR, lambda *a: None)
        try:
            mu.emu_start(0x0, 0x2A)             # 到 loop 结束
        except UcError:
            pass                                # 之后是 int 21h / 数据区
        emu = bytes(mu.mem_read(BASE + 0x7E, 0x21))
        ok = emu == plain
        print(f"[*] unicorn verify : {emu}  -> {'MATCH' if ok else 'MISMATCH'}")
    except ImportError:
        print("[*] unicorn not available, skipped emulation cross-check")
    print(f"[+] FLAG: {text}")


if __name__ == "__main__":
    main()
