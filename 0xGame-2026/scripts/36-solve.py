#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
36 · ez_upx —— 可复现解题脚本
================================

题目给的是 UPX 加壳的 PE64 (attachment1.exe)。环境里没有 upx 可执行文件，
所以本脚本不依赖 upx：直接用 Unicorn 把壳自己的 stub 跑起来（脱壳），
再从内存镜像里恢复校验逻辑所需的常量，解出 flag。

原理
----
1. 载入壳 PE：UPX0(VA 0x1000, 未压缩区) / UPX1(VA 0xc000, stub+压缩数据) /
   UPX2(VA 0xf000, stub 自己的导入表)。
2. 按 PE 头把三个节映射到镜像基址 0x400000，伪造 stub 需要的 5 个导入
   (LoadLibraryA / GetProcAddress / VirtualProtect / ExitProcess / exit)，
   然后从 AddressOfEntryPoint 跑 stub。
   stub 会用 UPX 自带的 LZMA 解码器把原始镜像解压到 VA 0x401000（长度 u_len），
   再重建原程序的导入表（调用 GetProcAddress），最后 VirtualProtect + 跳 OEP。
3. 当 RIP 第一次落回已解压区域（< 0x400000+0xc000）就是 OEP，停下 dump 内存。

校验逻辑（脱壳后可读）
----------------------
    xor_with_key(input, key, keylen)      // 0x401576: buf[i] ^= key[i % keylen]
    base64_encode(buf)                    // 0x4018ab 里的 base64 编码器
    strcmp(b64, "RhExDlhVDSdGGEJHKRBGGmpbGFkBMGBgLkhXTkg=")
    且 key = "vivo50"

即: flag -> 与 "vivo50" 循环异或 -> base64 编码 -> 常量比较。
反推: base64_decode(常量) 再异或 "vivo50" 即得 flag。

用法
----
    python3 scripts/36-solve.py            # 自动脱壳 + 自动求解
    python3 scripts/36-solve.py --no-emu   # 复用已脱壳镜像(work/36_ez_upx/unpacked_image.bin)
"""
import argparse
import base64
import os
import re
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(REPO, 'work', '36_ez_upx')
DEFAULT_PE = os.path.join(REPO, 'firmware', '36_ez_upx', 'attachment1.exe')
CACHE = os.path.join(WORK, 'unpacked_image.bin')

IMG = 0x400000
STACK = 0x00200000
STACK_SIZE = 0x00100000
FAKE = 0x00900000
MAX_INSNS = 200_000_000
IMAGE_SIZE = 0x10000


# --------------------------------------------------------------------------
# 1. 脱壳：用 Unicorn 跑壳 stub
# --------------------------------------------------------------------------
def parse_pe(data):
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    coff = pe + 4
    nsec = struct.unpack_from('<H', data, coff + 2)[0]
    optsz = struct.unpack_from('<H', data, coff + 16)[0]
    opt = coff + 20
    entry = struct.unpack_from('<I', data, opt + 16)[0]
    imagebase = struct.unpack_from('<Q', data, opt + 24)[0]
    sizeimg = struct.unpack_from('<I', data, opt + 56)[0]
    imp_rva, imp_sz = struct.unpack_from('<II', data, opt + 112 + 8)  # dir[1]
    sh = opt + optsz
    sections = []
    for i in range(nsec):
        b = sh + i * 40
        name = data[b:b + 8].rstrip(b'\0').decode('latin1')
        vs, va, rs, rp = struct.unpack_from('<IIII', data, b + 8)
        sections.append((name, va, vs, rp, rs))
    return dict(entry=entry, imagebase=imagebase, sizeimg=sizeimg, nsec=nsec,
                sections=sections, imp=(imp_rva, imp_sz))


def unpack_with_unicorn(pe_path):
    from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
    from unicorn.x86_const import (
        UC_X86_REG_RSP, UC_X86_REG_RIP, UC_X86_REG_RAX,
        UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8)

    data = open(pe_path, 'rb').read()
    hdr = parse_pe(data)
    assert hdr['imagebase'] == IMG, hex(hdr['imagebase'])
    sections = hdr['sections']

    def va2off(va, sections=sections):
        for _n, sva, vs, rp, rs in sections:
            if sva <= va < sva + max(vs, rs):
                return rp + (va - sva)
        return va - IMG

    def read_cstr(va):
        o = va2off(va)
        return data[o:data.index(b'\0', o)].decode('latin1')

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(IMG, 0x20000)
    mu.mem_map(STACK, STACK_SIZE)
    mu.mem_map(FAKE, 0x1000)
    for _n, va, vs, rp, rs in sections:
        if rs:
            mu.mem_write(IMG + va, data[rp:rp + rs])

    # 把壳自己的导入表重定向到假地址，稍后 hook 掉
    fake_map, k = {}, 0
    imp_rva = hdr['imp'][0]
    d = imp_rva
    while True:
        _oft, _ts, _fwd, name_rva, ft = struct.unpack_from('<IIIII', data, va2off(d))
        if not (name_rva or ft):
            break
        dll = read_cstr(name_rva)
        j = 0
        while True:
            val = struct.unpack_from('<Q', data, va2off(ft + j * 8))[0]
            if val == 0:
                break
            fname = ('ord#%d' % (val & 0xffff)) if val >> 63 else read_cstr(val + 2)
            fake = FAKE + k * 0x10
            k += 1
            fake_map[fake] = (dll, fname)
            mu.mem_write(IMG + ft + j * 8, struct.pack('<Q', fake))
            j += 1
        d += 20

    state = {'stop': None, 'insns': 0}

    def on_code(mu, address, size, user):
        state['insns'] += 1
        if state['insns'] > MAX_INSNS:
            state['stop'] = 'insn-cap'
            mu.emu_stop()
            return
        if IMG <= address < IMG + 0xc000:          # 落回已解压区域 => OEP
            state['stop'] = 'oep'
            mu.emu_stop()
            return
        info = fake_map.get(address)
        if info is None:
            return
        _dll, fname = info
        rsp = mu.reg_read(UC_X86_REG_RSP)
        ret = struct.unpack('<Q', mu.mem_read(rsp, 8))[0]
        rcx = mu.reg_read(UC_X86_REG_RCX)
        rdx = mu.reg_read(UC_X86_REG_RDX)
        if fname == 'GetProcAddress':
            nm = bytes(mu.mem_read(rdx, 64)).split(b'\0')[0].decode('latin1')
            rax = 0x7f000000 + (hash(nm) & 0xffff)
            fake_map.setdefault(rax, ('*', nm))
            mu.reg_write(UC_X86_REG_RAX, rax)
        elif fname == 'LoadLibraryA':
            mu.reg_write(UC_X86_REG_RAX, 0x12340000)
        elif fname == 'VirtualProtect':
            mu.reg_write(UC_X86_REG_RAX, 1)
        elif fname in ('ExitProcess', 'exit'):
            state['stop'] = 'exit'
            mu.emu_stop()
            return
        else:
            mu.reg_write(UC_X86_REG_RAX, 0)
        mu.reg_write(UC_X86_REG_RSP, rsp + 8)      # 模拟 ret
        mu.reg_write(UC_X86_REG_RIP, ret)

    mu.hook_add(UC_HOOK_CODE, on_code, begin=IMG, end=IMG + 0x20000 - 1)
    mu.hook_add(UC_HOOK_CODE, on_code, begin=FAKE, end=FAKE + 0xfff)
    mu.hook_add(UC_HOOK_CODE, on_code, begin=0x7f000000, end=0x7fffffff)
    mu.reg_write(UC_X86_REG_RSP, STACK + STACK_SIZE - 0x2000)
    mu.reg_write(UC_X86_REG_RIP, IMG + hdr['entry'])
    try:
        mu.emu_start(IMG + hdr['entry'], IMG + IMAGE_SIZE, count=MAX_INSNS)
    except UcError as e:
        sys.stderr.write('[!] emulation error %s\n' % e)
    sys.stderr.write('[+] stub stopped: %s, insns=%d, oep_rip=%#x\n'
                     % (state['stop'], state['insns'], mu.reg_read(UC_X86_REG_RIP)))
    return bytes(mu.mem_read(IMG, IMAGE_SIZE))


# --------------------------------------------------------------------------
# 2. 求解：从脱壳镜像里找 b64 常量 + 循环异或 key
# --------------------------------------------------------------------------
def solve(img):
    blobs = re.findall(rb'[A-Za-z0-9+/]{16,}={0,2}', img)
    keys = [s for s in re.findall(rb'[\x20-\x7e]{4,24}', img)]
    for b in blobs:
        try:
            raw = base64.b64decode(b, validate=True)
        except Exception:
            continue
        if not raw:
            continue
        for k in keys:
            pt = bytes(c ^ k[i % len(k)] for i, c in enumerate(raw))
            if re.fullmatch(rb'0xGame\{[\x20-\x7e]+\}', pt) or \
               re.fullmatch(rb'flag\{[\x20-\x7e]+\}', pt):
                return pt.decode(), b.decode(), k.decode()
    return None, None, None


def ensure_pe():
    """附件是 zip；若没解压过就先解压到 work/36_ez_upx/。"""
    if os.path.exists(DEFAULT_PE):
        return DEFAULT_PE
    import zipfile
    zp = os.path.join(REPO, 'firmware', '36_ez_upx', 'attachment1.zip')
    os.makedirs(WORK, exist_ok=True)
    with zipfile.ZipFile(zp) as z:
        z.extractall(WORK)
    out = os.path.join(WORK, 'attachment1.exe')
    return out if os.path.exists(out) else DEFAULT_PE


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pe', default=None)
    ap.add_argument('--no-emu', action='store_true',
                    help='复用缓存的脱壳镜像，不重新仿真')
    args = ap.parse_args()
    args.pe = args.pe or ensure_pe()

    if args.no_emu and os.path.exists(CACHE):
        img = open(CACHE, 'rb').read()
        sys.stderr.write('[+] 使用缓存镜像 %s\n' % CACHE)
    else:
        img = unpack_with_unicorn(args.pe)
        os.makedirs(WORK, exist_ok=True)
        open(CACHE, 'wb').write(img)
        sys.stderr.write('[+] 脱壳镜像已写入 %s\n' % CACHE)

    flag, b64, key = solve(img)
    if not flag:
        print('[-] 未能在镜像中自动定位 flag')
        return 1
    print('b64 常量 : %s' % b64)
    print('xor key  : %s' % key)
    print('FLAG     : %s' % flag)
    return 0


if __name__ == '__main__':
    sys.exit(main())
