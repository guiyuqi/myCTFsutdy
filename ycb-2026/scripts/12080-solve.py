#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""12080 · Jammed (2026 羊城杯 · MISC) — 可复现解题脚本

机制（本脚本自检，不依赖 sha256.txt —— 那个文件是干扰项）：
  两页 = 同 24 条记录的两次"卡字"打印。同一格的两页字符必在同一字球列（11 列 × 4 行）：
      S 行 = 两页都印过的字符   A 行 = 只有 A 页印过   D 行 = 只有 B 页印过   X 行 = 从未印出
  两个硬锚点：
      序号列 48 格全 combo SD ⇒ 真值行 = D（真值必是数字，数字只在 D 行）
      分隔符列 48 格全 combo AS（A 印 '/'，B 印 l 字形）⇒ 真值行 = A
  ⇒ combo→真值行被迫唯一：SS→S, SD→D, AS→A, AD→X
  片段列 12 格落在 AD ⇒ 真值在第 4 行（只与列有关）⇒ 只剩 6 个未知字符，
  且必须是 26 字母里未出现的 8 个字母中取 6 个（字球 26+10+8=44 约束）⇒ P(8,6)=20160。

判据：**WinZip-AES 自身的 10 字节 HMAC-SHA1 认证码**（80 bit），不是附件里的 sha256.txt。
用法：python3 scripts/12080-solve.py [--flag]
"""
import hashlib, hmac, struct, subprocess, sys, itertools, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZIP = os.path.join(ROOT, 'firmware/12080_Jammed/extracted/treasure.zip')
if not os.path.exists(ZIP):
    ZIP = os.path.join(ROOT, 'work/12080_jammed/treasure.zip')

# ── 逐格转写（BENCH RECORD A / B，行序 = 页面从上到下；片段列已 8× 目视复核）─────────
A = [("xl","xbxey","/-"),("xk","yxfgd","ke"),("xh","/qpb-","cb"),("hl","cdbbx","hu"),
     ("hu","ckbnq","-x"),("nh","clntx","px"),("xb","fxnh/","n,"),("nx","g;cxj","uu"),
     ("hk","hdjdu","xq"),("hc","eyhef","ef"),("xn","y;fcg",",p"),("xu","htybl","ju"),
     ("xd","jxty-","qn"),("hn","h//;g",",x"),("xx","/ck/g","xq"),("hx","l;tb-","-g"),
     ("xe","puygc","hu"),("hd","bxkgl","ek"),("nn","fl,uf","ln"),("nu","ppyhg","cd"),
     ("xc","ny-nn",";h"),("hb","cqlxy","qc"),("nl","x;hxp","cl"),("he","qeghg","xb")]
B = [("01","17z99","91"),("16","013x7","k5"),("13","hthb4","t3"),("14","19xeh","49"),
     ("06","hdt7u","16"),("05","6exhx","x9"),("04","8db91","03"),("11","4c64x","16"),
     ("10","46e99","89"),("12","07uc1","8e"),("02","0447x","81"),("08","e0h5u","5u"),
     ("19","3x204","28"),("18","2h92n","70"),("21","x78xt","3u"),("24","x70xe","c4"),
     ("22","u483u","12"),("15","e3018","03"),("07","91k11","ek"),("23","ee0h1","8d"),
     ("17","t1zh9","62"),("09","c611h","k8"),("03","ckbnk","91"),("20","clntx","e1")]

# 字球表：11 列 × 3 个已印行（第 4 行 X 未知）
S  = list("hxnulekdcbt")
AO = {0:'y',1:'g',2:None,3:'f',4:'/',5:'p',6:'q',7:';',8:',',9:'-',10:'j'}  # 只有 A 页印过
DN = list("0123456789")+['z']                                                # 只有 B 页印过
ALNUM = set('abcdefghijklmnopqrstuvwxyz0123456789')
POOL  = 'aimorsvw'          # 26 字母中未出现的 8 个（字球共 44 字符的约束）

def resolve(a, b):
    """两页字符 → 字球列（l 与 1 字形相同，允许互换后再定列）"""
    out = []
    for c in range(11):
        aset = {S[c]} | ({AO[c]} if AO[c] else set())
        bset = {S[c], DN[c]}
        def ok(ch, s):
            if ch in s: return True
            if ch in 'l1': return ('l' if ch == '1' else '1') in s
            return False
        if ok(a, aset) and ok(b, bset): out.append(c)
    return out

def row_of(ch, c, page):
    """该页在此格印的是哪一行"""
    if ch == S[c] or (ch in 'l1' and S[c] == 'l'): return 'S'
    return 'A' if page == 'A' else 'D'

def main():
    amap = dict(zip("hxnulekdcb", "0123456789"))          # S 行字母 → 该列的 D 行数字
    Arec = {"".join(amap[c] for c in s): (s, c, f) for s, c, f in A}
    Brec = {s: (s, c, f) for s, c, f in B}
    assert set(Arec) == set(Brec) == {f"{i:02d}" for i in range(1, 25)}

    # ── 自检 1：列结构在 168 个数据格上 0 矛盾 ────────────────────────────────
    cells = []
    for rec in sorted(Arec):
        _, ca, fa = Arec[rec]; _, cb, fb = Brec[rec]
        for fld, xs, ys in (('code', ca, cb), ('frag', fa, fb)):
            for i, (x, y) in enumerate(zip(xs, ys)):
                r = resolve(x, y)
                assert len(r) == 1, (fld, rec, i, x, y, r)
                c = r[0]
                cells.append((fld, rec, i, c, row_of(x, c, 'A') + row_of(y, c, 'B')))
    assert len(cells) == 168

    # ── 自检 2：两个锚点 ───────────────────────────────────────────────────
    ser = [(rec[i], rec[i]) for rec in sorted(Arec) for i in (0, 1)]
    assert all(row_of(a, resolve(a, b)[0], 'A') + row_of(b, resolve(a, b)[0], 'B') == 'SD'
               for a, b in zip([c for r in sorted(Arec) for c in Arec[r][0]],
                               [c for r in sorted(Arec) for c in r]))
    print("[+] 列结构 168/168 一致；序号列全 SD ⇒ 真值行=D；分隔符列全 AS ⇒ 真值行=A")

    # ── Case 1：SS→S, SD→D, AS→A, AD→X ─────────────────────────────────────
    TR = {'SS': 'S', 'SD': 'D', 'AS': 'A', 'AD': 'X'}
    ROW = {'S': S, 'A': AO, 'D': DN}
    frag = [c for c in cells if c[0] == 'frag']
    tmpl, slots = [], {}
    for fld, rec, i, c, cm in frag:
        r = TR[cm]
        if r == 'X':
            tmpl.append(None); slots.setdefault(c, []).append(len(tmpl) - 1)
        else:
            tmpl.append(ROW[r][c]); assert ROW[r][c] in ALNUM
    cols = sorted(slots)
    print(f"[+] 片段 48 格中 {sum(1 for t in tmpl if t is None)} 格在第 4 行，涉及列 {cols} ⇒ P(8,{len(cols)}) "
          f"= {len(list(itertools.permutations(POOL,len(cols))))} 个候选")

    # ── 判据：WinZip-AES 10 字节认证码 ─────────────────────────────────────
    raw = open(ZIP, 'rb').read()
    crc, cs, us = struct.unpack('<III', raw[14:26]); nl, el = struct.unpack('<HH', raw[26:30])
    extra = raw[30+nl:30+nl+el]; data = raw[30+nl+el:30+nl+el+cs]
    ei = extra.index(b'\x01\x99'); strength = struct.unpack('<H', extra[ei+8:ei+10])[0]
    SALT_LEN = {1: 8, 2: 12, 3: 16}[strength]; KEY_LEN = {1: 16, 2: 24, 3: 32}[strength]
    salt = data[:SALT_LEN]; verify = data[SALT_LEN:SALT_LEN+2]
    body = data[SALT_LEN+2:]; ct, auth = body[:-10], body[-10:]

    def opens_zip(pw):
        dk = hashlib.pbkdf2_hmac('sha1', pw.encode(), salt, 1000, 2*KEY_LEN+2)
        if dk[2*KEY_LEN:2*KEY_LEN+2] != verify: return False
        return hmac.new(dk[KEY_LEN:2*KEY_LEN], ct, hashlib.sha1).digest()[:10] == auth

    pw = None
    for perm in itertools.permutations(POOL, len(cols)):
        s = list(tmpl)
        for c, ch in zip(cols, perm):
            for j in slots[c]: s[j] = ch
        cand = ''.join(s)
        if opens_zip(cand):
            pw = cand; break
    assert pw, "未找到口令"
    print(f"[+] 口令 = {pw}  (通过 WinZip-AES 80-bit 认证码)")
    print(f"[!] 注意：sha256.txt 与该口令不符（{hashlib.sha256(pw.encode()).hexdigest()[:16]}… vs 附件），是干扰项")

    # ── 解密（WinZip-AES = AES-256-CTR，counter 从 1 开始，小端 128bit）────
    dk = hashlib.pbkdf2_hmac('sha1', pw.encode(), salt, 1000, 2*KEY_LEN+2)
    key = dk[:KEY_LEN]
    pt = b''
    for i in range(0, len(ct), 16):
        blk = ct[i:i+16]
        ks = subprocess.run(['openssl','enc','-aes-256-ecb','-nopad','-K',key.hex()],
                            input=((i//16)+1).to_bytes(16,'little'), capture_output=True).stdout
        pt += bytes(a ^ b for a, b in zip(blk, ks))
    print(f"[+] flag.txt = {pt.decode()}")
    assert pt.startswith(b'flag{') and pt.endswith(b'}') and len(pt) == us, (len(pt), us)
    if '--flag' in sys.argv:
        print(pt.decode())

if __name__ == '__main__':
    main()
