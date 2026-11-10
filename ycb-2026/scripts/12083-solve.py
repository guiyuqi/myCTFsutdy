#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
12083 · Lost_Memory  —— 可复现解题脚本（2026 羊城杯 · DASCTF）
用法:  python3 scripts/12083-solve.py [E01路径]
默认 E01: work/linxiao/YCB_linxiao.E01  (由 firmware/Linxiao.zip 解压; 解压密码见题目描述)

流程（全部为文件系统层定点取证，绝不 ewfexport 全量 64GB）:
  p3 offset=239616 扇区 (NTFS 主盘)
  1. 碎片1 `after`   : Users/Lin_xiao/AppData/Local/Google/Chrome/User Data/Default/History
                       (urls.title = "碎片 1/5: after | AIYA Tracking System Log")
  2. 碎片2 `_all`    : AIYA_Project git dangling blob (已清空仓库)
  3. 碎片3 `_this`   : CompanyChat/encrypted_messages.db (XOR, key = 芯片ID 的 etched 形)
  4. 碎片4 `_time`   : Downloads/AIYA_crash_backup.log (UTF-16LE)
  5. 碎片5 `_always` : Desktop/final_memory.png  RGB-LSB bit0 顺序嵌入
  芯片硬件编号 = config.yaml `chip_monitor: YA_20180507`；描述"外壳分段只为读数、固件里连续"
               → 取连续形 YA20180507
  拼装串 = 五片首尾相接 + '_' + 连续芯片号  = after_all_this_time_always_YA20180507
  它是 **aiya_memory.dump 的口令**（不是 flag！），PBKDF2-HMAC-SHA256(10000)/AES-256-CBC 解密，
  明文"雅的信"末尾给出 flag{} 串；**平台实际比对裸串**。
"""
import os, re, sys, sqlite3, binascii, hashlib, subprocess, tempfile

OFF = "239616"            # p3 起始扇区
CHIP_ETCHED = "YA_20180507"
CHIP_FW = CHIP_ETCHED.replace("_", "")     # 固件连续形
EXPECT_BARE = "We_wi1l_m3et_ag4in_a7_d4wn"  # 平台比对的裸串

E01 = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "work/linxiao/YCB_linxiao.E01")
assert os.path.exists(E01), f"找不到 E01: {E01}"

def icat(inode, dest):
    with open(dest, "wb") as f:
        subprocess.run(["icat", "-o", OFF, E01, str(inode)], stdout=f,
                       stderr=subprocess.DEVNULL, check=True)
    return dest

def fls(path="/"):
    """按路径解析 inode（根目录递归一次），返回 {posix路径: (inode, is_dir)}"""
    out = subprocess.run(["fls", "-r", "-p", "-o", OFF, E01],
                         capture_output=True).stdout.decode("utf-8", "replace")
    m = {}
    for line in out.splitlines():
        g = re.match(r"^([rd])/([rd])\s+(?:\*\s+)?(\d+)-\d+-\d+:\t(.+)$", line)
        if g:
            m[g.group(4).strip()] = (int(g.group(3)), g.group(1) == "d")
    return m

def find(files, *needles, is_dir=False):
    for p, (ino, d) in files.items():
        if d != is_dir:
            continue
        low = p.lower()
        if all(n.lower() in low for n in needles):
            return p, ino
    return None, None

tmp = tempfile.mkdtemp(prefix="12083_")
files = fls()

# ---- 碎片 1: Chrome History 标题 -----------------------------------------
p, ino = find(files, "chrome/user data/default/history")
hist = os.path.join(tmp, "History")
icat(ino, hist)
row = sqlite3.connect(hist).execute(
    "select title from urls where title like '%碎片%'").fetchone()
frag1 = re.search(r"碎片\s*1/5\s*:\s*(\S+)", row[0]).group(1)
print("[1/5]", repr(frag1), "  <-", p)

# ---- 碎片 2: git dangling blob ------------------------------------------
p, ino = find(files, "aiya_project/readme.md")
# 直接取整棵 .git 到临时目录后用 git fsck 找 dangling blob 中含 '碎片 2/5' 的
gitdir = os.path.join(tmp, "aiya_project")
os.makedirs(os.path.join(gitdir, ".git"), exist_ok=True)
for path, (i2, isd) in files.items():
    if not isd and path.lower().startswith("users/linxiao/documents/aiya_project/.git/"):
        rel = path.split("AIYA_Project/.git/", 1)[1]
        dest = os.path.join(gitdir, ".git", rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        icat(i2, dest)
blobs = subprocess.run(["git", "-C", gitdir, "cat-file", "--batch-all-objects",
                        "--batch-check"], capture_output=True).stdout.decode().splitlines()
frag2 = None
for b in blobs:
    sha, typ = b.split()[0], b.split()[1]
    if typ != "blob":
        continue
    body = subprocess.run(["git", "-C", gitdir, "cat-file", "-p", sha],
                          capture_output=True).stdout.decode("utf-8", "replace")
    m = re.search(r"碎片\s*2/5\s*\]\s*(\S+)", body)
    if m:
        frag2 = m.group(1); break
assert frag2, "git 里没找到碎片 2"
print("[2/5]", repr(frag2), "  <- git blob(s) of", p)

# ---- 碎片 3: 消息库 XOR（key = 芯片ID etched 形） ------------------------
p, ino = find(files, "companychat/encrypted_messages.db")
db = os.path.join(tmp, "enc.db"); icat(ino, db)
frag3 = None
for (content,) in sqlite3.connect(db).execute(
        "select content from messages where encrypted=1"):
    d = binascii.unhexlify(content)
    k = CHIP_ETCHED.encode()
    pt = bytes(b ^ k[i % len(k)] for i, b in enumerate(d)).decode("utf-8", "replace")
    m = re.search(r"碎片\s*3/5\s*\]\s*(\S+)", pt)
    if m:
        frag3 = m.group(1); break
assert frag3, "消息库里没找到碎片 3"
print("[3/5]", repr(frag3), "  <-", p, "(XOR key =", CHIP_ETCHED, ")")

# ---- 碎片 4: 崩溃备份日志（UTF-16LE） -----------------------------------
p, ino = find(files, "aiya_crash_backup.log")
log = icat(ino, os.path.join(tmp, "crash.log"))
raw = open(log, "rb").read()
txt = raw.decode("utf-16-le", "replace")
frag4 = re.search(r"碎片\s*4/5\s*\]\s*(\S+)", txt).group(1)
print("[4/5]", repr(frag4), "  <-", p, "(UTF-16LE)")

# ---- 碎片 5: 桌面 PNG 的 RGB-LSB bit0 -----------------------------------
p, ino = find(files, "desktop/final_memory.png")
png = icat(ino, os.path.join(tmp, "final_memory.png"))
from PIL import Image
im = Image.open(png).convert("RGB"); w, h = im.size; px = im.load()
bits = []
for y in range(h):
    for x in range(w):
        r, g, b = px[x, y]; bits.extend((r & 1, g & 1, b & 1))
ba = bytearray()
for i in range(len(bits) // 8):
    v = 0
    for j in range(8): v = (v << 1) | bits[i * 8 + j]
    ba.append(v)
lsb = bytes(ba)
frag5 = re.search(r"碎片\s*5/5\s*\]\s*(\S+)".encode(), lsb).group(1).decode()
print("[5/5]", repr(frag5), "  <-", p, "(RGB bit0 sequential LSB)")

# ---- 拼装 + 解密 dump ---------------------------------------------------
key = "".join([frag1, frag2, frag3, frag4, frag5]) + "_" + CHIP_FW
print("\n拼装串(= dump 口令):", key)

p, ino = find(files, "aiya_memory.dump", is_dir=False)
dump = icat(ino, os.path.join(tmp, "aiya_memory.dump"))
data = open(dump, "rb").read()
assert data[:8] == b"Salted__", "dump 不是 OpenSSL Salted 格式"
salt, ct = data[8:16], data[16:]
dk = hashlib.pbkdf2_hmac("sha256", key.encode(), salt, 10000, 48)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
d = Cipher(algorithms.AES(dk[:32]), modes.CBC(dk[32:48])).decryptor()
pt = d.update(ct) + d.finalize()
pad = pt[-1]
assert 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad, "padding 非法（口令错）"
plain = pt[:-pad]
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                   "work/12083_lostmem/aiya_core_memory.txt")
os.makedirs(os.path.dirname(out), exist_ok=True)
open(out, "wb").write(plain)
print("\n--- 解密出的『核心记忆』 ---")
print(plain.decode("utf-8"))

inner = re.search(r"flag\{(.+?)\}", plain.decode("utf-8")).group(1)
assert inner == EXPECT_BARE, f"内容与预期不符: {inner}"
print("自检通过。平台比对裸串:", inner)
print("提示: 带 flag{} 外壳提交会被 40001 拒（本题实测）。")
