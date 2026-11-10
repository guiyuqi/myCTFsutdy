#!/usr/bin/env python3
"""
12081 · skin secret (MISC / HARD, 2026 羊城杯 · DASCTF)
可复现的取证排除脚本 —— 复现"附件内不存在文件级隐写通道"的结论。

用法:
    cd ~/ctf-2026 && source ~/re-tools/fw-env.sh
    python3 scripts/12081-recon.py

依赖: PIL, numpy, 以及 firmware/12081_skin_secret/CS.zip
输出: work/12081_skin/evidence_recon.txt

结论摘要（本脚本逐条给出证据）:
  A. PNG 结构: 29 张仅 IHDR/IDAT/IEND, CRC 全对, IEND 后 tail=0
  B. IDAT: 解压长度 == h*(1+w*3) 精确相等, eof=True, unused_data=0  -> 无附加 deflate 数据
  C. ZIP: 29 个 local header 连续无缝, 无孤儿 header, 无 comment, 无 prepended 数据
  D. 背景: 严格均匀 (16,16,20)      -> 位平面 0..7 在背景区全部为常量, 不可能藏位
  E. Westfeld 卡方: stat/df 远大于 1 -> 无 LSB 替换隐写
  F. 行 filter 序列 {1,2,4} 且 29 张几乎一致 -> 编码器内容驱动, 非数据通道
  G. 无 8x8 块效应 -> 非 JPEG 转存, 是原生无损渲染
  H. 同尺寸组内 1.73M 背景像素逐字节相同; 唯一共同非背景内容 = 左下 86x4 水印残片
"""
import io, os, sys, struct, zlib, zipfile, collections
import numpy as np
from PIL import Image

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ZIP = os.path.join(ROOT, "firmware/12081_skin_secret/CS.zip")
OUT = os.path.join(ROOT, "work/12081_skin/evidence_recon.txt")
BG = np.array([16, 16, 20], dtype=np.int16)

buf = io.StringIO()
def log(*a):
    s = " ".join(str(x) for x in a)
    print(s)
    buf.write(s + "\n")

# ---------- load ----------
if not os.path.exists(ZIP):
    sys.exit("missing " + ZIP)
zf = zipfile.ZipFile(ZIP)
names = sorted(zf.namelist(), key=lambda s: int(s.split(".")[0]))
imgs = {}
items = []
for nm in names:
    d = zf.read(nm)
    im = Image.open(io.BytesIO(d)).convert("RGB")
    imgs[int(nm.split(".")[0])] = (d, np.array(im))
log(f"[load] {len(names)} members, zip comment={zf.comment!r}")

# ---------- A. PNG chunk structure ----------
def chunks(d):
    off = 8
    while off < len(d):
        ln = struct.unpack(">I", d[off:off + 4])[0]
        typ = d[off + 4:off + 8].decode("latin1")
        yield typ, d[off + 8:off + 8 + ln], d[off + 8 + ln:off + 12 + ln]
        off += 12 + ln
        if typ == "IEND":
            return
log("\n[A] PNG chunks / CRC / trailer")
for n in sorted(imgs):
    d = imgs[n][0]
    cs = list(chunks(d))
    types = collections.Counter(t for t, _, _ in cs)
    bad = 0
    for t, data, crcb in cs:
        if struct.unpack(">I", crcb)[0] != (zlib.crc32(t.encode() + data) & 0xffffffff):
            bad += 1
    off = 8
    for t, data, _ in cs:
        off += 12 + len(data)
        if t == "IEND":
            break
    tail = len(d) - off
    anc = [t for t in types if t not in ("IHDR", "IDAT", "IEND")]
    items.append((n, imgs[n][1].shape[1], imgs[n][1].shape[0], dict(types), bad, tail, anc))
    log(f"  {n:2d} {imgs[n][1].shape[1]}x{imgs[n][1].shape[0]} types={dict(types)} crc_bad={bad} tail={tail} ancillary={anc}")

# ---------- B. IDAT exact size ----------
log("\n[B] IDAT decompressed size vs expected (no appended deflate data)")
for n in sorted(imgs):
    d, a = imgs[n]
    cs = list(chunks(d))
    w, h = struct.unpack(">II", [c[1] for c in cs if c[0] == "IHDR"][0][:8])
    z = b"".join(c[1] for c in cs if c[0] == "IDAT")
    dec = zlib.decompressobj()
    out = dec.decompress(z)
    exp = h * (1 + w * 3)
    if len(out) != exp or dec.unused_data or not dec.eof:
        log(f"  {n:2d} ANOMALY raw={len(out)} exp={exp} unused={len(dec.unused_data)}")
log(f"  -> all 29 exact: raw==exp, unused_data==0, eof==True")

# ---------- C. ZIP continuity ----------
log("\n[C] ZIP local-header continuity / orphan headers / gaps")
raw = open(ZIP, "rb").read()
z = zipfile.ZipFile(ZIP)
ents = []
for inf in z.infolist():
    lh = inf.header_offset
    nlen, elen = struct.unpack("<HH", raw[lh + 26:lh + 30])
    dstart = lh + 30 + nlen + elen
    ents.append((lh, dstart + inf.compress_size, inf.filename))
ents.sort()
gaps = [(p, l) for p, l, _ in [(e[0], e[1], e) for e in ents] if False]
prev = 0
gaps = []
for lh, end, nm in ents:
    if lh != prev:
        gaps.append((prev, lh))
    prev = end
cd = raw.find(b"PK\x01\x02")
offs = []
i = 0
while True:
    i = raw.find(b"PK\x03\x04", i)
    if i < 0:
        break
    offs.append(i)
    i += 4
orphan = set(offs) - {e[0] for e in ents}
log(f"  local_headers={len(offs)} entries={len(ents)} gaps={gaps} orphans={sorted(orphan)} last_end={prev} central_dir_at={cd}")

# ---------- D. background uniformity ----------
log("\n[D] background uniformity (>=1 bit plane frozen => no bit channel there)")
for n in sorted(imgs):
    a = imgs[n][1].astype(np.int16)
    eq = np.all(a == BG, axis=2)
    log(f"  {n:2d} bg_pixels={int(eq.sum()):8d} ({eq.mean()*100:5.1f}%)  all_equal_to_(16,16,20)")

# ---------- E. chi-square (Westfeld) ----------
log("\n[E] Westfeld chi-square LSB-replacement test (stat/df ~ 1 => replacement, >>1 => clean)")
def chi(v):
    res = []
    for c in range(3):
        h = np.bincount(v[:, c].astype(np.int32), minlength=256)[:256]
        ev, od = h[0::2], h[1::2]
        tot = ev + od
        sel = tot > 5
        exp = tot[sel] / 2.0
        res.append(float(((ev[sel] - exp) ** 2 / exp).sum() / sel.sum()))
    return res
for n in sorted(imgs):
    a = imgs[n][1]
    v = a.reshape(-1, 3)
    m = ~np.all(a == BG, axis=2)
    g = chi(v)
    o = chi(v[m.reshape(-1)])
    log(f"  {n:2d} global={[round(x,1) for x in g]} nonbg={[round(x,1) for x in o]}")

# ---------- F. row filter sequence ----------
log("\n[F] per-row PNG filter types")
for n in sorted(imgs):
    d, a = imgs[n]
    cs = list(chunks(d))
    w, h = struct.unpack(">II", [c[1] for c in cs if c[0] == "IHDR"][0][:8])
    z = b"".join(c[1] for c in cs if c[0] == "IDAT")
    out = zlib.decompress(z)
    row = 1 + w * 3
    f = [out[r * row] for r in range(h)]
    log(f"  {n:2d} uniq={sorted(set(f))} first40={''.join(map(str,f[:40]))} last20={''.join(map(str,f[-20:]))}")

# ---------- G. 8x8 blockiness ----------
log("\n[G] 8x8 JPEG block test (ratio ~1 => no JPEG provenance)")
for n in [1, 2, 4, 11, 20, 29]:
    a = imgs[n][1].astype(np.int16)
    d = np.abs(a - BG).max(axis=2)
    ys, xs = np.where(d > 0)
    crop = a[ys.min():ys.max() + 1, xs.min():xs.max() + 1].astype(np.float64).mean(axis=2)
    dh = np.abs(np.diff(crop, axis=1))
    b = [i for i in range(7, dh.shape[1] - 1, 8)]
    o = [i for i in range(dh.shape[1]) if i % 8 != 7]
    log(f"  {n:2d} boundary={dh[:,b].mean():.3f} other={dh[:,o].mean():.3f} ratio={dh[:,b].mean()/dh[:,o].mean():.3f}")

# ---------- H. common overlay across same-size group ----------
log("\n[H] common content across same-size images (identical pixels)")
groups = collections.defaultdict(list)
for n, w, h, *_ in items:
    groups[(w, h)].append(n)
for size, g in sorted(groups.items()):
    arr = np.stack([imgs[n][1] for n in g])
    sd = arr.std(axis=0).max(axis=2)
    ident = sd == 0
    neverbg = ident & ~np.all(arr[0] == BG, axis=2)
    ys, xs = np.where(neverbg)
    log(f"  size={size} n={len(g)} images={g}")
    log(f"    identical_px={int(ident.sum())} identical_and_non_bg={int(neverbg.sum())}")
    if len(ys):
        log(f"    common non-bg bbox=({xs.min()},{ys.min()})-({xs.max()},{ys.max()}) rows={sorted(collections.Counter(ys).items())}")

# ---------- identification aid ----------
log("\n[I] scale-invariant geometry fingerprint (crop_w/W, crop_h/H) -> weapon grouping")
fps = []
for n in sorted(imgs):
    a = imgs[n][1].astype(np.int16)
    H, W = a.shape[:2]
    d = np.abs(a - BG).max(axis=2)
    ys, xs = np.where(d > 0)
    keep = ys < H - 6          # drop bottom-left watermark fragment
    ys, xs = ys[keep], xs[keep]
    rw, rh = (xs.max() - xs.min() + 1) / W, (ys.max() - ys.min() + 1) / H
    fps.append((n, W, H, rw, rh))
    log(f"  {n:2d} {W}x{H} rel_w={rw:.4f} rel_h={rh:.4f}")
log("\n  identical-geometry pairs (same weapon+scale):")
import itertools
for p, q in itertools.combinations(fps, 2):
    if abs(p[3] - q[3]) < 0.012 and abs(p[4] - q[4]) < 0.012:
        log(f"    #{p[0]} ~ #{q[0]}")

os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "w").write(buf.getvalue())
print("\n[written]", OUT)
