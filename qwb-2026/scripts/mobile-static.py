#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mobile-static.py —— 移动 / UE 题的**静态**资产管线（不依赖 KVM、不依赖模拟器）

背景（2026 羊城杯 12084「千千的咲」）：
  该题给的是 UE5 Android 包，真正的信息在纹理里；当时因为"看不到纹理"，
  静态扫描 45.6MB 后得出"0 命中"的错误结论。事后确认：APK 里 `assets/main.obb.png`
  其实是**伪装成 PNG 的 zip**（OBB），内含 UE5 IoStore（.pak / .utoc / .ucas）。
  ⇒ 移动/UE 题的第一步永远是"把资产容器剥到见纹理"，而不是跑模拟器。

本工具做四件事，**每步都打印可判定的断言**（不静默失败）：
  1. 剥 APK：so/dex/assets 清单 + 嵌套 zip（含伪装扩展名）递归解包
  2. 识别 UE 容器：.pak / .utoc / .ucas，并解析 .pak（UE5 v11，零依赖）
  3. 导出 .pak 条目（可按子串过滤），校验 size 与 usize
  4. 扫 ASTC/KTX 纹理 → PNG（texture2ddecoder），校验解码尺寸

Oodle 压缩的条目**不会**被硬解：若包里没带 `liboo2core*` / `oo2core*`，会明确列为
"需要 Oodle 库"，而不是假装成功（这正是 12084 那次"静默失败 → 误判资产缺失"的教训）。

用法:
  python3 scripts/mobile-static.py <apk|zip|目录> [选项]

  --out DIR            输出根（默认 work/<输入名>_static）
  --list-pak           只列 .pak 条目，不导出
  --extract SUBSTR     导出名字含该子串的 .pak 条目（可多次；默认不导出）
  --all                导出 .pak 全部条目
  --textures           扫 ASTC 纹理并解码成 PNG（默认只在 --textures 时做）
  --decompile          额外跑 apktool（取 Manifest/资源；慢，默认不做）
  --max-nested N       嵌套 zip 递归深度上限（默认 3）
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

# 让本工具在**没有 source fw-env.sh** 的 shell 里也能用 re-tools 的 Python 库
# （texture2ddecoder / Pillow 都在那里；不自动加路径的话会误报"未安装"）
_PYL = Path.home() / "re-tools" / "pylibs"
if _PYL.is_dir() and str(_PYL) not in sys.path:
    sys.path.append(str(_PYL))

# ---- 常量
UE_PAK_MAGIC = b"\xe1\x12\x6f\x5a"          # FPakInfo magic 0x5A6F12E1 (LE)
ASTC_MAGIC = b"\x13\xab\xa1\x5c"            # ASTC 文件头 magic 0x5CA1AB13 (LE)
ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
ZIP_BOMB_LIMIT = 8 << 30                     # 解压总量上限 8GB（AGENTS.md 大内存禁令）


def human(n: int) -> str:
    for u in ("B", "K", "M", "G"):
        if n < 1024 or u == "G":
            return f"{n:.1f}{u}" if u != "B" else f"{n}{u}"
        n /= 1024
    return f"{n}B"


def sha256_head(p: Path, n: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        h.update(f.read(n))
    return h.hexdigest()[:16]


class Report:
    def __init__(self, out: Path):
        self.out = out
        self.lines: list[str] = []
        self.warnings: list[str] = []

    def say(self, msg: str = "") -> None:
        print(msg)
        self.lines.append(msg)

    def ok(self, msg: str) -> None:
        self.say(f"  [OK]   {msg}")

    def miss(self, msg: str) -> None:
        self.say(f"  [MISS] {msg}")
        self.warnings.append(msg)

    def info(self, msg: str) -> None:
        self.say(f"  ..     {msg}")

    def save(self) -> None:
        (self.out / "report.txt").write_text("\n".join(self.lines), encoding="utf-8")


# ---------------------------------------------------------------- 1. 输入 / 剥壳

def sniff_zip(p: Path) -> bool:
    try:
        with p.open("rb") as f:
            return f.read(4) in ZIP_MAGICS
    except OSError:
        return False


def safe_extract(zf: zipfile.ZipFile, dest: Path, rep: Report, budget: list[int]) -> int:
    """解 zip，带路径穿越防护与总量上限。返回解出的文件数。"""
    n = 0
    for info in zf.infolist():
        if info.is_dir():
            continue
        name = info.filename.replace("\\", "/")
        if name.startswith("/") or ".." in Path(name).parts:
            rep.miss(f"跳过可疑路径条目: {name}")
            continue
        budget[0] -= info.file_size
        if budget[0] < 0:
            rep.miss(f"解压总量超过 {human(ZIP_BOMB_LIMIT)}，停止（防 zip bomb）")
            break
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with zf.open(info) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            n += 1
        except Exception as e:                      # noqa: BLE001
            rep.miss(f"解包失败 {name}: {e}")
    return n


def strip_apk(apk: Path, out: Path, rep: Report, max_nested: int) -> Path:
    """解 APK，并对 assets 里伪装成其它扩展名的 zip 递归解包。返回嵌套解包根目录。"""
    rep.say("## 1. 剥 APK")
    apk_dir = out / "apk"
    budget = [ZIP_BOMB_LIMIT]
    with zipfile.ZipFile(apk) as zf:
        infos = zf.infolist()
        n = safe_extract(zf, apk_dir, rep, budget)
        rep.ok(f"APK 解包 {n} 个条目（{human(sum(i.file_size for i in infos))} 解压后）")

        # 分类统计
        cats: dict[str, list[str]] = {"lib": [], "dex": [], "assets": [], "其他": []}
        for i in infos:
            nm = i.filename
            if nm.startswith("lib/"):
                cats["lib"].append(nm)
            elif nm.endswith(".dex"):
                cats["dex"].append(nm)
            elif nm.startswith("assets/"):
                cats["assets"].append(nm)
        for k, v in cats.items():
            if v:
                rep.info(f"{k}: {len(v)} 项")
        for so in sorted(cats["lib"])[:12]:
            rep.info(f"  so: {so}")

    # 嵌套 zip：按魔数找，不看扩展名（12084 的 main.obb.png 就是 zip）
    nested_root = out / "nested"
    seen: set[Path] = set()
    depth = 0
    layer = [p for p in apk_dir.rglob("*") if p.is_file() and sniff_zip(p)]
    while layer and depth < max_nested:
        depth += 1
        rep.say(f"\n## 2.{depth} 嵌套容器（第 {depth} 层，{len(layer)} 个 zip）")
        nxt: list[Path] = []
        for z in layer:
            if z in seen:
                continue
            seen.add(z)
            rel = z.relative_to(apk_dir)
            dest = nested_root / f"L{depth}" / rel.with_suffix("")
            dest.mkdir(parents=True, exist_ok=True)
            try:
                with zipfile.ZipFile(z) as zf2:
                    cnt = safe_extract(zf2, dest, rep, budget)
                # 别按扩展名判断——先把真 zip 找出来
                rep.ok(f"{rel}  → {cnt} 条目  (含伪装扩展名: {'' if z.suffix in ('.zip', '.apk', '.obb') else z.suffix})")
                nxt += [p for p in dest.rglob("*") if p.is_file() and sniff_zip(p)]
            except zipfile.BadZipFile:
                rep.info(f"{rel}: 魔数像 zip 但非有效 zip，跳过")
        layer = nxt
    if depth == 0:
        rep.info("没有发现嵌套 zip（APK 内没有 OBB/二次压缩包）")
    return nested_root


# ---------------------------------------------------------------- 2. UE 容器

def find_ue(root: Path) -> dict[str, list[Path]]:
    got: dict[str, list[Path]] = {"pak": [], "utoc": [], "ucas": [], "obb": []}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        s = p.suffix.lower()
        if s == ".pak":
            got["pak"].append(p)
        elif s == ".utoc":
            got["utoc"].append(p)
        elif s == ".ucas":
            got["ucas"].append(p)
        elif s == ".obb":
            got["obb"].append(p)
    return got


class UePak:
    """UE5 .pak v11 读取器（移植自 12084b-pak-extract.py，已实测 1397 entries）。"""

    def __init__(self, path: Path):
        self.d = path.read_bytes()
        mo = self.d.rfind(UE_PAK_MAGIC)
        if mo < 0:
            raise ValueError("找不到 FPakInfo magic")
        magic, self.ver = struct.unpack_from("<Ii", self.d, mo)
        assert magic == 0x5A6F12E1
        io_, isz = struct.unpack_from("<qq", self.d, mo + 8)
        p = io_
        n = struct.unpack_from("<i", self.d, p)[0]
        self.mount = self.d[p + 4:p + 4 + n].rstrip(b"\0").decode()
        p += 4 + n
        self.num = struct.unpack_from("<i", self.d, p)[0]
        p += 4
        p += 8                                    # pathHashSeed
        hasPH = struct.unpack_from("<i", self.d, p)[0]
        p += 4
        if hasPH:
            p += 36
        hasFD = struct.unpack_from("<i", self.d, p)[0]
        p += 4
        fdo, fds = struct.unpack_from("<qq", self.d, p)
        p += 16
        p += 20
        esz = struct.unpack_from("<i", self.d, p)[0]
        p += 4
        self.enc = self.d[p:p + esz]
        self.fdo, self.fds = fdo, fds
        self.files = self._dir_index()

    def _dir_index(self):
        d, p, end = self.d, self.fdo, self.fdo + self.fds

        def rf(p):
            n = struct.unpack_from("<i", d, p)[0]
            p += 4
            if n < 0:
                s = d[p:p - 2 * n].decode("utf-16-le")
                p += -2 * n
            else:
                s = d[p:p + n].decode("utf8")
                p += n
            return s.rstrip("\0"), p

        nd = struct.unpack_from("<i", d, p)[0]
        p += 4
        files = []
        for _ in range(nd):
            dn, p = rf(p)
            nf = struct.unpack_from("<i", d, p)[0]
            p += 4
            for _ in range(nf):
                fn, p = rf(p)
                loc = struct.unpack_from("<i", d, p)[0]
                p += 4
                files.append(((dn.rstrip("/") + "/" + fn) if dn else fn, loc))
        assert p == end, f"目录索引结构自检失败 {p}!={end}"
        return files

    def entry(self, loc: int) -> dict:
        enc = self.enc
        h = struct.unpack_from("<I", enc, loc)[0]
        p = loc + 4
        method = (h >> 23) & 0x3F
        bc = (h >> 6) & 0xFFFF
        bs = (h & 0x3F) << 11
        if method == 0:
            off, size = struct.unpack_from("<II", enc, p)
            return dict(method=0, off=off, usize=size, size=size, blocks=[])
        off, usize, size = struct.unpack_from("<III", enc, p)
        p += 12
        n = bc if bs else 0
        blocks = [struct.unpack_from("<I", enc, p + 4 * k)[0] for k in range(n)]
        return dict(method=method, off=off, usize=usize, size=size, blocks=blocks)

    def read(self, e: dict) -> bytes:
        return self.d[e["off"]:e["off"] + e["size"]]


def handle_paks(paks: list[Path], out: Path, rep: Report,
                list_only: bool, substrs: list[str], do_all: bool) -> list[Path]:
    exported: list[Path] = []
    if not paks:
        rep.info("没有 .pak（可能是纯 IoStore 包，见 .utoc/.ucas）")
        return exported
    rep.say(f"\n## 3. .pak 解析（{len(paks)} 个）")
    dst_root = out / "ue"
    for pak in paks:
        try:
            P = UePak(pak)
        except Exception as e:                      # noqa: BLE001
            rep.miss(f"{pak.name}: 解析失败 {e}")
            continue
        rep.ok(f"{pak.name}: v{P.ver}, {len(P.files)} 条目, mount={P.mount!r}")
        need_oodle = 0
        hits: list[tuple[str, int]] = []
        for name, loc in P.files:
            if list_only:
                continue
            if do_all or any(s.lower() in name.lower() for s in substrs):
                hits.append((name, loc))
        if list_only:
            for name, loc in P.files[:400]:
                rep.say(f"    {loc:6d}  {name}")
            if len(P.files) > 400:
                rep.say(f"    … 共 {len(P.files)} 条，只显示前 400")
            continue
        for name, loc in hits:
            e = P.entry(loc)
            if e["method"] != 0:
                need_oodle += 1
                rep.miss(f"{name}: method={e['method']}（Oodle）{len(e['blocks'])} blocks, "
                         f"usize={e['usize']} —— 需 Oodle 解压，未导出")
                continue
            data = P.read(e)
            # 断言：读到的字节数必须等于索引里的 size
            if len(data) != e["size"]:
                rep.miss(f"{name}: 读出 {len(data)}B != 索引 {e['size']}B（偏移/版本不匹配）")
                continue
            dst = dst_root / name.lstrip("/")
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
            exported.append(dst)
            rep.ok(f"{name}  {len(data)}B  → {dst.relative_to(out)}  sha256:{sha256_head(dst)}")
        if need_oodle:
            rep.miss(f"{pak.name}: {need_oodle} 个 Oodle 压缩条目未导出（见上）")
    return exported


# ---------------------------------------------------------------- 4. ASTC

def _astc_header(data: bytes, i: int):
    """在偏移 i 处解析 ASTC 文件头；合法则返回 (w,h,bx,by)。"""
    if data[i:i + 4] != ASTC_MAGIC or i + 16 > len(data):
        return None
    bx, by, bz = data[i + 4], data[i + 5], data[i + 6]
    w = int.from_bytes(data[i + 7:i + 10], "little")
    h = int.from_bytes(data[i + 10:i + 13], "little")
    if not (0 < w <= 16384 and 0 < h <= 16384 and 0 < bx <= 12 and 0 < by <= 12):
        return None
    return w, h, bx, by


ASTC_SCAN_EXT = {".astc", ".uasset", ".uexp", ".ubulk", ".ucas", ".pak", ".bin", ".dat"}
ASTC_SCAN_MAX = 64 << 20       # 单文件扫描上限（AGENTS.md 大内存禁令）


def find_oodle(roots: list[Path], rep: Report) -> None:
    """找 Oodle 的可用形态：随包 .so/.dll，或静态链进 libUnreal.so 的符号。

    这一步决定瓶颈在哪：
      ① 有独立 Oodle 库 → 可尝试 ctypes 直接调（Android .so 依赖 bionic，host 上未必能 dlopen）；
      ② 只静态链进 so → 需要 retoc/FModel 这类带 Oodle 的工具；
      ③ 都没有 → 明确记录"本包不含可用 Oodle"，别再猜。
    """
    rep.say("\n## 4.0 Oodle 线索（ucas/ASTC 的常见前置）")
    named: list[Path] = []
    for r in roots:
        if not r.exists():
            continue
        for p in r.rglob("*"):
            if p.is_file() and any(s in p.name.lower() for s in
                                   ("oo2core", "oodle", "libooz", "oozlib")):
                named.append(p)
    if named:
        for p in named[:8]:
            rep.ok(f"找到 Oodle 库: {p.name}  {human(p.stat().st_size)}  → {p}")
        rep.info("下一步：用 ctypes 载入该库的 OodleLZ_Decompress；注意 Android .so 可能依赖 bionic")
        return

    sig = (b"OodleLZ_Decompress", b"OodleLZ", b"oo2core")
    for r in roots:
        if not r.exists():
            continue
        for p in sorted(r.rglob("*.so")):
            try:
                if p.stat().st_size > (128 << 20):
                    continue
                chunk = p.read_bytes()
            except OSError:
                continue
            hit = next((s for s in sig if s in chunk), None)
            if hit:
                rep.ok(f"{p.name} 内含 Oodle 符号 {hit.decode()!r}（静态链接）")
                rep.info("下一步：符号在 Android .so 里，host 上通常 dlopen 不动；"
                         "优先用 retoc / FModel 处理 .ucas")
                return
    rep.miss("未发现 Oodle 库（无独立 .so，也没在 lib*.so 里找到 Oodle 符号）")
    rep.info("→ IoStore(.ucas) 里的纹理需要外部工具：retoc / FModel / UnrealPak(带 Oodle)")


def scan_astc(roots: list[Path], out: Path, rep: Report) -> int:
    """扫 ASTC：① 文件头即是 ASTC 的独立纹理；② 在 ucas/uasset/pak 里 carve 魔数。

    UE 的 ASTC 通常被 Oodle 压缩后塞进 ucas/uasset，**不一定**有标准文件头；
    但只要原始 ASTC 块还在（未压缩或已解压），carve 就能直接抠出来 —— 不需要 Oodle。
    """
    try:
        import texture2ddecoder as t2d
        from PIL import Image
    except ImportError as e:
        rep.miss(f"缺依赖（{e}）—— texture2ddecoder/Pillow 在 ~/re-tools/pylibs，"
                 f"确认该目录存在；或 source ~/re-tools/fw-env.sh")
        return 0

    tex_dir = out / "textures"
    tex_dir.mkdir(parents=True, exist_ok=True)
    found = 0
    seen_hash: set[str] = set()

    def emit(data: bytes, i: int, tag: str) -> bool:
        nonlocal found
        hdr = _astc_header(data, i)
        if not hdr:
            return False
        w, h, bx, by = hdr
        raw = data[i + 16:]
        # ASTC 每个压缩块固定 16B，块数 = ceil(w/bx)*ceil(h/by)
        need = ((w + bx - 1) // bx) * ((h + by - 1) // by) * 16
        if len(raw) < need:
            rep.info(f"{tag} @{i}: 头像是 ASTC {w}x{h} block {bx}x{by}，但剩余字节不足（需 {need}）")
            return False
        raw = raw[:need]
        key = hashlib.sha256(raw[:4096]).hexdigest()[:16] + f"{w}x{h}"
        if key in seen_hash:
            return False
        seen_hash.add(key)
        try:
            buf = t2d.decode_astc(raw, w, h, bx, by)
            if len(buf) != w * h * 4:
                rep.miss(f"{tag} @{i}: 解码长度 {len(buf)} != {w*h*4}（断言失败，丢弃）")
                return False
            img = Image.frombytes("RGBA", (w, h), buf)
        except Exception as e:                      # noqa: BLE001
            rep.miss(f"{tag} @{i}: ASTC 解码失败 {e}")
            return False
        safe = re.sub(r"[^\w.-]+", "_", tag)[-80:]
        dst = tex_dir / f"{safe}_{i:x}_{w}x{h}.png"
        img.save(dst)
        found += 1
        rep.ok(f"ASTC→PNG  {tag} @{i}  {w}x{h} block {bx}x{by} → {dst.relative_to(out)}")
        return True

    for root in roots:
        if not root.exists():
            continue
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if p.suffix.lower() not in ASTC_SCAN_EXT or size > ASTC_SCAN_MAX:
                continue
            try:
                data = p.read_bytes()
            except OSError:
                continue
            rel = str(p.relative_to(root)) if root in p.parents else p.name
            emit(data, 0, rel)                       # 独立 ASTC 文件（头在 0）
            pos = 0                                  # carve：文件内任意位置
            while True:
                i = data.find(ASTC_MAGIC, pos)
                if i < 0:
                    break
                emit(data, i, rel)
                pos = i + 4
    if found == 0:
        rep.info("未 carve 到 ASTC 纹理 —— 多半是整块被 Oodle 压缩了，需要 Oodle 库先解压")
    return found


# ---------------------------------------------------------------- 5. APK 元信息

def apk_meta(apk: Path, out: Path, rep: Report, decompile: bool) -> None:
    if not decompile:
        return
    rep.say("\n## 5. apktool（Manifest / 资源）")
    apktool = shutil.which("apktool") or str(Path.home() / "re-tools/android/apktool")
    if not Path(apktool).exists():
        rep.miss(f"找不到 apktool（{apktool}）")
        return
    dst = out / "apktool"
    r = subprocess.run([apktool, "d", "-f", "-s", "-o", str(dst), str(apk)],
                       capture_output=True, text=True)
    if r.returncode == 0:
        rep.ok(f"apktool 解出 → {dst.relative_to(out)}")
        mf = dst / "AndroidManifest.xml"
        if mf.exists():
            txt = mf.read_text(encoding="utf-8", errors="replace")
            for pat in (r'package="([^"]+)"', r'android:versionName="([^"]+)"'):
                m = re.search(pat, txt)
                if m:
                    rep.info(f"{pat.split('(')[0].strip()}: {m.group(1)}")
            for perm in re.findall(r'android:name="(android\.permission\.[^"]+)"', txt)[:8]:
                rep.info(f"perm: {perm}")
    else:
        rep.miss(f"apktool 失败: {(r.stderr or r.stdout)[:200]}")


# ---------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description="移动/UE 题静态资产管线（不需要 KVM）")
    ap.add_argument("target")
    ap.add_argument("--out")
    ap.add_argument("--list-pak", action="store_true")
    ap.add_argument("--extract", action="append", default=[])
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--textures", action="store_true")
    ap.add_argument("--decompile", action="store_true")
    ap.add_argument("--max-nested", type=int, default=3)
    args = ap.parse_args()

    src = Path(args.target).expanduser().resolve()
    if not src.exists():
        print(f"[!] 不存在: {src}", file=sys.stderr)
        return 2
    slug = re.sub(r"[^\w.-]+", "_", src.stem)[:60] or "target"
    out = Path(args.out).expanduser() if args.out else (
        Path.cwd() / "work" / f"{slug}_static")
    out.mkdir(parents=True, exist_ok=True)
    rep = Report(out)

    rep.say(f"=== mobile-static  {src.name}  ({human(src.stat().st_size)}) ===")
    rep.say(f"输出: {out}\n")

    # 输入统一成一个"已经解开"的目录
    roots: list[Path] = []
    if src.is_dir():
        rep.say("## 0. 输入是目录，跳过 APK 解包")
        roots.append(src)
        nested_root = src
    elif sniff_zip(src):
        nested_root = strip_apk(src, out, rep, args.max_nested)
        roots += [out / "apk", nested_root]
    else:
        rep.miss(f"{src.name} 既不是目录也不是 zip（{src.read_bytes()[:8].hex()}），本工具不处理")
        rep.save()
        return 2

    # UE 容器
    ue = find_ue(nested_root) if nested_root.exists() else {"pak": [], "utoc": [], "ucas": [], "obb": []}
    ue2 = find_ue(out / "apk")
    for k in ue:
        ue[k] = sorted(set(ue[k] + ue2[k]))
    rep.say("\n## 3.0 UE 容器概览")
    for k in ("pak", "utoc", "ucas", "obb"):
        if ue[k]:
            rep.ok(f"{k}: {len(ue[k])} 个  （{human(sum(p.stat().st_size for p in ue[k]))}）")
            for p in ue[k][:6]:
                rep.info(f"  {p.name}  {human(p.stat().st_size)}")
    if ue["utoc"] and not ue["pak"]:
        rep.miss("只有 IoStore（.utoc/.ucas）没有 .pak —— 需要 retoc/FModel 等工具解析 ucas 索引")

    # .pak
    exported = handle_paks(ue["pak"], out, rep, args.list_pak, args.extract, args.all)

    # Oodle 线索（有 IoStore 时最关键）
    if ue["utoc"] or ue["ucas"] or args.textures:
        find_oodle(roots, rep)

    # 纹理
    if args.textures:
        rep.say("\n## 4. ASTC 扫描 / 解码")
        scan_astc(roots + [out / "ue"], out, rep)

    # apktool
    if args.decompile and src.is_file():
        apk_meta(src, out, rep, True)

    # 收尾
    rep.say("\n## 结论")
    if rep.warnings:
        rep.say(f"  有 {len(rep.warnings)} 项未能完成（见上，**都不是静默失败**）：")
        for w in rep.warnings[:12]:
            rep.say(f"    - {w}")
    else:
        rep.say("  全部步骤通过")
    rep.say(f"\n输出目录: {out}")
    rep.save()
    return 0 if not rep.warnings else 1


if __name__ == "__main__":
    sys.exit(main())
