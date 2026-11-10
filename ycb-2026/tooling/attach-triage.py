#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""赛前附件三分钟分诊（密码闸门 + 题型路由）。

用途：比赛方下发 misc 附件、开赛才给密码时，一次性回答三个问题：
  1) 这批附件是什么格式、有没有加密、加密的是头还是内容；
  2) 给了密码能不能一次解开（含嵌套压缩包，递归一层到两层）；
  3) 每份附件该加载哪个 skill（名字直接抄进子代理 brief）。

判据来源（2026-10-23 本机实测，见 evidence/attach-triage-smoke.log）：
  - zip：Python zipfile 的 flag_bits & 0x1，无需密码即可判定；
  - 7z/rar：`7z l -slt -p""` 的 `Encrypted = +`；
    头部加密的 7z 直接报 `Cannot open encrypted archive. Wrong password?`；
  - 内容加密但文件名明文时，能列出清单、只有解压才失败 → 必须试密码。

用法：
  python3 scripts/attach-triage.py                      # 默认扫 firmware/
  python3 scripts/attach-triage.py firmware/a.zip x.7z
  python3 scripts/attach-triage.py --password 'P@ss'    # 解包到 work/triage_out/
  echo 'P@ss' | python3 scripts/attach-triage.py --password-stdin
  --depth 2 递归解嵌套压缩包；--extract-only a.zip 只解指定文件

内存纪律：只读文件头 32 字节判魔数，解包全部交给 7z 子进程，不在 Python 里搬大文件。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

WS = Path(__file__).resolve().parent.parent
DEFAULT_DROP = WS / "firmware"
OUT_BASE = WS / "work" / "triage_out"

# 魔数 → (类别, 路由技能)。
# 技能名必须与 work/briefs/RULES.md §0 / §0.2 一致（本机技能目录已核对存在）。
MAGIC = [
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip-empty"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\x1f\x8b", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
    (b"BM", "bmp"),
    (b"RIFF", "riff"),
    (b"%PDF", "pdf"),
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"\x00asm", "wasm"),
    (b"\xd0\xcf\x11\xe0", "ole"),
    (b"\x1aE\xdf\xa3", "mkv"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"\xd4\xc3\xb2\xa1", "pcap"),
    (b"\xa1\xb2\xc3\xd4", "pcap"),
    (b"\x0a\x0d\x0d\x0a", "pcapng"),
]

ROUTE = {
    "png": ("competition-stego-media + png-lsb-skills", "位平面/块元数据/尾部三路并查"),
    "jpeg": ("competition-stego-media", "EXIF/尾附/量化表异常"),
    "gif": ("competition-stego-media", "帧差/调色板/帧注释"),
    "bmp": ("competition-stego-media", "调色板/尾部"),
    "riff": ("competition-stego-media + ctf-forensics", "WAV LSB/频谱；AVI 帧"),
    "pdf": ("ctf-forensics + competition-stego-media", "对象流/ToUnicode/隐藏层"),
    "zip": ("competition-zip-archive + ctf-misc", "ZipCrypto→bkcrack 已知明文"),
    "zip-empty": ("competition-zip-archive", "空档：可能是分段附件"),
    "7z": ("competition-zip-archive + ctf-misc", "头加密 vs 仅内容加密"),
    "rar": ("competition-zip-archive + ctf-misc", "7z/bsdtar 直读，注意 Rar5"),
    "gzip": ("ctf-misc", "gzip -d 后再判"),
    "xz": ("ctf-misc", "xz -d 后再判"),
    "bzip2": ("ctf-misc", "bzip2 -d 后再判"),
    "elf": ("reverse-engineering + ghidra-reverse", "readelf→fw-decompile；先 file 看架构"),
    "pe": ("reverse-engineering + dotnet-reverse", "先验 CLR 头再选 .NET/原生"),
    "wasm": ("ctf-reverse", "wasm2wat→还原逻辑"),
    "py": ("ctf-misc", "pyjail / 逻辑题"),
    "pyc": ("ctf-reverse + dsl-vm-reverse", "版本对齐后 decompyle"),
    "apk": ("apk-reverse + competition-android-hooking", "jadx→smali→frida"),
    "pcap": ("competition-pcap-protocol + ctf-forensics", "scapy 重组四元组"),
    "pcapng": ("competition-pcap-protocol + ctf-forensics", "同上"),
    "sqlite": ("ctf-forensics", "sqlite3 表/页残留"),
    "ole": ("ctf-forensics", "OLE/Office 宏与内嵌对象"),
    "mkv": ("competition-stego-media", "帧/字幕轨/附件轨"),
    "disk": ("ctf-forensics", "MBR/分区→foremost/tsk"),
    "unknown": ("ctf-misc（fallback）", "先 file + binwalk + strings 再定路由"),
}

EXEC_HINT = (".exe", ".dll", ".so", ".bin", ".out", ".elf", ".dylib")

# 7z 能解的类型；递归解嵌套只看这些
ARCHIVE_KINDS = {"zip", "zip-empty", "7z", "rar", "gzip", "xz", "bzip2"}


def read_magic(p: Path, n: int = 32) -> bytes:
    try:
        with p.open("rb") as f:
            return f.read(n)
    except OSError:
        return b""


def kind_of(p: Path) -> str:
    ext = p.suffix.lower()
    if ext == ".apk":
        return "apk"
    if ext == ".pyc":
        return "pyc"
    if ext == ".py":
        return "py"
    m = read_magic(p)
    for sig, k in MAGIC:
        if m.startswith(sig):
            if k == "riff" and m[:4] == b"RIFF":
                sub = m[8:12]
                return {"WAVE": "riff", "AVI ": "riff", "WEBP": "riff"}.get(sub.decode("latin1", "ignore"), "riff")
            return k
    if m[0:4] == b"Rar!":
        return "rar"
    if m.startswith(b"7z\xbc\xaf"):
        return "7z"
    if ext in (".img", ".iso", ".raw", ".dd", ".vmdk", ".qcow2"):
        return "disk"
    if ext in EXEC_HINT:
        return "elf"
    return "unknown"


def human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0
    return str(n)


def sha256(p: Path, limit: int = 64 << 20) -> str:
    h = hashlib.sha256()
    left = limit
    with p.open("rb") as f:
        while left > 0:
            b = f.read(min(1 << 20, left))
            if not b:
                break
            h.update(b)
            left -= len(b)
    return h.hexdigest()


def run(cmd, timeout=60):
    try:
        # stdin=/dev/null：7z 无密码时会交互式提示，关掉 stdin 才能无人值守快速失败
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           errors="replace", stdin=subprocess.DEVNULL)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return 127, f"{type(e).__name__}: {e}"


def zip_encrypted(p: Path):
    """返回 (是否加密, 条目名列表)。Python 标准库判 ZipCrypto/AES 的 flag_bits。"""
    try:
        with zipfile.ZipFile(p) as z:
            infos = z.infolist()
            enc = any(i.flag_bits & 0x1 for i in infos)
            return enc, [i.filename for i in infos[:20]]
    except Exception as e:  # noqa: BLE001
        return None, [f"<zipfile 打不开: {type(e).__name__}>"]


def seven_zip_listing(p: Path):
    """7z l -slt -p'' ：返回 (是否加密, 是否头加密, 条目名列表, 7z 类型串)。"""
    # 密码必须紧贴 -p（`-pXXX`）；`-p=XXX` 会把 "=XXX" 当密码（2026-10-23 实测）。
    # 不给密码时用裸 "-p" + stdin=/dev/null → 立即报 Cannot open encrypted archive，不卡提示。
    rc, out = run(["7z", "l", "-slt", "-p", str(p)], timeout=60)
    entries = re.findall(r"^Path = (.+)$", out, re.M)
    entries = [e for e in entries if e != str(p)]
    names = [(e.split("/")[-1] if "/" in e else e) for e in entries][:20]
    info = ""
    m = re.search(r"^Type = (.+)$", out, re.M)
    if m:
        info = m.group(1).strip()
    header_enc = "Cannot open encrypted archive" in out or "Headers Error" in out
    enc = header_enc or ("Encrypted = +" in out)
    return enc, header_enc, names, info


def try_extract(p: Path, password: str | None, dest: Path, kind: str):
    """用 7z 解包；返回 (ok, 说明)。zip 再补一次 pyzipper 兜底。"""
    dest.mkdir(parents=True, exist_ok=True)
    args = ["7z", "x", "-y", "-bd"]
    args.append(f"-p{password}" if password is not None else "-p")
    args += [f"-o{dest}", str(p)]
    rc, out = run(args, timeout=180)
    ok = rc == 0 and any(dest.iterdir())
    if ok:
        return True, "7z 解包成功"
    if kind in ("zip", "zip-empty"):
        try:
            import pyzipper  # noqa: F401
            with pyzipper.AESZipFile(p) as z:
                z.extractall(dest, pwd=(password or "").encode())
            return True, "pyzipper 解包成功（AES-ZIP 兜底）"
        except ImportError:
            tail = "（本机无 pyzipper，跳过兜底）"
        except Exception as e:  # noqa: BLE001
            tail = f"（pyzipper 也失败: {type(e).__name__}）"
    else:
        tail = ""
    first = [ln for ln in out.splitlines() if ln.strip()][-3:]
    return False, " ".join(first)[:200] + tail


def survey(p: Path):
    kind = kind_of(p)
    size = p.stat().st_size
    enc = None
    header_enc = False
    names: list[str] = []
    ainfo = ""
    if kind in ("zip", "zip-empty"):
        enc, names = zip_encrypted(p)
    elif kind in ("7z", "rar"):
        enc, header_enc, names, ainfo = seven_zip_listing(p)
    return {
        "path": str(p), "name": p.name, "size": size, "human": human(size),
        "kind": kind, "encrypted": enc, "header_encrypted": header_enc,
        "entries": names, "archive_type": ainfo, "sha256": sha256(p),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="赛前附件分诊：格式 / 加密 / 密码 / 题型路由")
    ap.add_argument("paths", nargs="*", help="文件或目录（默认 firmware/）")
    ap.add_argument("--password", help="比赛方给的密码（也可 --password-stdin）")
    ap.add_argument("--password-stdin", action="store_true", help="从 stdin 读密码，避免进 shell 历史")
    ap.add_argument("--out", default=str(OUT_BASE), help="解包输出目录（默认 work/triage_out）")
    ap.add_argument("--depth", type=int, default=2, help="嵌套压缩包递归层数（默认 2，0=不解包）")
    ap.add_argument("--no-extract", action="store_true", help="只分诊，不解包")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    a = ap.parse_args()

    pw = a.password
    if a.password_stdin:
        pw = sys.stdin.readline().rstrip("\n")

    roots = [Path(x) for x in a.paths] or [DEFAULT_DROP]
    files: list[Path] = []
    for r in roots:
        if r.is_dir():
            files += sorted(x for x in r.rglob("*") if x.is_file())
        elif r.is_file():
            files.append(r)
        else:
            print(f"[!] 不存在: {r}", file=sys.stderr)
    if not files:
        print("[!] 没有任何附件。把比赛方下发的文件放进 firmware/ 再跑本脚本。", file=sys.stderr)
        return 2

    rows = []
    out_root = Path(a.out)
    queue: list[tuple[Path, int]] = [(p, 0) for p in files]
    seen: set[str] = set()
    while queue:
        p, lvl = queue.pop(0)
        key = str(p.resolve())
        if key in seen:
            continue
        seen.add(key)
        s = survey(p)
        s["level"] = lvl
        if (pw is not None and not a.no_extract and lvl < a.depth
                and s["kind"] in ARCHIVE_KINDS):
            dest = out_root / (p.stem if lvl == 0 else f"L{lvl}_{p.parent.name}_{p.stem}")
            ok, why = try_extract(p, pw, dest, s["kind"])
            s["extract"] = "OK" if ok else "FAIL"
            s["extract_note"] = why
            s["extract_dir"] = str(dest) if ok else ""
            if ok and lvl + 1 < a.depth:
                for c in sorted(dest.rglob("*")):
                    if c.is_file() and kind_of(c) in ARCHIVE_KINDS:
                        queue.append((c, lvl + 1))
        rows.append(s)
        pad = "  " * lvl
        print(f"[+] {pad}{p.name:<34} {s['human']:>8}  {s['kind']:<9} "
              f"enc={('?' if s['encrypted'] is None else s['encrypted'])}"
              f"{' (header)' if s['header_encrypted'] else ''}"
              f"  {s.get('extract', '')}", file=sys.stderr)

    if a.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0

    print("\n# 附件分诊\n")
    print("| 附件 | 大小 | 类型 | 加密 | 密码解包 | 路由技能 | 首查判据 |")
    print("|---|---|---|---|---|---|---|")
    for s in rows:
        enc = "?" if s["encrypted"] is None else ("头加密" if s["header_encrypted"] else "有" if s["encrypted"] else "无")
        ex = s.get("extract", "-")
        if ex == "FAIL":
            ex = f"FAIL：{s.get('extract_note', '')[:40]}"
        elif ex == "OK":
            ex = f"OK → `{s['extract_dir']}`"
        route, judge = ROUTE.get(s["kind"], ROUTE["unknown"])
        print(f"| `{s['name']}` | {s['human']} | {s['kind']} | {enc} | {ex} | {route} | {judge} |")

    print("\n## 条目预览（前 10）\n")
    for s in rows:
        if s["entries"]:
            print(f"- `{s['name']}` ({s['archive_type'] or s['kind']}): " + ", ".join(s["entries"][:10]))

    print("\n## sha256\n")
    for s in rows:
        print(f"- `{s['name']}` `{s['sha256']}`")

    if pw is None and any(s["encrypted"] for s in rows):
        print("\n> 有加密附件但没给密码：开赛后用 `--password '<密码>'` 重跑即可一键解包。")
    if pw is not None:
        failed = [s["name"] for s in rows if s.get("extract") == "FAIL"]
        if failed:
            print(f"\n> 解包失败：{', '.join(failed)} —— 可能是密码错/分卷/RAR5 头加密；"
                  f"试 `bsdtar -xf` 或核对分卷是否只下了一部分。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
