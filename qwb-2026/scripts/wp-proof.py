#!/usr/bin/env python3
"""生成 WP 用的「获得 flag」证据图。

用法（在仓库根目录）:
    work/12084e/venv/bin/python scripts/wp-proof.py            # 用现有素材重排
    work/12084e/venv/bin/python scripts/wp-proof.py --list     # 列出还缺哪些平台截图

素材优先级（每题一张 assets/wp/flag-<题号>.png）:
  1) assets/wp/shot-<题号>.png 存在  → 「平台页面截图（上） + 提交回包（下）」双拼，证据最强；
  2) 不存在                          → 仅「提交回包卡」（数据源 evidence/submit-log.jsonl，图头标注来源）。

平台截图怎么来（每题 1 次点击）:
  打开赛事页 → 点题目卡片 → 题目详情页会显示「已解答」，截图保存为 assets/wp/shot-<题号>.png
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOG = ROOT / "evidence" / "submit-log.jsonl"
OUT = ROOT / "assets" / "wp"
CJK = "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
NAMES = {
    "12063": "GraphNexus", "12064": "DataPulse", "12067": "Goodbye!shell",
    "12072": "justledger", "12078": "cacheline", "12080": "Jammed",
    "12082": "谁教坏了我的Agent", "12083": "Lost_Memory", "12085": "VVMM",
    "12086": "NeuralVault",
}


def is_cjk(ch: str) -> bool:
    o = ord(ch)
    return (0x3400 <= o <= 0x4DBF) or (0x4E00 <= o <= 0x9FFF) or (0x3000 <= o <= 0x303F) or (0xFF00 <= o <= 0xFFEF)


def draw_mixed(d: ImageDraw.ImageDraw, xy, text: str, fs: int, bold=False, fill=(24, 30, 38)):
    fc = ImageFont.truetype(CJK, fs + 1)
    fa = ImageFont.truetype(MONO_B if bold else MONO, fs)
    x, y = xy
    for ch in text:
        f = fc if is_cjk(ch) else fa
        d.text((x, y), ch, font=f, fill=fill)
        x += d.textlength(ch, font=f)
    return x


def log_card(rec: dict, cid: str, width: int = 1400, fs: int | None = None) -> Image.Image:
    fs = fs or max(14, int(round(16 * width / 1000)))
    lines = [
        f'time    : {rec["time"]}',
        f'flag    : {rec["flag"]}',
        f'code    : {rec["resp_code"]}',
        f'message : {rec["message"]}',
        f'data    : {json.dumps(rec.get("data", {}), ensure_ascii=False)}',
    ]
    lt, pad = int(fs * 1.5), int(fs * 1.4)
    h = pad * 2 + 36 + lt * len(lines)
    im = Image.new("RGB", (width, h), (245, 247, 250))
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, width - 1, h - 1], outline=(200, 206, 214), width=2)
    d.rectangle([0, 0, width, 36], fill=(32, 44, 62))
    draw_mixed(d, (12, 9), f"平台提交回包原文（evidence/submit-log.jsonl） · {cid} {NAMES.get(cid, '')}", fs + 1, True, (255, 255, 255))
    y = 36 + pad
    for ln in lines:
        draw_mixed(d, (pad, y), ln, fs)
        y += lt
    return im


def compose(cid: str, rec: dict, shot: pathlib.Path, width: int = 1400) -> Image.Image:
    top = Image.open(shot).convert("RGB")
    scale = width / top.width
    top = top.resize((width, int(top.height * scale)), Image.LANCZOS)
    card = log_card(rec, cid, width)
    gap, pad = 14, 20
    h = pad + top.height + gap + card.height + pad + 30
    im = Image.new("RGB", (width, h), (255, 255, 255))
    d = ImageDraw.Draw(im)
    im.paste(top, (0, pad))
    cap_y = pad + top.height + 2
    draw_mixed(d, (12, cap_y), f"平台页面截图：{cid} {NAMES.get(cid, '')}（显示已解答）", 15, False, (70, 80, 95))
    im.paste(card, (0, pad + top.height + 30))
    return im


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--width", type=int, default=1400)
    ap.add_argument("--jpeg", action="store_true", help="输出 JPEG（体积小，适合有上传大小限制的平台）")
    a = ap.parse_args()

    recs = [json.loads(l) for l in LOG.read_text(encoding="utf-8").splitlines() if l.strip()]
    ok = {r["id"]: r for r in recs if r.get("result") is True}
    OUT.mkdir(parents=True, exist_ok=True)

    have, missing = [], []
    for cid, rec in sorted(ok.items(), key=lambda kv: int(kv[0])):
        shot = OUT / f"shot-{cid}.png"
        if shot.exists():
            img = compose(cid, rec, shot, a.width)
            if a.jpeg:
                img.convert("RGB").save(OUT / f"flag-{cid}.jpg", quality=88, optimize=True, progressive=True)
            else:
                img.save(OUT / f"flag-{cid}.png", optimize=True)
            have.append(cid)
        else:
            img = log_card(rec, cid, a.width)
            if a.jpeg:
                img.convert("RGB").save(OUT / f"flag-{cid}.jpg", quality=88, optimize=True, progressive=True)
            else:
                img.save(OUT / f"flag-{cid}.png", optimize=True)
            missing.append(cid)
    print(f"[+] 已生成 {len(ok)} 张：双拼 {len(have)} 张 {have}；仅回包卡 {len(missing)} 张 {missing}")
    if a.list and missing:
        print("\n还缺的平台截图（存为 assets/wp/shot-<题号>.png 后重跑本脚本）：")
        for cid in missing:
            print(f"  - {cid} {NAMES.get(cid,'')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
