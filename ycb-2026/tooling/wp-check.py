#!/usr/bin/env python3
"""wp.md ↔ evidence/submit-log.jsonl 逐字节对账（收尾必跑）。

用法:
    python3 scripts/wp-check.py            # 对账，退出码 0=一致 1=有差异
    python3 scripts/wp-check.py --verbose  # 打印每题明细
    python3 scripts/wp-check.py --fix-hint # 只提示怎么修，不改文件

判据（不猜）:
  * "已解出" = submit-log 里该题存在 result=true 的记录（取最后一条）。
  * wp.md 每节的 `- **flag**: X` 取反引号内的 X；剥掉 DASCTF{}/flag{} 外壳后逐字节比较。
  * 未解出的题 wp.md 必须写"未解出"/"未尝试"/"不适用"，且 submit-log 不得有 result=true。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WP = ROOT / "wp.md"
LOG = ROOT / "evidence" / "submit-log.jsonl"

SECTION_RE = re.compile(r"^#{3,4}\s+(?:题目[一二三四五六七八九十]+：)?(\d{4,5})\s*[·:：]?\s*(.*)$")
FLAG_RE = re.compile(r"^-\s*\*{0,2}flag\*{0,2}\s*[:：]\s*(.+?)\s*$")
SHELL_RE = re.compile(r"^(?:DASCTF|flag)\{(.*)\}$", re.S)
PENDING_WORDS = ("未解出", "未尝试", "不适用", "NOT_ATTEMPTED", "无")


def bare(s: str) -> str:
    """剥掉 DASCTF{}/flag{} 外壳，返回裸串（平台只收裸串）。"""
    s = s.strip()
    s = s.strip("`").strip()
    m = SHELL_RE.match(s)
    return m.group(1) if m else s


def parse_wp(path: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    cur: dict | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        m = SECTION_RE.match(line)
        if m:
            cid, name = m.group(1), m.group(2).strip()
            cur = {"id": cid, "name": name, "flag_line": "", "flag": "", "pending": False}
            out[cid] = cur
            continue
        if cur is None:
            continue
        fm = FLAG_RE.match(line.strip())
        if fm:
            cur["flag_line"] = fm.group(1)
            cur["flag"] = bare(fm.group(1))
            cur["pending"] = any(w in fm.group(1) for w in PENDING_WORDS)
    return out


def parse_log(path: Path) -> dict[str, dict]:
    solved: dict[str, dict] = {}
    if not path.exists():
        return solved
    for ln in path.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if rec.get("result") is True or (rec.get("data") or {}).get("isCorrect") is True:
            solved[str(rec.get("id"))] = rec
    return solved


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("wp", nargs="?", default=None,
                    help="WP 文件路径（默认 <工作区>/wp.md；归档里可用 wp-ycb-2026.md）")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--fix-hint", action="store_true")
    args = ap.parse_args()

    wp_path = Path(args.wp).expanduser().resolve() if args.wp else WP
    if not wp_path.exists():
        print(f"[!] 缺 {wp_path}")
        return 1
    wp = parse_wp(wp_path)
    solved = parse_log(LOG)
    problems: list[str] = []

    for cid, rec in sorted(solved.items(), key=lambda kv: int(kv[0])):
        want = bare(str(rec.get("flag", "")))
        sec = wp.get(cid)
        if sec is None:
            problems.append(f"{cid}: submit-log 有正确记录（{want}），wp.md 没有这一节")
            continue
        if sec["pending"]:
            problems.append(f"{cid}: submit-log 已解出（{want}），wp.md 仍写“{sec['flag_line']}”")
            continue
        if sec["flag"] != want:
            problems.append(f"{cid}: 不一致 wp=“{sec['flag']}” log=“{want}”")
        elif args.verbose:
            print(f"[ok] {cid} {sec['name']} = {want}")

    for cid, sec in sorted(wp.items(), key=lambda kv: int(kv[0])):
        if cid in solved:
            continue
        if not sec["pending"]:
            problems.append(
                f"{cid}: wp.md 给了 flag“{sec['flag']}”，但 submit-log 无 result=true 记录（不许未证先写）"
            )
        elif args.verbose:
            print(f"[ok] {cid} {sec['name']} = 未解出（与 log 一致）")

    print(f"\n[汇总] wp.md {len(wp)} 节 / submit-log 正确记录 {len(solved)} 题")
    if not problems:
        print("[✓] 逐字节对账通过")
        return 0
    print(f"[!] {len(problems)} 处差异：")
    for p in problems:
        print("   -", p)
    if args.fix_hint:
        print("\n修法：以 submit-log 的 flag 为准改 wp.md；无 result=true 的题把 flag 行改成“未解出”。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
