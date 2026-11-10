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

# 题号口径（2026-10-31 修 · 假绿修复 1）：
#   旧正则只认 `\d{4,5}`（4–5 位纯数字），而本场题号是 `Ik_y7i9Zazs2MsSc` /
#   `brz2pZwJzt8gV8r6` 这类**字符串 ID** ⇒ wp.md 一节都解析不到，
#   汇总打印「wp.md 0 节 / submit-log 正确记录 0 题 → [✓] 逐字节对账通过」——
#   自检报绿而实际什么都没对账（假绿）。
#   现在两种都认：
#     * 纯数字题号 4–5 位：**放在前面优先匹配**，兼容旧场次/归档 wp（不改老口径）；
#     * 字符串 ID `[A-Za-z0-9_-]{8,24}`：本场形态，后面带负向前瞻，
#       避免把一个更长的标识切成前 24 个字符而误判成题号。
QID_PAT = r"(?:\d{4,5}|[A-Za-z0-9_-]{8,24})(?![A-Za-z0-9_-])"
SECTION_RE = re.compile(
    rf"^#{{3,4}}\s+(?:题目[一二三四五六七八九十]+：)?({QID_PAT})\s*[·:：]?\s*(.*)$")
FLAG_RE = re.compile(r"^-\s*\*{0,2}flag\*{0,2}\s*[:：]\s*(.+?)\s*$")
SHELL_RE = re.compile(r"^(?:DASCTF|flag)\{(.*)\}$", re.S)
PENDING_WORDS = ("未解出", "未尝试", "不适用", "NOT_ATTEMPTED", "无")


def qkey(cid: str) -> tuple[int, int, str]:
    """排序键：纯数字题号按数值排，字符串题号按字典序排（数字整体在前）。

    旧代码是 `key=lambda kv: int(kv[0])`：题号是 `Ik_y7i9Zazs2MsSc` 时
    int() 会直接 ValueError 把整个自检崩掉。正则修好之后真会走到这里，
    所以必须一并改（否则"修好正则"立刻换来一个 Traceback）。
    """
    return (0, int(cid), "") if cid.isdigit() else (1, 0, cid)


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

    # 假绿修复 1 配套：解析到 0 节 = 口径又错配了，不能当成"通过"。
    # （旧行为：0 节 + 0 题 ⇒ 空循环 ⇒ 无 problems ⇒ 打印 [✓] 并退 0。）
    if not wp:
        print(f"[!] 从 {wp_path} 一节都没解析到 —— 这不是「通过」，是「口径错配」：")
        print("    合法标题形如 `### Ik_y7i9Zazs2MsSc · cwp` 或 `### 1234 · 题名`（3–4 级标题）。")
        print("    先核对题号正则（SECTION_RE）与 wp.md 的标题格式，再谈对账。")
        return 1

    for cid, rec in sorted(solved.items(), key=lambda kv: qkey(kv[0])):
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

    for cid, sec in sorted(wp.items(), key=lambda kv: qkey(kv[0])):
        if cid in solved:
            continue
        if not sec["pending"]:
            problems.append(
                f"{cid}: wp.md 给了 flag“{sec['flag']}”，但 submit-log 无 result=true 记录（不许未证先写）"
            )
        elif args.verbose:
            print(f"[ok] {cid} {sec['name']} = 未解出（与 log 一致）")

    print(f"\n[汇总] wp.md {len(wp)} 节 / submit-log 正确记录 {len(solved)} 题")
    if not solved:
        # 「一致」只等于"wp 与台账没打架"，不等于"有题通过"。
        # 台账 0 条 result:true 时，对账只在"全部未解出"这一种口径上成立，
        # 别把这一行当成交付完成（假绿修复 2 的同类坑，在 wp-pack.py 里是硬红灯）。
        print("[i] 注意：台账里 0 条 result:true —— 本次「通过」只表示"
              "「wp.md 与该台账不矛盾」，不表示任何一题已提交成功。")
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
