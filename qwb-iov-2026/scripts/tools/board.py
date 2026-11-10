#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一屏看今天所有 run：题名 / 状态 / flag / token / 耗时。

为什么不用面板：面板要开浏览器点进去；比赛里你要的是"扫一眼，谁卡了、谁出 flag了"。
这个脚本直接读 state/muteki/<run>.jsonl，一次把全部 run 汇总成一张表。

用法：
  python3 tools/board.py                 # 全部 run（新的在上）
  python3 tools/board.py --active        # 只看还在跑的
  python3 tools/board.py --solved        # 只看已解出
  python3 tools/board.py --watch 30      # 每 30 秒重画（Ctrl-C 停）
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVENTS = ROOT / "state" / "muteki"
DONE = {"run.finished"}
STATE_WORDS = {
    "solved": "✅ 解出",
    "runtime_failure": "💀 失败",
    "cancelled": "⏹ 停",
    "budget_exhausted": "🔇 预算",
}


def summarize(path: str) -> dict | None:
    name, category, started, ended, solved, reason, flag = "", "", 0.0, 0.0, None, "", ""
    tokens, tools, last_ts = 0, 0, 0.0
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                t = ev.get("event_type", "")
                p = ev.get("payload") or {}
                ts = float(ev.get("ts") or 0)
                if ts:
                    last_ts = ts
                    started = started or ts
                if t == "run.preparing":
                    ch = p.get("challenge") or {}
                    name = str(ch.get("name") or name)
                    category = str(ch.get("category") or category)
                elif t == "tool.start":
                    tools += 1
                elif t == "cost.update":
                    rt = p.get("run_total") or {}
                    tokens = int(rt.get("tokens") or tokens)
                elif t == "worker.finished" and p.get("flag"):
                    flag = str(p.get("flag"))
                elif t == "run.finished":
                    solved = bool(p.get("solved"))
                    reason = str(p.get("reason") or "")
                    flag = str(p.get("flag") or flag)
                    ended = ts
    except OSError:
        return None
    if not name and not started:
        return None
    return {
        "run": Path(path).stem, "name": name or Path(path).stem,
        "category": category, "started": started, "ended": ended,
        "solved": solved, "reason": reason, "flag": flag,
        "tokens": tokens, "tools": tools, "last": last_ts,
    }


def line_for(row: dict, now: float) -> str:
    if row["ended"]:
        status = STATE_WORDS.get("solved" if row["solved"] else row["reason"],
                                "✅ 解出" if row["solved"] else f"💀 {row['reason'] or '?'}")
        dur = row["ended"] - row["started"]
    elif now - row["last"] < 180:
        status = "⏳ 运行中"
        dur = now - row["started"]
    else:
        status = "💤 已停（无收尾事件）"
        dur = row["last"] - row["started"]
    mmss = f"{int(dur // 60)}m{int(dur % 60):02d}s"
    flag = row["flag"] or ("—" if not row["solved"] else "?")
    return (f"{row['run']:<14} {row['name'][:22]:<22} {row['category'][:8]:<8} "
            f"{status:<12} {mmss:>7}  {row['tokens'] / 1000:>6.0f}k tok  {row['tools']:>3} tools  {flag}")


def draw(args) -> int:
    now = time.time()
    rows = [r for r in (summarize(p) for p in glob.glob(str(EVENTS / "*.jsonl"))) if r]
    if args.active:
        rows = [r for r in rows if not r["ended"] and now - r["last"] < 180]
    if args.solved:
        rows = [r for r in rows if r["solved"]]
    rows.sort(key=lambda r: r["started"], reverse=True)
    if args.limit:
        rows = rows[: args.limit]

    print(f"== ctfagent 看板 · {time.strftime('%H:%M:%S')} · {len(rows)} 个 run ==")
    print(f"{'run':<14} {'题名':<22} {'类别':<8} {'状态':<12} {'耗时':>7}  {'token':>10}  "
          f"{'工具':>7}  flag")
    total_tok = 0
    for row in rows:
        print(line_for(row, now))
        total_tok += row["tokens"]
    print(f"-- 合计 {total_tok / 1000:.0f}k token ≈ ${total_tok / 1e6 * 0.30:.2f}"
          f"（flash 按 $0.30/M 输入粗估，输出另计）")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--active", action="store_true", help="只看运行中")
    ap.add_argument("--solved", action="store_true", help="只看已解出")
    ap.add_argument("--limit", type=int, default=0, help="最多显示几条（默认全部）")
    ap.add_argument("--watch", type=float, default=0, help="每 N 秒重画")
    args = ap.parse_args(argv)
    if args.watch:
        try:
            while True:
                os.system("clear" if os.environ.get("TERM") else "")
                draw(args)
                time.sleep(args.watch)
        except KeyboardInterrupt:
            return 0
    return draw(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
