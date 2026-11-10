#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""压缩已结束 run 的事件流，让面板打开它不再卡。

为什么需要它：`/api/runs/<id>/events` 在没有 Last-Event-ID 时**从 seq=1 全量重放**
持久化 JSONL（`muteki/core/session_store.py: replay_monotonic`）。而一个 run 的
JSONL 里 99% 是 `reasoning.delta`（模型思考，一个 token 一条）：
  run-914360 = 77,140 条 / 17 MB，其中 76,379 条是 reasoning.delta
所以打开一个 run = 重放几万条事件，经 Next 代理后 3 秒才 38 KB。

本脚本只做一件事：把**已结束**的 run 的 `reasoning.delta` 行删掉，其余（工具调用、
blackboard 事实、成本、结束事件）全部保留；原文件备份成 `<run>.jsonl.full`。
`replay_monotonic` 会把 seq 重排成连续值，所以删行造成的空洞是安全的。

用法：
  python3 tools/compact_events.py --list              # 看每个 run 能省多少
  python3 tools/compact_events.py --all               # 压缩所有已结束的 run
  python3 tools/compact_events.py run-914360 run-63775
  python3 tools/compact_events.py --all --dry-run
  python3 tools/compact_events.py --restore run-914360   # 从 .full 还原

注意：**不会碰还在跑的 run**（没有 run.finished 的一律跳过），避免打断现场。
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVENTS = ROOT / "state" / "muteki"
# 删掉这些（纯流式噪声）；其余全部保留
DROP = {"reasoning.delta"}


def scan(path: Path) -> dict:
    total = kept = 0
    finished = False
    size = path.stat().st_size
    keep_bytes = 0
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            total += 1
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                kept += 1
                keep_bytes += len(line)
                continue
            if ev.get("event_type") == "run.finished":
                finished = True
            if ev.get("event_type") in DROP:
                continue
            kept += 1
            keep_bytes += len(line)
    return {"path": path, "total": total, "kept": kept, "finished": finished,
            "size": size, "keep_bytes": keep_bytes}


def compact(row: dict, dry: bool) -> None:
    path: Path = row["path"]
    if not row["finished"]:
        print(f"  · 跳过 {path.stem}（还在跑 / 没有 run.finished）")
        return
    if row["kept"] == row["total"]:
        print(f"  · 跳过 {path.stem}（没有可删的 reasoning）")
        return
    if dry:
        print(f"  · [dry] {path.stem}: {row['total']} → {row['kept']} 条，"
              f"{row['size'] / 1048576:.1f} MB → {row['keep_bytes'] / 1048576:.1f} MB")
        return
    full = path.with_suffix(path.suffix + ".full")
    if not full.exists():
        shutil.copy2(path, full)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with path.open(encoding="utf-8", errors="replace") as src, \
            tmp.open("w", encoding="utf-8") as dst:
        for line in src:
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                dst.write(line)
                continue
            if ev.get("event_type") in DROP:
                continue
            dst.write(line)
    os.replace(tmp, path)
    print(f"  ✓ {path.stem}: {row['total']} → {row['kept']} 条，"
          f"{row['size'] / 1048576:.1f} MB → {path.stat().st_size / 1048576:.1f} MB"
          f"（原文件 {full.name}）")


def restore(run: str) -> None:
    path = EVENTS / f"{run}.jsonl"
    full = path.with_suffix(path.suffix + ".full")
    if not full.exists():
        raise SystemExit(f"没有备份：{full}")
    shutil.copy2(full, path)
    print(f"已还原 {run}（{path.stat().st_size / 1048576:.1f} MB）")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", nargs="*", help="run id；不给就配合 --all")
    ap.add_argument("--all", action="store_true", help="所有已结束的 run")
    ap.add_argument("--list", action="store_true", help="只统计不写")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--restore", default="", help="从 .full 还原某个 run")
    args = ap.parse_args(argv)

    if args.restore:
        restore(args.restore)
        return 0

    if args.all or (args.list and not args.runs):
        paths = [Path(p) for p in glob.glob(str(EVENTS / "*.jsonl"))]
    elif args.runs:
        paths = [EVENTS / f"{r}.jsonl" for r in args.runs]
    else:
        raise SystemExit("给 run id，或 --all")

    rows = [scan(p) for p in paths if p.is_file()]
    rows.sort(key=lambda r: -r["size"])
    before = sum(r["size"] for r in rows)
    if args.list:
        print(f"{'run':<26} {'事件':>8} {'保留':>8} {'体积':>9} {'压缩后':>9} 状态")
        for r in rows:
            print(f"{r['path'].stem:<26} {r['total']:>8} {r['kept']:>8} "
                  f"{r['size'] / 1048576:>8.1f}M {r['keep_bytes'] / 1048576:>8.1f}M "
                  f"{'已结束' if r['finished'] else '运行中/未收尾'}")
        print(f"合计 {before / 1048576:.1f} MB → "
              f"{sum(r['keep_bytes'] for r in rows) / 1048576:.1f} MB")
        return 0

    for r in rows:
        compact(r, dry=args.dry_run)
    after = sum(r["path"].stat().st_size for r in rows)
    print(f"\n合计 {before / 1048576:.1f} MB → {after / 1048576:.1f} MB")
    print("面板打开这些 run 时重放的事件数会少 99%（仍是全量重放，但量小了）")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
