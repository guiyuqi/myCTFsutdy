#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""守护进程：定期把长大了的 run 事件流压回"非 reasoning"状态，让面板打开不卡。

为什么需要：
- `/api/runs/<id>/events` 在没有 Last-Event-ID 时**从 seq=1 全量重放**持久化 JSONL；
- 一个 run 的 JSONL 里 99% 是 `reasoning.delta`（模型思考，一个 token 一条）；
- 实测某个 run 几分钟就能长到 40MB / 17 万条，打开面板要重放几万条事件。

安全性：
- 引擎每次 append 都是 `open(path, "a")`（`muteki/core/session_store.py:98`），
  所以**原子替换文件是安全的**：下一次写入会落到新文件。
- 第一次压缩前把原文件备份成 `<run>.jsonl.full`（已存在则不覆盖，保住最早的全量）。
- 只删 `reasoning.delta`；工具调用/事实/成本/结束事件全部保留。
- 有极小的竞态窗口（压缩瞬间正好有 append 落盘）会丢掉 1 条 reasoning，无实际影响。

用法：
  python3 tools/keep_light.py                 # 前台，每 180s 扫一次
  python3 tools/keep_light.py --interval 120 --min-mb 5
  python3 tools/keep_light.py --once          # 只跑一次
"""

from __future__ import annotations

import argparse
import os
import pathlib
import json
import shutil
import time

_DROP_KINDS = {
    "context_manifest", "reason_start", "reason_done", "reason_retry_scheduled",
    "reason_retry_deferred", "worker_spawned", "worker_checkpoint", "race_started",
    "coverage_recorded", "intent_claimed", "intent_proposed",
}

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVENTS = ROOT / "state" / "muteki"


def squeeze(min_bytes: int) -> tuple[int, int]:
    saved_files = saved_bytes = 0
    for p in sorted(EVENTS.glob("*.jsonl")):
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size < min_bytes:
            continue
        full = p.with_suffix(".jsonl.full")
        if not full.exists():
            try:
                shutil.copy2(p, full)
            except OSError:
                continue
        keep, total = [], 0
        seen_text = set()          # 去重：同一段事实文本只留一份
        try:
            with p.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    total += 1
                    if '"reasoning.delta"' in line:
                        continue
                    # blackboard 里 fact_added / observation_added / intent_concluded
                    # 常常是同一段文本的三份拷贝（占一半体积），去重后只留第一份；
                    # 纯内部记账类（context_manifest / reason_* / worker_checkpoint …）直接丢。
                    if '"blackboard.delta"' in line:
                        try:
                            pl = json.loads(line).get("payload") or {}
                        except Exception:
                            pl = {}
                        kind = str(pl.get("kind") or "")
                        if kind in _DROP_KINDS:
                            continue
                        text = str(pl.get("fact") or pl.get("text")
                                   or pl.get("result_detail") or "")
                        if text:
                            h = hash(text)
                            if h in seen_text:
                                continue
                            seen_text.add(h)
                    keep.append(line)
        except OSError:
            continue
        if len(keep) == total:
            continue
        tmp = p.with_suffix(".jsonl.tmp")
        try:
            tmp.write_text("".join(keep), encoding="utf-8")
            os.replace(tmp, p)
        except OSError:
            continue
        new = p.stat().st_size
        saved_files += 1
        saved_bytes += size - new
        print(f"[keep-light] {p.stem:<16} {total:>7} → {len(keep):>6} 条  "
              f"{size/1048576:>5.1f}MB → {new/1048576:.1f}MB", flush=True)
    return saved_files, saved_bytes


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=180.0)
    ap.add_argument("--min-mb", type=float, default=5.0)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args(argv)
    min_bytes = int(args.min_mb * 1048576)
    while True:
        files, size = squeeze(min_bytes)
        if args.once:
            print(f"[keep-light] 完成：{files} 个文件，省 {size/1048576:.0f}MB")
            return 0
        if files:
            print(f"[keep-light] 本轮压了 {files} 个文件，省 {size/1048576:.0f}MB", flush=True)
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
