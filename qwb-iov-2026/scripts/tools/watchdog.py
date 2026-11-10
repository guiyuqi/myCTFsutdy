#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""看门狗：把跑飞的 run 按墙钟砍掉。

背景：`wall_clock_budget=900` 对手工派发的 run **不生效**（实测 run-51063 跑了
33 分钟、5.9M token）。tsec_eval 的 visit 时间盒是 0，所以刹车只能在外面做：
本脚本轮询事件日志，超过上限还没解出就 POST control {"action":"stop"}。

用法：
  python3 tools/watchdog.py                  # 前台轮询（默认 15 分钟上限）
  python3 tools/watchdog.py --limit 720      # 12 分钟
  python3 tools/watchdog.py --once           # 只检查一轮（测试用）
  python3 tools/watchdog.py --dry-run        # 只打印会砍谁，不动手

决策口径（2026-11-08 定）：单 run 15 分钟没出 flag 就砍，
砍完用 dispatch.py --reuse <run> 带更窄的任务重开。理由：实测 20-33 分钟的
run 平均烧 4M+ token 且 7/8 以 no_progress/failed 结束，边际收益极低。
"""

from __future__ import annotations

import argparse
import glob
import json
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVENTS = ROOT / "state" / "muteki"
BASE = "http://127.0.0.1:8011"
LOG = ROOT / "state" / "watchdog.log"


def note(text: str) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {text}"
    print(line, flush=True)
    try:
        with LOG.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def post(path: str, body: dict, timeout: float = 15.0) -> dict:
    req = urllib.request.Request(
        BASE + path, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode() or "{}")


def scan() -> list[dict]:
    """返回还没收尾的 run（含起始时间、题名、已用秒数）。"""
    now = time.time()
    out = []
    for path in glob.glob(str(EVENTS / "*.jsonl")):
        started = last = 0.0
        name = ""
        finished = False
        token = 0
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
                    ts = float(ev.get("ts") or 0)
                    if ts:
                        started = started or ts
                        last = max(last, ts)
                    t = ev.get("event_type")
                    if t == "run.preparing":
                        name = str((ev.get("payload") or {}).get(
                            "challenge", {}).get("name") or "")
                    elif t == "run.finished":
                        finished = True
                    elif t == "cost.update":
                        token = int(((ev.get("payload") or {}).get("run_total") or {})
                                    .get("tokens") or token)
        except OSError:
            continue
        if finished or not started:
            continue
        out.append({"run": Path(path).stem, "name": name or Path(path).stem,
                    "elapsed": now - started, "idle": now - last, "tokens": token})
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=float, default=900, help="墙钟上限秒（默认 900）")
    ap.add_argument("--idle", type=float, default=0, help="空闲上限秒（0=不管）")
    ap.add_argument("--poll", type=float, default=30)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    note(f"看门狗启动：上限 {args.limit:.0f}s，轮询 {args.poll:.0f}s"
         f"{'，dry-run' if args.dry_run else ''}")
    while True:
        for row in scan():
            reason = ""
            if args.limit and row["elapsed"] > args.limit:
                reason = f"跑过墙钟上限（{row['elapsed'] / 60:.1f} min > {args.limit / 60:.0f} min）"
            elif args.idle and row["idle"] > args.idle:
                reason = f"空闲 {row['idle']:.0f}s 无事件"
            if not reason:
                continue
            if args.dry_run:
                note(f"[dry-run] 会停 {row['run']}（{row['name']}）— {reason}")
                continue
            try:
                post(f"/api/runs/{row['run']}/control", {"action": "stop"})
                note(f"已停 {row['run']}（{row['name']}）— {reason}；"
                     f"tokens≈{row['tokens'] / 1000:.0f}k。续做："
                     f"python3 tools/dispatch.py --reuse {row['run']} …")
            except Exception as exc:          # noqa: BLE001 - 停不掉要记下来
                note(f"停 {row['run']} 失败：{exc}")
        if args.once:
            return 0
        time.sleep(args.poll)


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
