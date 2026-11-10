#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""看一个 run 的事件尾巴（读 state/muteki/<run>.jsonl，不走 SSE）。

为什么不用 /api/runs/<id>/events：那是 SSE 流，curl 不退，终端里很难用。
事件行本来就落在 state/muteki/<run>.jsonl，直接读更快也更稳。

用法：
  python3 tools/run_events.py run-3335              # 最后 40 条（思考合并、工具精简）
  python3 tools/run_events.py run-3335 -n 100       # 更多
  python3 tools/run_events.py run-3335 --tools      # 只看工具调用
  python3 tools/run_events.py run-3335 --flag       # 只看结论/flag/成本
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEEP = {
    "run.preparing", "run.started", "run.finished", "progress.brief",
    "worker.finished", "worker.lifecycle", "worker.status", "cost.update",
    "flag.delta", "sharedgraph.delta", "blackboard.delta",
}
INTERESTING_BB = {
    "flag_found", "worker_finished", "goal_conclude_complete", "race_started",
    "worker_spawned", "intent_concluded", "fact_added", "observation_added",
    "worker_checkpoint", "coverage_recorded",
}


def clip(text: str, n: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


def render(event: dict, n: int) -> str | None:
    t = event.get("event_type", "")
    p = event.get("payload") or {}
    if t == "reasoning.delta":
        return None                      # 思考流噪声太大，默认不显示
    if t == "tool.start":
        args = p.get("args") or {}
        head = args.get("command") if isinstance(args, dict) else None
        return f"[tool] {p.get('tool')}: {clip(head or json.dumps(args, ensure_ascii=False), n)}"
    if t == "tool.result":
        r = (p.get("result") or {}).get("condensed") or ""
        return f"   ↳ {clip(r, n)}" if r else None
    if t == "blackboard.delta":
        kind = p.get("kind", "")
        if kind not in INTERESTING_BB:
            return None
        for key in ("flag", "result_detail", "text"):
            if p.get(key):
                return f"[bb:{kind}] {clip(p[key], n)}"
        return f"[bb:{kind}] {clip(json.dumps(p, ensure_ascii=False), n)}"
    if t == "run.finished":
        return (f"[run.finished] solved={p.get('solved')} reason={p.get('reason')} "
                f"flag={p.get('flag')}")
    if t == "worker.finished":
        return f"[worker.finished] solved={p.get('solved')} flags={p.get('flags')}"
    if t == "cost.update":
        rt = p.get("run_total") or {}
        return f"[cost] tokens={rt.get('tokens')} run_total_usd={rt.get('usd')}"
    if t in KEEP:
        return f"[{t}] {clip(json.dumps(p, ensure_ascii=False), n)}"
    return None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run")
    ap.add_argument("-n", "--lines", type=int, default=40)
    ap.add_argument("--width", type=int, default=200)
    ap.add_argument("--tools", action="store_true", help="只看工具调用与结果")
    ap.add_argument("--flag", action="store_true", help="只看结论/flag/成本")
    args = ap.parse_args(argv)

    path = ROOT / "state" / "muteki" / f"{args.run}.jsonl"
    if not path.is_file():
        raise SystemExit(f"没有这个 run 的事件日志：{path}")

    outline: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        t = ev.get("event_type", "")
        if args.tools and t not in {"tool.start", "tool.result"}:
            continue
        if args.flag and t not in {"run.finished", "worker.finished", "cost.update",
                                   "progress.brief", "blackboard.delta", "flag.delta"}:
            continue
        text = render(ev, args.width)
        if text:
            outline.append(text)
    for line in outline[-args.lines:]:
        print(line)
    print(f"\n（共 {len(outline)} 条可读事件，显示最后 {min(args.lines, len(outline))} 条）")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
