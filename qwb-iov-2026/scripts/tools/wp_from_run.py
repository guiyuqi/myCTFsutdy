#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 muteki run 的事件流生成 WP 草稿（人再改）。

设计取舍：
- **不编过程**。叙述只用到事件流里真实出现的 fact/observation（原样引用），
  推断处一律标 `【需确认】`；工具调用按时间顺序列成"操作流水"。
- 一篇 WP = 题面 / 环境 / 解题路径（叙述）/ 实测记录（证据，原样）/ 复现要点 / flag。
- 产物清单只列 >2KB 且排除缓存目录，避免一堆空文件。

用法：
  python3 tools/wp_from_run.py run-37596 run-63775 --out .tmp/wp
  python3 tools/wp_from_run.py --all-solved --out .tmp/wp
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVENTS = ROOT / "state" / "muteki"
SESSIONS = ROOT / "state" / "sessions"
SKIP_PARTS = {".cache", ".agents", "homes", "logs", ".muteki", ".muteki-skills",
              ".muteki-agent-state", ".muteki-blackboard-ingress", ".tmp"}
SKIP_PREFIX = ("prev-",)


def load(run: str) -> list[dict]:
    path = EVENTS / f"{run}.jsonl"
    out = []
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


def facts_of(events: list[dict]) -> list[str]:
    seen, out = set(), []
    for ev in events:
        pl = ev.get("payload") or {}
        if ev.get("event_type") != "blackboard.delta":
            continue
        if pl.get("kind") not in {"fact_added", "observation_added", "intent_concluded"}:
            continue
        text = str(pl.get("fact") or pl.get("text") or pl.get("result_detail") or "").strip()
        if len(text) < 80:
            continue
        key = text[:120]
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
    return out


def tools_of(events: list[dict]) -> list[str]:
    out = []
    for ev in events:
        if ev.get("event_type") != "tool.start":
            continue
        pl = ev.get("payload") or {}
        args = pl.get("args") or {}
        cmd = str(args.get("command") or args.get("flag") or pl.get("tool") or "").strip()
        if cmd and cmd not in out[-1:]:
            out.append(cmd)
    return out


def files_of(run: str, limit: int = 25) -> list[tuple[str, int]]:
    ws = SESSIONS / run / "workspace"
    rows = []
    if not ws.is_dir():
        return rows
    for base, dirs, names in os.walk(ws):
        dirs[:] = [d for d in dirs if d not in SKIP_PARTS and not d.startswith(SKIP_PREFIX)]
        for name in names:
            p = Path(base) / name
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if size < 2048:
                continue
            rows.append((str(p.relative_to(ws)), size))
    rows.sort(key=lambda r: -r[1])
    return rows[:limit]


def write_wp(run: str, outdir: Path) -> Path | None:
    events = load(run)
    if not events:
        return None
    name = run
    desc = ""
    flag = None
    started = ended = 0.0
    for ev in events:
        pl = ev.get("payload") or {}
        t = ev.get("event_type")
        ts = float(ev.get("ts") or 0)
        if t == "run.preparing":
            ch = pl.get("challenge") or {}
            desc = str(ch.get("description") or desc)
            name = str(ch.get("name") or name)
            started = ts
        elif t == "run.finished":
            flag = pl.get("flag") or flag
            ended = ts
    facts = facts_of(events)
    tools = tools_of(events)
    files = files_of(run)
    dur = (ended - started) / 60 if started and ended else 0

    doc = [f"# {name} — Write-up", ""]
    doc.append(f"> 证据来源：muteki run `{run}`（时长 ≈{dur:.0f} 分钟，"
               f"事件 {len(events)} 条）。本文由事件流自动生成草稿，"
               f"叙述部分请人复核；标 `【需确认】` 的地方是推断，未经验证。")
    doc.append("")
    doc.append(f"**FLAG：** `{flag}`" if flag else "**FLAG：** 未取得")
    doc.append("")
    doc.append("## 1. 题面")
    doc.append("")
    doc.append(desc.strip() or "【需确认】题面未记录")
    doc.append("")
    doc.append("## 2. 环境与附件")
    doc.append("")
    doc.append("- 附件与工作区：`state/sessions/" + run + "/workspace/`（下表为其中 >2KB 的产物）")
    doc.append("- 工具链：binwalk / unblob / unsquashfs / 7z / r2 / gdb-multiarch / "
               "qemu-*-static / ghidra(analyzeHeadless) / python3(capstone,pwntools,lief,z3,angr,unicorn,Crypto) / wine")
    doc.append("")
    if files:
        doc.append("| 产物 | 大小 |")
        doc.append("|---|---|")
        for rel, size in files:
            doc.append(f"| `{rel}` | {size} B |")
        doc.append("")

    doc.append("## 3. 解题路径（按事实整理，需人工顺一遍）")
    doc.append("")
    for idx, fact in enumerate(facts[:14], 1):
        head = fact.split("\n")[0][:150]
        doc.append(f"{idx}. **{head}**")
        body = fact.strip()
        if len(body) > len(head) + 20:
            doc.append("")
            doc.append("   ```text")
            for line in body.splitlines()[1:14]:
                doc.append("   " + line)
            doc.append("   ```")
        doc.append("")

    doc.append("## 4. 操作流水（真实执行过的命令，前 40 条）")
    doc.append("")
    for cmd in tools[:40]:
        one = " ".join(cmd.split())
        doc.append(f"1. `{one[:220]}`")
    doc.append("")

    doc.append("## 5. 关键结论与复现要点")
    doc.append("")
    if facts:
        doc.append("最后一轮收束：")
        doc.append("")
        doc.append("```text")
        for line in facts[-1].splitlines()[:20]:
            doc.append(line)
        doc.append("```")
    doc.append("")
    doc.append("【需确认】复现所需的最小文件集、起始命令、以及判定成功的判据（人补）。")
    doc.append("")
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / f"WP-{name.replace('/', '_')}-{run}.md"
    path.write_text("\n".join(doc) + "\n", encoding="utf-8")
    return path


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", nargs="*")
    ap.add_argument("--all-solved", action="store_true")
    ap.add_argument("--out", default=".tmp/wp")
    args = ap.parse_args(argv)
    runs = list(args.runs)
    if args.all_solved:
        for p in EVENTS.glob("*.jsonl"):
            if '"solved": true' in p.read_text(encoding="utf-8", errors="replace"):
                runs.append(p.stem)
    if not runs:
        raise SystemExit("给 run id，或 --all-solved")
    for run in dict.fromkeys(runs):
        path = write_wp(run, Path(args.out))
        print(f"{run}: {path if path else '跳过（无事件）'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
