#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""复盘扫描：把每个 run 的事件流压成一行结构化事实（供人/agent 分析）。

输出：
  retro/runs.json    每个 run 的完整结构化摘要
  retro/runs.csv     便于表格/Excel 看
  retro/tools.json   每个 run 的工具使用直方图（命令首词/工具名）

为什么单独写：run 的事件流单文件 1–50MB，逐个肉眼读不现实；先把
"题名/结果/耗时/token/工具构成/事实数/失败码"抽出来，再决定深读哪几个。
"""

from __future__ import annotations

import json
import pathlib
import re
import time
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVENTS = ROOT / "state" / "muteki"
OUT = ROOT / "retro"

# 命令分类：用来回答"agent 是在调工具还是在写 python 脚本"
TOOL_PATTERNS = [
    ("radare2", r"\b(r2|radare2|rabin2)\b"),
    ("binwalk", r"\bbinwalk\b"),
    ("unblob", r"\bunblob\b"),
    ("squashfs", r"\b(unsquashfs|sasquatch)\b"),
    ("jffs2/ubi", r"\b(jefferson|ubireader_\w+)\b"),
    ("7z/unzip", r"\b(7z|unzip|cpio)\b"),
    ("file/strings/xxd", r"\b(file|strings|xxd|hexdump)\b"),
    ("qemu", r"\bqemu-[a-z0-9]+(-static)?\b"),
    ("ghidra", r"\b(analyzeHeadless|ghidra)\b"),
    ("gdb", r"\b(gdb|winedbg)\b"),
    ("wine", r"\bwine\b"),
    ("angr/unicorn", r"\b(angr|unicorn|claripy)\b"),
    ("objdump/readelf", r"\b(objdump|readelf|nm)\b"),
    ("curl/nc/socket", r"\b(curl|wget|nc|ncat|socat)\b"),
    ("openssl", r"\bopenssl\b"),
    ("python-script", r"\bpython3?\b"),
    ("shell-recon", r"\b(ls|cat|grep|sed|awk|find|head|tail|wc)\b"),
]


def classify(tool: str) -> str:
    s = tool.lower()
    for name, pat in TOOL_PATTERNS:
        if re.search(pat, s):
            return name
    return "other"


def scan(path: pathlib.Path) -> dict | None:
    started = ended = 0.0
    desc = name = ""
    flag = None
    solved = False
    reason = detail = ""
    tokens = 0
    tok_calls = 0
    cmds: list[str] = []
    facts = 0
    dead_ends = 0
    kinds: Counter = Counter()
    for line in path.open(encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        t = ev.get("event_type", "")
        pl = ev.get("payload") or {}
        ts = float(ev.get("ts") or 0)
        if ts:
            started = started or ts
            ended = max(ended, ts)
        if t == "run.preparing":
            ch = pl.get("challenge") or {}
            name = str(ch.get("name") or name)
            desc = str(ch.get("description") or desc)
        elif t == "run.finished":
            solved = bool(pl.get("solved"))
            flag = pl.get("flag") or flag
            reason = str(pl.get("reason") or "")
            detail = str(pl.get("detail") or "")
        elif t == "cost.update":
            rt = pl.get("run_total") or {}
            tokens = max(tokens, int(rt.get("tokens") or 0))
        elif t == "tool.start":
            tok_calls += 1
            cmds.append(str(pl.get("tool") or ""))
        elif t == "blackboard.delta":
            k = str(pl.get("kind") or "")
            kinds[k] += 1
            if k in {"fact_added", "observation_added"}:
                facts += 1
            elif k == "dead_end":
                dead_ends += 1
    if not started:
        return None
    hist: Counter = Counter()
    for c in cmds:
        hist[classify(c)] += 1
    py_only = sum(1 for c in cmds if classify(c) == "python-script")
    return {
        "run": path.stem,
        "name": name,
        "category": "",
        "desc": desc[:400],
        "solved": solved,
        "flag": flag,
        "reason": reason,
        "detail": detail[:300],
        "duration_min": round((ended - started) / 60, 1) if started and ended else 0,
        "tokens": tokens,
        "cost_usd_est": round(tokens / 1_000_000 * 0.30, 3),
        "tool_calls": tok_calls,
        "python_calls": py_only,
        "fact_events": facts,
        "dead_ends": dead_ends,
        "tool_hist": dict(hist.most_common()),
        "blackboard_kinds": dict(kinds.most_common(12)),
        "cmds_sample": [c[:180] for c in cmds[:6]],
    }


def main() -> int:
    OUT.mkdir(exist_ok=True)
    rows = []
    paths = sorted(EVENTS.glob("*.jsonl"))
    seen = {p.name[:-len(".jsonl")] for p in paths}
    # 被面板归档的 run 只剩 .full 备份；复盘要全量，所以一并扫
    for p in sorted(EVENTS.glob("*.jsonl.full")):
        base = p.name[:-len(".jsonl.full")]
        if base not in seen:
            paths.append(p)
    for p in paths:
        r = scan(p)
        if r:
            r["source"] = p.name
            rows.append(r)
    rows.sort(key=lambda r: (not r["solved"], r["run"]))
    (OUT / "runs.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1),
                                   encoding="utf-8")
    cols = ["run", "name", "solved", "reason", "duration_min", "tokens",
            "cost_usd_est", "tool_calls", "python_calls", "fact_events", "flag"]
    with (OUT / "runs.csv").open("w", encoding="utf-8") as fh:
        fh.write(",".join(cols) + "\n")
        for r in rows:
            fh.write(",".join(str(r.get(c, "")).replace(",", ";") for c in cols) + "\n")
    tot_tok = sum(r["tokens"] for r in rows)
    print(f"{len(rows)} 个 run · 合计 {tot_tok/1e6:.1f}M token "
          f"(≈${tot_tok/1e6*0.30:.2f}) · 解出 {sum(1 for r in rows if r['solved'])}")
    print(f"输出：{OUT/'runs.json'} / {OUT/'runs.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
