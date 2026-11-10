#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为每个 run 生成一份"复盘摘要"（retro/digests/<run>.md）。

摘要包含：结果/耗时/token/工具构成/重启次数/提交过的 flag/首末事实/死路/
首末命令。目的是让人（或复盘 agent）不必读 1–50MB 原始事件流就能判断
"这个 run 在哪一步、用什么手段、卡在哪、为什么死"。

用法：
  python3 tools/retro_digest.py                 # 全部 run
  python3 tools/retro_digest.py run-51063 ...   # 指定
"""

from __future__ import annotations

import json
import pathlib
import sys
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVENTS = ROOT / "state" / "muteki"
OUT = ROOT / "retro" / "digests"


def load(rid: str) -> list[dict]:
    for name in (f"{rid}.jsonl", f"{rid}.jsonl.full"):
        p = EVENTS / name
        if p.is_file():
            out = []
            for line in p.open(encoding="utf-8", errors="replace"):
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            return out
    return []


def digest(rid: str) -> str | None:
    ev = load(rid)
    if not ev:
        return None
    desc = ""
    flags: list[str] = []
    finished = []
    started = 0
    tools: list[str] = []
    facts: list[str] = []
    dead: list[str] = []
    tokens = 0
    submits = 0
    for e in ev:
        t = e.get("event_type", "")
        pl = e.get("payload") or {}
        if t == "run.preparing":
            ch = pl.get("challenge") or {}
            desc = desc or str(ch.get("description") or "")
        elif t == "run.started":
            started += 1
        elif t == "run.finished":
            finished.append(pl)
        elif t == "cost.update":
            rt = pl.get("run_total") or {}
            tokens = max(tokens, int(rt.get("tokens") or 0))
        elif t == "tool.start":
            tools.append(str(pl.get("tool") or ""))
            if "submit_flag" in tools[-1]:
                submits += 1
        elif t == "blackboard.delta":
            k = str(pl.get("kind") or "")
            txt = str(pl.get("fact") or pl.get("text") or pl.get("result_detail") or "").strip()
            if k in {"fact_added", "observation_added"} and len(txt) > 60:
                facts.append(txt)
            elif k == "dead_end" and txt:
                dead.append(txt)
            elif k == "flag_found" and pl.get("flag"):
                flags.append(str(pl["flag"]))

    solv = next((f for f in reversed(finished) if f.get("solved")), None)
    last = finished[-1] if finished else {}
    doc = [f"# {rid}", ""]
    doc.append(f"- 结果：{'✅ solved' if solv else '💀 ' + str(last.get('reason') or 'unknown')}")
    if last.get("detail"):
        doc.append(f"- 失败细节：{str(last['detail'])[:300]}")
    doc.append(f"- run.started 次数（重启）：**{started}**｜run.finished 次数：{len(finished)}")
    doc.append(f"- token（各代最大值）：**{tokens/1e6:.1f}M** ≈ ${tokens/1e6*0.30:.2f}")
    doc.append(f"- 工具调用：{len(tools)} 次｜submit_flag 尝试：{submits}")
    if flags:
        doc.append(f"- 报出的 flag：{sorted(set(flags))}")
    hist = Counter()
    for c in tools:
        low = c.lower()
        for key in ("binwalk", "unblob", "unsquashfs", "7z", "r2", "radare2", "ghidra",
                    "qemu", "gdb", "wine", "angr", "unicorn", "strings", "xxd", "file",
                    "curl", "nc ", "python"):
            if key in low:
                hist[key] += 1
                break
        else:
            hist["other"] += 1
    doc.append(f"- 工具构成：{dict(hist.most_common())}")
    doc.append("")
    if desc:
        doc += ["## 题面", desc[:600], ""]
    if facts:
        doc += ["## 最早 3 条事实"]
        for f in facts[:3]:
            doc.append("- " + " ".join(f.split())[:320])
        doc += ["", "## 最后 5 条事实"]
        for f in facts[-5:]:
            doc.append("- " + " ".join(f.split())[:420])
        doc.append("")
    if dead:
        doc += [f"## 死路（{len(dead)} 条，前 6 条）"]
        for d in dead[:6]:
            doc.append("- " + " ".join(d.split())[:260])
        doc.append("")
    if tools:
        doc += ["## 头 4 条命令"]
        doc += ["- `" + " ".join(c.split())[:200] + "`" for c in tools[:4]]
        doc += ["", "## 尾 12 条命令"]
        doc += ["- `" + " ".join(c.split())[:200] + "`" for c in tools[-12:]]
    return "\n".join(doc) + "\n"


def main(argv: list[str]) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    rids = argv or sorted({p.name.replace(".jsonl.full", "").replace(".jsonl", "")
                           for p in EVENTS.glob("*.jsonl*")})
    n = 0
    for rid in rids:
        doc = digest(rid)
        if doc:
            (OUT / f"{rid}.md").write_text(doc, encoding="utf-8")
            n += 1
    print(f"写出 {n} 份摘要 → {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
