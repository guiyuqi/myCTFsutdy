#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""车联网专项赛 2026-11-08 复盘：逐 run 深度摘要（v2）。

v2 与 v1 的区别：
  - 工具分类改为看 **bash 命令内容**（v1 把所有 bash 记成一个桶，看不出"写脚本"还是"调工具"）；
  - 单独统计 meta 调用（submit_fact/commit_step/mark_deadend/submit_flag）——它们是编排开销；
  - 合并 console 的题名（retro/api_names.json）；
  - 额外给"真实逆向工具"计数与"同一条命令重复次数"。
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
from collections import Counter, defaultdict

HOME = pathlib.Path.home()
STATE = HOME / ".ctfagent" / "state" / "muteki"
OUT = pathlib.Path(__file__).resolve().parent / "digests"
NAMES = HOME / ".ctfagent" / "retro" / "api_names.json"

# bash 命令里"真的在调工具"的模式（而不是自己写 python 算）
REAL_TOOLS = [
    ("binwalk", r"\bbinwalk\b"),
    ("unblob", r"\bunblob\b"),
    ("unsquashfs", r"\b(unsquashfs|sasquatch)\b"),
    ("jefferson/ubi", r"\b(jefferson|ubireader_\w+|ubidump)\b"),
    ("7z/cpio", r"\b(7z|7za|unzip|cpio|tar)\b"),
    ("r2", r"\b(r2|radare2|rabin2|rizin)\b"),
    ("ghidra", r"\b(analyzeHeadless|ghidra)\b"),
    ("objdump/readelf", r"\b(objdump|readelf|nm|llvm-objdump)\b"),
    ("xxd/hexdump", r"\b(xxd|hexdump|od)\b"),
    ("strings/grep", r"\b(strings|grep|rg)\b"),
    ("qemu", r"\bqemu-[a-z0-9]+(-static)?\b"),
    ("gdb", r"\b(gdb|winedbg|wine)\b"),
    ("angr/z3", r"\b(angr|claripy|import z3|z3\.)\b"),
    ("openssl", r"\bopenssl\b"),
    ("curl/net", r"\b(curl|wget|nc|ncat|socat)\b"),
    ("file/ls/cat", r"\b(file|ls|cat|head|tail|wc|find|stat)\b"),
]
PY_RE = re.compile(r"\bpython3?\b")
HEREDOC_RE = re.compile(r"<<\s*'?EOF'?|<<\s*'?PY'?")
META = {"submit_fact", "commit_step", "mark_deadend", "submit_flag", "save_poc"}


def bash_class(cmd: str) -> str:
    if HEREDOC_RE.search(cmd):
        return "bash:heredoc-script"
    if re.search(r"python3?\s+[^\s|;&]+\.py", cmd):
        return "bash:python-file"
    if re.search(r"python3?\s+-c\b", cmd):
        return "bash:python-c"
    if PY_RE.search(cmd):
        return "bash:python-other"
    for name, pat in REAL_TOOLS:
        if re.search(pat, cmd):
            return f"tool:{name}"
    return "bash:other"


def tool_class(tool: str) -> str:
    if ":" in tool[:32]:
        head, rest = tool.split(":", 1)
        head = head.strip()
        if head == "bash":
            return bash_class(rest)
        if head in META:
            return f"meta:{head}"
        return f"tool:{head}"
    return f"tool:{tool.strip()[:24]}"


def load(path: pathlib.Path):
    out = []
    for line in path.open(encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def fmt_ts(ts: float, t0: float) -> str:
    m = int((ts - t0) // 60)
    s = int((ts - t0) % 60)
    return f"+{m:03d}:{s:02d}"


def run_body(path: pathlib.Path, names: dict) -> tuple[dict, str]:
    evs = load(path)
    if not evs:
        return {}, ""
    t0 = min(float(e.get("ts") or 0) for e in evs)
    t1 = max(float(e.get("ts") or 0) for e in evs)
    name = names.get(path.stem, "")
    desc = ""
    gens = defaultdict(lambda: {"start": None, "end": None, "tools": [], "facts": 0,
                               "dead": 0, "reason": "", "code": "", "detail": ""})
    tokens = {}
    flags = []
    for e in evs:
        p = e.get("payload") or {}
        t = e.get("event_type") or ""
        ts = float(e.get("ts") or 0)
        g = int(p.get("execution_generation") or 0)
        if not g:
            continue
        d = gens[g]
        if t == "run.started":
            d["start"] = d["start"] or ts
            ch = p.get("challenge") or {}
            desc = desc or str(ch.get("description") or "")
        elif t == "run.finished":
            d["end"] = ts
            d["reason"] = str(p.get("reason") or "")
            d["code"] = str(p.get("failure_code") or "")
            d["detail"] = str(p.get("detail") or "").replace("\n", " ")[:160]
            if p.get("flag"):
                flags.append(str(p["flag"]))
        elif t == "tool.start":
            d["tools"].append((ts, str(p.get("tool") or "")))
        elif t == "cost.update":
            rt = p.get("run_total") or {}
            if rt.get("tokens") is not None:
                tokens[g] = rt
        elif t == "blackboard.delta":
            k = p.get("kind")
            if k in {"fact_added", "observation_added"}:
                d["facts"] += 1
            elif k == "dead_end":
                d["dead"] += 1

    all_tools = [(g, ts, t) for g, d in gens.items() for ts, t in d["tools"]]
    classes = Counter(tool_class(t) for _, _, t in all_tools)
    bash_cmds = [t.split(":", 1)[1].strip() for _, _, t in all_tools if t.startswith("bash:")]
    cmd_dupes = Counter(bash_cmds)
    top_dupe = [(c, n) for c, n in cmd_dupes.most_common(5) if n > 1]
    meta_calls = sum(v for k, v in classes.items() if k.startswith("meta:"))
    py_calls = sum(v for k, v in classes.items() if k.startswith("bash:python") or k == "bash:heredoc-script")
    tool_calls = sum(v for k, v in classes.items() if k.startswith("tool:") and k not in {"tool:read", "tool:ls"})
    tt = max((v.get("tokens") or 0) for v in tokens.values()) if tokens else 0
    ti = max((v.get("input_tokens") or 0) for v in tokens.values()) if tokens else 0
    to = max((v.get("output_tokens") or 0) for v in tokens.values()) if tokens else 0
    unp = max((v.get("unpriced_calls") or 0) for v in tokens.values()) if tokens else 0

    meta = {
        "run": path.stem, "name": name, "desc": desc[:300],
        "start": t0, "end": t1, "dur_min": round((t1 - t0) / 60, 1),
        "gens": len(gens), "calls": len(all_tools),
        "classes": dict(classes.most_common()),
        "meta_calls": meta_calls, "py_calls": py_calls, "tool_calls": tool_calls,
        "py_ratio": round(py_calls / max(1, len(all_tools) - meta_calls), 3),
        "tokens": tt, "in": ti, "out": to, "unpriced": unp,
        "flags": flags,
        "fact": sum(d["facts"] for d in gens.values()),
        "dead": sum(d["dead"] for d in gens.values()),
        "reasons": dict(Counter(d["reason"] or "none" for d in gens.values())),
        "codes": dict(Counter(d["code"] or "-" for d in gens.values())),
        "top_dupe": top_dupe,
    }

    L = [f"# {meta['run']} · {name or '(未命名)'}", ""]
    L.append(f"- 题面：{desc[:240]}")
    L.append(f"- 跨度 **{meta['dur_min']} 分钟** / **{meta['gens']} 代** / 调用 **{meta['calls']}**"
             f"（其中 meta 编排 {meta_calls}，python 类 {py_calls} = 非 meta 的 {meta['py_ratio']:.0%}，"
             f"真工具 {tool_calls}）")
    L.append(f"- token **{meta['tokens']:,}**（入 {meta['in']:,} / 出 {meta['out']:,}，unpriced {unp}）")
    L.append(f"- 事实 {meta['fact']} / 死路 {meta['dead']} / flag {flags or '无'}")
    L.append(f"- 每代结局 {meta['reasons']}")
    L.append(f"- 失败码 {meta['codes']}")
    if top_dupe:
        L.append(f"- 重复命令 top: " + "; ".join(f"{n}× {c[:60]}" for c, n in top_dupe[:3]))
    L.append("")
    L.append("## 工具构成")
    L.append("")
    L.append("```")
    for k, v in classes.most_common(18):
        L.append(f"{v:5d}  {k}")
    L.append("```")
    L.append("")
    L.append("## 时间线（按代）")
    L.append("")
    L.append("| 代 | 起点 | 分钟 | 调用 | 事实 | 死路 | 结局 | 失败码 |")
    L.append("|---|---|---|---|---|---|---|---|")
    for g in sorted(gens):
        d = gens[g]
        st, en = d["start"] or 0, d["end"] or st
        dur = round((en - st) / 60, 1) if st else 0
        L.append(f"| g{g} | {fmt_ts(st, t0) if st else '?'} | {dur} | {len(d['tools'])} | "
                 f"{d['facts']} | {d['dead']} | {d['reason'] or '-'} | {d['code'] or '-'} |")
    L.append("")

    L.append("## 事实与死路（原文，截断 260 字）")
    L.append("")
    n = 0
    seen_txt = set()
    for e in evs:
        p = e.get("payload") or {}
        if e.get("event_type") != "blackboard.delta":
            continue
        k = p.get("kind")
        if k in {"fact_added", "observation_added"}:
            txt = (p.get("text") or p.get("fact") or "").strip().replace("\n", " ")
            key = txt[:80]
            if not txt or key in seen_txt:
                continue
            seen_txt.add(key)
            n += 1
            L.append(f"{n}. [{fmt_ts(float(e.get('ts') or 0), t0)}] {txt[:260]}")
        elif k == "dead_end":
            reason = str(p.get("reason") or "").strip().replace("\n", " ")
            key = "dead:" + reason[:60]
            if key in seen_txt:
                continue
            seen_txt.add(key)
            n += 1
            L.append(f"{n}. [{fmt_ts(float(e.get('ts') or 0), t0)}][DEAD] {reason[:220]}")
    L.append("")
    L.append("## 每代最后 3 条命令")
    L.append("")
    for g in sorted(gens):
        d = gens[g]
        if not d["tools"]:
            continue
        L.append(f"### g{g}（{len(d['tools'])} 调用，结局 {d['reason'] or '-'}/{d['code'] or '-'}）")
        L.append("```")
        for ts, cmd in d["tools"][-3:]:
            L.append(f"{fmt_ts(ts, t0)} {cmd[:200].replace(chr(10), ' ')}")
        L.append("```")
    return meta, "\n".join(L)


def main() -> int:
    OUT.mkdir(exist_ok=True)
    names = {}
    if NAMES.exists():
        names = {k: v.get("name", "") for k, v in json.loads(NAMES.read_text()).items()}
    rows = []
    for p in sorted(STATE.glob("*.jsonl")):
        meta, text = run_body(p, names)
        if not meta:
            continue
        rows.append(meta)
        (OUT / f"{p.stem}.md").write_text(text, encoding="utf-8")
    rows.sort(key=lambda r: r["start"])
    L = ["# 全部 run 对照表（按开始时间）", "",
         "| run | 题名 | 分钟 | 代 | 调用 | meta | py% | 真工具 | token(入/出) | 事实 | 死路 | flag |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        L.append(f"| {r['run']} | {r['name'][:22] or '-'} | {r['dur_min']} | {r['gens']} | {r['calls']} | "
                 f"{r['meta_calls']} | {r['py_ratio']:.0%} | {r['tool_calls']} | "
                 f"{r['tokens']/1e6:.1f}M ({r['in']/1e6:.1f}/{r['out']/1e3:.0f}k) | {r['fact']} | {r['dead']} | "
                 f"{(r['flags'] or ['-'])[0][:28]} |")
    tot = sum(r["tokens"] for r in rows)
    tin = sum(r["in"] for r in rows)
    tout = sum(r["out"] for r in rows)
    cost = tin / 1e6 * 0.30 + tout / 1e6 * 1.20
    L += ["", f"合计 **{len(rows)}** run · **{tot/1e6:.0f}M token**（入 {tin/1e6:.0f}M / 出 {tout/1e6:.2f}M）"
              f" · 按 flash 目录价 ≈ **${cost:.1f}** · 解出 {sum(1 for r in rows if r['flags'])}"]
    (OUT / "ALL.md").write_text("\n".join(L), encoding="utf-8")
    (OUT / "runs_meta.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{len(rows)} runs -> {OUT}")
    print(f"tokens {tot:,} in {tin:,} out {tout:,} ~${cost:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
