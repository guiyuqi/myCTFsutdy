#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统计 DSH 会话：每个会话的时长、轮次、工具调用量、结束语关键词。

用途（2026-11-02 复盘）：
  * 回答"老模式（一个对话长时间自己跑）vs 新模式（短派单+block 语义）"的差别；
  * 量化 QWB 期间的"投入分布"：多少会话活了多久、每个会话用了多少工具调用。

用法：
    python3 work/sess-stats.py [--store ~/.dsh/sessions/<编码>] [--out work/sess-stats.json]
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

WS = Path(__file__).resolve().parents[1]
DEFAULT_STORE = Path.home() / ".dsh/sessions/--home-fragranstea-ctf-2026--"

# 结束语里出现这些词，说明会话以"负面定性"收尾
NEG = ["blocked", "block", "不可解", "无解", "判死", "放弃", "诱饵", "残留", "无投入",
       "没有投入", "别再做", "勿再投入", "死路", "走不通"]
POS = ["flag{", "已解出", "success", "solved"]


def decompress(path: Path) -> bytes:
    """DSH 的 session.v3.jsonl.zstd 是**多帧追加**流：必须用能处理 concatenated frames 的解压器。"""
    seven = shutil.which("7z") or shutil.which("7zz") or shutil.which("7za")
    if seven:
        r = subprocess.run([seven, "x", "-so", str(path)], capture_output=True)
        if r.returncode == 0 and r.stdout:
            return r.stdout
    raise RuntimeError(f"解不开 {path}：需要 7z")


def text_of(msg) -> str:
    """DSH 的真实结构：{"role":"assistant","content":[{type:text,text:...},{type:tool-call,...}]}"""
    if isinstance(msg, str):
        return msg
    if isinstance(msg, dict):
        c = msg.get("content")
        if isinstance(c, list):
            out = []
            for it in c:
                if isinstance(it, dict):
                    if it.get("type") == "text" and isinstance(it.get("text"), str):
                        out.append(it["text"])
                    elif it.get("type") == "tool-call":
                        out.append(f"[tool {it.get('name')}]")
            return "\n".join(out)
        for k in ("text", "content"):
            v = msg.get(k)
            if isinstance(v, str):
                return v
            if isinstance(v, list):
                out = []
                for it in v:
                    if isinstance(it, dict) and isinstance(it.get("text"), str):
                        out.append(it["text"])
                    elif isinstance(it, str):
                        out.append(it)
                if out:
                    return "\n".join(out)
    return ""


def analyse(path: Path) -> dict:
    try:
        raw = decompress(path).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return {"id": path.parent.name, "error": str(e)}
    first_user = ""
    first_ts = last_ts = None
    turns = tools = 0
    tool_names: dict[str, int] = {}
    last_assistant = ""
    origin = preset = ""
    title = ""
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        t = o.get("type")
        ts = o.get("time") or o.get("createdAt")
        if isinstance(ts, (int, float)):
            ts = ts / 1000.0 if ts > 1e11 else ts
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
        if t == "session":
            origin = o.get("origin", "")
            preset = o.get("agentPreset", "")
        elif t == "session/title":
            d = o.get("data") or {}
            title = d.get("title", "") if isinstance(d, dict) else ""
        elif t == "user/message":
            d = o.get("data") or {}
            txt = text_of(d.get("message") if isinstance(d, dict) and "message" in d else (o.get("message") or d))
            if not first_user and "compacted" not in (o.get("data") or {}):
                first_user = txt[:400]
        elif t == "assistant/message":
            turns += 1
            d = o.get("data") or {}
            txt = text_of(d.get("message") if isinstance(d, dict) and "message" in d else (o.get("message") or d))
            if txt.strip():
                last_assistant = txt[-1500:]
        elif t == "tool/call":
            tools += 1
            d = o.get("data") or {}
            name = d.get("name") or d.get("tool") or "?"
            tool_names[name] = tool_names.get(name, 0) + 1
    low = last_assistant.lower()
    neg_hit = [k for k in NEG if k in low or k in last_assistant]
    pos_hit = [k for k in POS if k in low or k in last_assistant]
    return {
        "id": path.parent.name,
        "origin": origin,
        "preset": preset,
        "title": title,
        "first_user": first_user,
        "span_min": round((last_ts - first_ts) / 60, 1) if first_ts and last_ts else None,
        "start": first_ts,
        "turns": turns,
        "tools": tools,
        "tool_names": tool_names,
        "neg_end": neg_hit,
        "pos_end": pos_hit,
        "tail": last_assistant[-320:],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default=str(DEFAULT_STORE))
    ap.add_argument("--out", default=str(WS / "work/sess-stats.json"))
    args = ap.parse_args()
    store = Path(args.store).expanduser()
    if not store.is_dir():
        sys.exit(f"[!] 没有会话目录 {store}")
    rows = []
    for d in sorted(p for p in store.iterdir() if p.is_dir()):
        f = d / "session.v3.jsonl.zstd"
        if f.exists():
            rows.append(analyse(f))
    Path(args.out).write_text(json.dumps(rows, ensure_ascii=False, indent=1), encoding="utf-8")
    ok = [r for r in rows if "error" not in r]
    print(f"[✓] {len(ok)}/{len(rows)} 个会话解析成功 → {args.out}")
    spans = [r["span_min"] for r in ok if r.get("span_min") is not None]
    tools = [r["tools"] for r in ok]
    if spans:
        spans.sort()
        print(f"    时长(min): 中位 {spans[len(spans)//2]:.0f}  P90 {spans[int(len(spans)*0.9)]:.0f}  最大 {max(spans):.0f}")
        print(f"    工具调用:  中位 {sorted(tools)[len(tools)//2]}  最大 {max(tools)}  合计 {sum(tools)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
