#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A. 注入审计 v2：本场（qwb-iov-2026）+ 上一场主赛（qwb-2026）的文本与附件。

对每个来源：
  - run 事件流：tool.result 的 result（递归收集所有字符串）、worker.prompt、blackboard 事实
  - 文本文件：evidence/notes/retrospective 下的 .md/.json/.txt/.log
  - 附件：递归解包，扫文本文件与二进制 strings（不扫压缩包字节）
输出 findings2.json；控制台打印"非自指"命中与统计。
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
from collections import Counter

HOME = pathlib.Path.home()
WORK = HOME / "dsh-workspace/dsh-plugin-ctf/research/injection-audit"
UNPACK = WORK / "unpacked2"

PHRASE = re.compile(
    r"(?i)("
    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instruction|prompt|message)"
    r"|disregard\s+(the\s+)?(above|previous|prior)"
    r"|system[_\s]?(instruction|prompt|message)"
    r"|you\s+are\s+(now\s+)?(an?\s+)?(ai|assistant|llm|language\s+model)"
    r"|new\s+instructions?"
    r"|prompt\s+injection"
    r"|忽略\s*(以上|之前|前面|上述).{0,10}(指令|要求|提示|内容)"
    r"|(系统|管理员)(指令|提示|命令)"
    r"|你现在是"
    r"|不要(分析|继续|回答|理会)"
    r"|跳[过過]\s*(分析|细节)"
    r"|SYSTEM_INSTRUCTION"
    r")")
CTRL_TOKEN = re.compile(
    r"(?i)(<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>"
    r"|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>|###\s*(system|assistant|human)\s*:)")
SUSP = {
    "tag_block": re.compile("[\U000E0000-\U000E007F]"),
    "format_cf": re.compile("[\u00AD\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]"),
    "variation_selector": re.compile("[\uFE00-\uFE0F\U000E0100-\U000E01EF]"),
    "cyrillic": re.compile("[\u0400-\u04FF]"),
    "greek": re.compile("[\u0370-\u03FF]"),
}
MIXED = re.compile(r"(?i)(?:[a-z][\u0400-\u04FF\u0370-\u03FF]|[\u0400-\u04FF\u0370-\u03FF][a-z])")

# 我们自己的纪律文本（会提到 SYSTEM_INSTRUCTION / 指令性文字），命中算自指，不算敌意注入
SELF_REF = ("指令性文字（如", "平台规则明令禁止", "当数据、记成可疑字符串", "prompt injection 的字符串",
            "如 SYSTEM_INSTRUCTION", "一律当数据")


def ctx(text: str, i: int, j: int, n: int = 70) -> str:
    return text[max(0, i - n):j + n].replace("\n", " ")


def scan_text(text: str, where: str, kind: str, source: str, out: list) -> None:
    for name, rx in (("phrase", PHRASE), ("ctrl_token", CTRL_TOKEN)):
        for m in rx.finditer(text):
            c = ctx(text, m.start(), m.end())
            o = {"source": source, "where": where, "kind": kind, "signal": name,
                 "match": m.group(0)[:80], "context": c}
            if any(s in c for s in SELF_REF):
                o["self_ref"] = True
            out.append(o)
    for name, rx in SUSP.items():
        ms = list(rx.finditer(text))
        if not ms:
            continue
        o = {"source": source, "where": where, "kind": kind, "signal": f"unicode:{name}",
             "count": len(ms), "context": ctx(text, ms[0].start(), ms[0].end(), 50)}
        if name == "tag_block":
            dec = "".join(chr(ord(ch) - 0xE0000) for ch in text if 0xE0000 <= ord(ch) <= 0xE007F)
            o["tag_decoded_sample"] = dec[:120]
        out.append(o)
    m = MIXED.search(text)
    if m:
        out.append({"source": source, "where": where, "kind": kind, "signal": "mixed_script",
                    "match": m.group(0), "context": ctx(text, m.start(), m.end(), 40)})


def walk_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from walk_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from walk_strings(v)


def scan_run_logs(logs_dir: pathlib.Path, source: str, out: list) -> dict:
    stats = {}
    for p in sorted(logs_dir.glob("*.jsonl")):
        n = {"tool_result": 0, "worker_prompt": 0, "facts": 0}
        for line in p.open(errors="replace"):
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = e.get("event_type") or ""
            pl = e.get("payload") or {}
            if t == "tool.result":
                n["tool_result"] += 1
                for s in walk_strings(pl.get("result")):
                    if len(s) > 20:
                        scan_text(s, p.name, "tool_result", source, out)
            elif t == "worker.prompt":
                n["worker_prompt"] += 1
                scan_text(str(pl.get("prompt") or ""), p.name, "worker_prompt", source, out)
            elif t == "blackboard.delta" and pl.get("kind") in {"fact_added", "observation_added"}:
                n["facts"] += 1
                scan_text(str(pl.get("text") or pl.get("fact") or ""), p.name, "fact", source, out)
        stats[p.name] = n
    return stats


def scan_text_files(root: pathlib.Path, source: str, out: list, limit: int = 4_000_000) -> int:
    n = 0
    if not root.exists():
        return 0
    for f in root.rglob("*"):
        if not f.is_file() or f.stat().st_size > limit:
            continue
        if f.suffix.lower() not in {".md", ".txt", ".json", ".jsonl", ".log", ".csv", ".yaml", ".yml"}:
            continue
        n += 1
        try:
            scan_text(f.read_text(errors="replace"), str(f.relative_to(root)),
                      "text_file", source, out)
        except OSError:
            pass
    return n


def strings_of(b: bytes) -> str:
    parts = [m.group(0).decode("latin-1") for m in re.finditer(rb"[\x20-\x7e]{8,}", b)]
    parts += [m.group(0).decode("utf-16-le", "ignore")
              for m in re.finditer(rb"(?:[\x20-\x7e]\x00){8,}", b)]
    return "\n".join(parts)


def scan_attachments(att: pathlib.Path, source: str, out: list) -> dict:
    dest_root = UNPACK / source
    dest_root.mkdir(parents=True, exist_ok=True)
    stats = {"archives": 0, "files": 0, "text": 0, "binary": 0, "failed": []}
    if not att.exists():
        return stats
    for arc in sorted(att.rglob("*")):
        if not arc.is_file():
            continue
        stats["archives"] += 1
        dest = dest_root / arc.relative_to(att).with_suffix("")
        dest.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(["7z", "x", "-y", f"-o{dest}", str(arc)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode != 0:
            stats["failed"].append(str(arc.relative_to(att)))
        for child in list(dest.rglob("*")):
            if child.is_file() and child.suffix.lower() in {".zip", ".7z", ".gz"}:
                d2 = child.with_suffix(child.suffix + ".d")
                d2.mkdir(parents=True, exist_ok=True)
                subprocess.run(["7z", "x", "-y", f"-o{d2}", str(child)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for f in dest_root.rglob("*"):
        if not f.is_file() or f.stat().st_size > 120_000_000:
            continue
        stats["files"] += 1
        b = f.read_bytes()
        try:
            text = b.decode("utf-8")
            stats["text"] += 1
            scan_text(text, str(f.relative_to(dest_root)), "attachment_text", source, out)
        except UnicodeDecodeError:
            stats["binary"] += 1
            s = strings_of(b)
            if s:
                scan_text(s, str(f.relative_to(dest_root)), "attachment_strings", source, out)
    return stats


def main() -> int:
    out: list = []
    report = {}
    iov = HOME / "ctf/archive/qwb-iov-2026"
    qwb = HOME / "ctf/archive/qwb-2026"
    report["qwb-iov runs"] = scan_run_logs(WORK / "logs", "qwb-iov", out)
    report["qwb-iov text files"] = scan_text_files(iov / "retrospective", "qwb-iov", out)
    report["qwb-iov notes"] = scan_text_files(iov / "notes", "qwb-iov", out)
    report["qwb-iov evidence"] = scan_text_files(iov / "evidence", "qwb-iov", out)
    report["qwb-iov attachments"] = scan_attachments(iov / "attachments", "qwb-iov", out)
    report["qwb-2026 text files"] = scan_text_files(qwb, "qwb-2026", out)
    report["qwb-2026 attachments"] = scan_attachments(qwb / "attachments", "qwb-2026", out)

    (WORK / "findings2.json").write_text(json.dumps(out, ensure_ascii=False, indent=1),
                                         encoding="utf-8")
    print("== 扫描规模 ==")
    print(json.dumps(report, ensure_ascii=False, indent=1)[:2000])
    sig = Counter((x["source"], x["signal"]) for x in out)
    print("\n== 信号计数 ==")
    for k, v in sig.most_common():
        print(f"  {k}: {v}")
    hostile = [x for x in out if not x.get("self_ref")
               and x["signal"] in {"phrase", "ctrl_token"}]
    print(f"\n== 非自指的话术/控制 token 命中：{len(hostile)} ==")
    for x in hostile[:30]:
        print(f"  [{x['signal']}] {x['source']}/{x['kind']} {x['where']} :: {x['match']}")
        print(f"      …{x['context'][:150]}")
    uni = [x for x in out if x["signal"].startswith("unicode:") and x["signal"] not in
           {"unicode:greek", "unicode:cyrillic"}]
    print(f"\n== 不可见/控制类 Unicode 命中：{len(uni)} ==")
    for x in uni[:10]:
        print(f"  [{x['signal']}] {x['source']}/{x['kind']} {x['where']} count={x['count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
