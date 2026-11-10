#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为**每一道**题生成/刷新 `team/<题名>/EVIDENCE.md`（赛后复盘的证据卡）。

设计要点
--------
1. **自动段可重复生成**：脚本每次重跑都会重写 `AUTO` 段（平台事实 / 我方投入 /
   提交历史 / 证据清单 / 复现入口），数字全部现场统计，不抄旧文档。
2. **人工段永不覆盖**：`MANUAL:START ... MANUAL:END` 之间的文字属于人（或子代理），
   重跑时原样保留；首次生成时写入占位（并明确"待补"，不要装作已写）。
3. **只陈述可核查事实**：每个数字都能指向 `evidence/submit-log.jsonl`、
   `evidence/` 下的文件、`work/` 下的目录或 `notes/` 下的笔记；找不到就写"无"。
4. **不改 README**：README 是叙事，EVIDENCE 是账本；两者互相链接。

用法
----
    python3 scripts/evidence-index.py                 # 生成/刷新全部
    python3 scripts/evidence-index.py --check         # 只校验，不写文件（CI 用）
    python3 scripts/evidence-index.py --only KVlvgNuOwJXPAyAQ
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
from datetime import datetime
from pathlib import Path

WS = Path(__file__).resolve().parents[1]
TEAM = WS / "team"
EVIDENCE = WS / "evidence"
WORK = WS / "work"
NOTES = WS / "notes"
BOARD = WORK / "team-board.json"
SUBMIT_LOG = EVIDENCE / "submit-log.jsonl"
GATE_LOG = EVIDENCE / "gate-log.jsonl"

AUTO_START = "<!-- AUTO:START 由 scripts/evidence-index.py 生成，重跑会覆盖本段 -->"
AUTO_END = "<!-- AUTO:END -->"
MAN_START = "<!-- MANUAL:START 人工段：本脚本不会改动这两行之间的内容 -->"
MAN_END = "<!-- MANUAL:END -->"

# 文件名里出现这些词就认作该题的证据（题名别名 → 该题）
ALIASES = {
    "宇宙微波背景辐射": ["CMB", "cmb", "KVlvgNuOwJXPAyAQ"],
    "问卷调查": ["survey", "4yUAPAGmS0zRzdjp"],
    "vaultlink": ["vaultlink"],
    "fault_web_and_fault_hash": ["fault_web", "fault_hash", "gMVQqQRNfKaNkYdy"],
    "What The Fox!": ["What The Fox", "WhatTheFox"],
    "谍影重重7": ["谍影重重"],
}

STATUS_CN = {True: "✅ 已解出", False: "❌ 未解出"}


def human(n: int) -> str:
    if n >= 1 << 30:
        return f"{n / (1 << 30):.1f} GB"
    if n >= 1 << 20:
        return f"{n / (1 << 20):.1f} MB"
    if n >= 1 << 10:
        return f"{n / (1 << 10):.1f} KB"
    return f"{n} B"


def load_questions() -> list[dict]:
    if not BOARD.exists():
        sys.exit(f"[!] 缺 {BOARD}（先跑 scripts/qwb-board.py --write）")
    d = json.loads(BOARD.read_text(encoding="utf-8"))
    qs = []
    for q in d.get("solved_by_us", []):
        qs.append(dict(q, _status=True))
    for q in d.get("open", []):
        qs.append(dict(q, _status=False))
    qs.sort(key=lambda q: (not q["_status"], q.get("cls", ""), q.get("title", "")))
    return qs


def load_submits() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    if not SUBMIT_LOG.exists():
        return out
    for line in SUBMIT_LOG.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.setdefault(rec.get("id", "?"), []).append(rec)
    return out


def q_keys(q: dict) -> list[str]:
    keys = {q["id"], q["title"]}
    keys.update(ALIASES.get(q["title"], []))
    if " " in q["title"]:
        keys.add(q["title"].split()[0])
    # 小写副本：`Ironclad` 要能匹配 `work/ironclad/`
    keys |= {k.lower() for k in list(keys)}
    # 题号前 5 位：`gMVQqQRNfKaNkYdy` 要能匹配 `work/gMVQ_probe/`（题名与目录名无关的题）
    if len(q["id"]) >= 8:
        keys.add(q["id"][:5])
        keys.add(q["id"][:5].lower())
    return [k for k in keys if k and len(k) >= 3]


def norm(x: str) -> str:
    """只保留小写字母与数字：让 `crp-11741` 能匹配 `crp11741-samples.json`。"""
    return re.sub(r"[^a-z0-9]+", "", x.lower())


def collect(q: dict) -> dict:
    keys = q_keys(q)
    nkeys = [k for k in (norm(x) for x in keys) if len(k) >= 4]
    ev_files, work_dirs, note_files = [], [], []
    for p in sorted(EVIDENCE.rglob("*")):
        rel = p.relative_to(EVIDENCE).as_posix()
        nrel = norm(rel)
        if (any(k in rel for k in keys) or any(k in nrel for k in nkeys)) and p.is_file():
            ev_files.append((rel, p.stat().st_size))
    if WORK.exists():
        for p in sorted(WORK.iterdir()):
            if p.is_dir() and (any(k in p.name for k in keys) or any(k in norm(p.name) for k in nkeys)):
                size = sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
                cnt = sum(1 for f in p.rglob("*") if f.is_file())
                work_dirs.append((p.name, cnt, size))
    if NOTES.exists():
        for p in sorted(NOTES.iterdir()):
            if p.is_file() and (any(k in p.name for k in keys) or any(k in norm(p.name) for k in nkeys)):
                note_files.append(p.name)
    tdir = TEAM / q["title"]
    readme = tdir / "README.md"
    return {
        "ev_files": ev_files,
        "work_dirs": work_dirs,
        "note_files": note_files,
        "team_dir": tdir if tdir.is_dir() else None,
        "readme_lines": len(readme.read_text(encoding="utf-8", errors="replace").splitlines())
        if readme.exists()
        else 0,
    }


def submit_stats(recs: list[dict]) -> dict:
    ok = [r for r in recs if r.get("result") is True]
    wrong = [r for r in recs if r.get("kind") == "wrong" or (r.get("result") is False)]
    thrott = [r for r in recs if r.get("kind") == "throttle"]
    other = [r for r in recs if r not in ok and r not in wrong and r not in thrott]
    times = sorted(r.get("time", "") for r in recs if r.get("time"))
    return {
        "n": len(recs),
        "ok": ok,
        "wrong": wrong,
        "throttle": thrott,
        "other": other,
        "first": times[0] if times else "",
        "last": times[-1] if times else "",
        "distinct": len({r.get("flag", "") for r in recs if r.get("flag")}),
    }


def fmt_auto(q: dict, info: dict, st: dict, now: str) -> str:
    L: list[str] = []
    a = L.append
    a(AUTO_START)
    a("")
    a("## 1. 平台事实（来源 `work/team-board.json` @ 现场复拉）")
    a("")
    a("| 项 | 值 |")
    a("|---|---|")
    a(f"| 题号 | `{q['id']}` |")
    a(f"| 题名 | {q['title']} |")
    a(f"| 分类 | {q.get('cls', '?')} |")
    a(f"| 类型 | {q.get('kind', '?')}（动态 flag={q.get('dyn_flag', '?')}，answer_limit={q.get('answer_limit', '?')}）|")
    a(f"| 分值 | {q.get('score', '?')} |")
    a(f"| 平台解出 | **{q.get('solved_teams', '?')} 队** |")
    a(f"| 我方状态 | **{STATUS_CN[q['_status']]}**"
      + (f"（{q.get('solved_time')}）" if q.get("solved_time") else "")
      + " |")
    a("")
    a(f"> 解出数是实时变量；本表取自快照 `{board_time()}`。"
      "**README / 旧笔记里的解出数一律视为过期**，引用前先复拉 `scripts/qwb-board.py`。")
    a("")
    a("## 2. 我方投入（可核查，数字现场统计）")
    a("")
    a("| 项 | 数量 | 指向 |")
    a("|---|---|---|")
    a(f"| 提交记录 | **{st['n']}** 条（正确 {len(st['ok'])} / 判错 {len(st['wrong'])} / "
      f"限流 {len(st['throttle'])} / 其他 {len(st['other'])}，去重 flag {st['distinct']} 个）"
      f" | `evidence/submit-log.jsonl` |")
    if st["n"]:
        a(f"| 提交时间跨度 | `{st['first']}` → `{st['last']}` | 同上 |")
    a(f"| 证据文件 | **{len(info['ev_files'])}** 个 | `evidence/` |")
    a(f"| 草稿目录 | **{len(info['work_dirs'])}** 个 | `work/` |")
    a(f"| 笔记 | **{len(info['note_files'])}** 篇 | `notes/` |")
    a(f"| 队内文档 | {'`team/' + q['title'] + '/README.md`（' + str(info['readme_lines']) + ' 行）' if info['team_dir'] else '**无**'} | `team/` |")
    a("")
    if not (st["n"] or info["ev_files"] or info["work_dirs"] or info["note_files"]):
        a("> ⚠️ **零本地留痕**：这道题我方没有提交、没有证据文件、没有草稿目录、没有笔记。"
          "复盘时按「零投入」处理，不要事后补叙事。")
        a("")

    # 证据清单
    a("### 2.1 证据清单")
    a("")
    if info["ev_files"]:
        a("| 文件 | 大小 |")
        a("|---|---|")
        for rel, size in info["ev_files"]:
            a(f"| `evidence/{rel}` | {human(size)} |")
    else:
        a("_无证据文件。_")
    a("")
    if info["work_dirs"]:
        a("草稿目录（`work/`，可丢弃）：")
        a("")
        for name, cnt, size in info["work_dirs"]:
            a(f"- `work/{name}/` — {cnt} 个文件 / {human(size)}")
        a("")
    if info["note_files"]:
        a("笔记：" + "、".join(f"`notes/{n}`" for n in info["note_files"]))
        a("")

    # 提交历史
    a("## 3. 提交历史")
    a("")
    if not st["n"]:
        a("_无提交记录。_")
    else:
        rows = sorted(st["ok"] + st["wrong"] + st["throttle"] + st["other"],
                      key=lambda r: r.get("time", ""))
        show = rows if len(rows) <= 12 else rows[:6] + rows[-6:]
        a("| 时间 | flag | 结果 | code |")
        a("|---|---|---|---|")
        for r in show:
            flag = (r.get("flag") or "").replace("|", "\\|")
            res = "**正确**" if r.get("result") is True else ("限流未判" if r.get("kind") == "throttle" else "判错")
            a(f"| {r.get('time', '')} | `{flag}` | {res} | {r.get('resp_code', '')} |")
        if len(rows) > len(show):
            a(f"\n_（共 {len(rows)} 条，此处按时间头 6 / 尾 6 展示；全量见 `evidence/submit-log.jsonl`）_")
    a("")

    # 复现入口
    a("## 4. 复现入口")
    a("")
    rep = []
    if info["readme_lines"]:
        rep.append(f"- 叙事与判据：`team/{q['title']}/README.md`")
    md = [rel for rel, _ in info["ev_files"] if rel.endswith(".md")]
    for rel in md[:3]:
        rep.append(f"- 证据正文：`evidence/{rel}`")
    if len(md) > 3:
        rep.append(f"- 其余 {len(md) - 3} 篇 .md 见 §2.1（**文件名排序不代表权威性**，"
                   f"以 `team/{q['title']}/README.md` 的最新结论为准）")
    scripts = sorted(p.name for p in (WS / "scripts").glob("*") if q["id"] in p.name or q["title"] in p.name)
    for s in scripts:
        rep.append(f"- 脚本：`scripts/{s}`")
    if not rep:
        rep.append("- **无可复现入口**（本题没有留下脚本或证据）。")
    L.extend(rep)
    a("")
    a(f"_自动段生成于 {now}；平台数字取自 `work/team-board.json`（{board_time()}）。_")
    a("")
    a(AUTO_END)
    return "\n".join(L)


def board_time() -> str:
    try:
        return json.loads(BOARD.read_text(encoding="utf-8")).get("time", "?")
    except Exception:
        return "?"


def manual_default(q: dict, info: dict, st: dict) -> str:
    if st["ok"]:
        body = ("- **谁解出的**：待补（我方 agent / 队友）。\n"
                "- **关键一步**：待补。\n"
                "- **踩过的坑**：待补。")
    elif st["n"] or info["ev_files"] or info["work_dirs"] or info["note_files"]:
        body = ("- **做到哪一步**：待补。\n"
                "- **为什么没出**：待补（要能指向上面的证据文件）。\n"
                "- **若继续，下一步是什么**：待补。")
    else:
        kind_hint = ("- **为什么是零**：本题为**容器题**，容器由队长统一分配；本代理未取得实例、未提交、未留任何文件（推测为未派单，非事实）。"
                     if q.get("kind") == "容器" else
                     "- **为什么是零**：本题为**静态题**，本代理未派单、未提交、未留任何文件。")
        body = (f"- **零投入（有据）**：`submit-log.jsonl` 无本题记录；`evidence/`、`work/`、`notes/` 均无本题文件。\n"
                f"{kind_hint}\n"
                "- **负责人**：**未记录**（队内无派单台账；若属队长/队友，赛后请补填，不要猜）。")
    return f"{MAN_START}\n\n## 5. 复盘要点\n\n{body}\n\n{MAN_END}"


def render(q: dict, info: dict, st: dict, now: str, prev: str | None) -> str:
    title = q["title"]
    head = [
        f"# {title} · {q.get('cls', '?')} · `{q['id']}`",
        "",
        f"> {STATUS_CN[q['_status']]}｜平台 {q.get('solved_teams', '?')} 队解出｜"
        f"{q.get('kind', '?')} {q.get('score', '?')} 分｜"
        f"提交 {st['n']} 条 / 证据 {len(info['ev_files'])} 个",
        "",
        "**这是一张「证据卡」**：第 1–4 节由 `scripts/evidence-index.py` 现场统计生成（重跑会覆盖），",
        "第 5 节是人工复盘（永不覆盖）。叙事看同目录 `README.md`。",
        "",
        "---",
        "",
    ]
    auto = fmt_auto(q, info, st, now)
    if prev and MAN_START in prev and MAN_END in prev:
        manual = prev.split(MAN_START, 1)[1].rsplit(MAN_END, 1)[0]
        manual = f"{MAN_START}\n{manual}\n{MAN_END}"
    else:
        manual = manual_default(q, info, st)
    return "\n".join(head) + auto + "\n\n" + manual + "\n"


def master_index(qs: list[dict], rows: list[dict], now: str) -> str:
    d = json.loads(BOARD.read_text(encoding="utf-8"))
    t = d.get("team", {})
    L = [
        "# 证据总索引（41 题逐题证据卡）",
        "",
        f"> 生成于 **{now}**｜平台快照 **{d.get('time', '?')}**｜"
        f"队伍 **{t.get('name', '?')}**：{t.get('score', '?')} 分 / {t.get('solved', '?')} 题 / 排名 {t.get('rank', '?')}",
        "> 生成器：`scripts/evidence-index.py`（自动段可重跑，人工段 `MANUAL` 保护）",
        "",
        "## A. 已解出（12 题）",
        "",
        "| 题名 | 题号 | 分类 | 谁解出的 | 我方提交 | 证据 | 草稿 | 证据卡 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    solved = [r for r in rows if r["q"]["_status"]]
    opened = [r for r in rows if not r["q"]["_status"]]
    for r in solved:
        q, st, info = r["q"], r["st"], r["info"]
        who = "**我方提交**" if st["ok"] else "队友提交"
        sub = f"{st['n']} 条（正确 {len(st['ok'])} / 判错 {len(st['wrong'])} / 限流 {len(st['throttle'])}）"
        L.append(f"| {q['title']} | `{q['id']}` | {q.get('cls')} | {who} | {sub} | "
                 f"{len(info['ev_files'])} | {len(info['work_dirs'])} | "
                 f"[`EVIDENCE.md`]({q['title']}/EVIDENCE.md) |")
    L += ["", "## B. 未解出（29 题，按平台解出队数降序）", "",
          "| 题名 | 题号 | 分类 | 平台解出 | 提交 | 证据 | 留痕判定 | 证据卡 |",
          "|---|---|---|---|---|---|---|---|"]
    for r in sorted(opened, key=lambda x: -(x["q"].get("solved_teams") or 0)):
        q, st, info = r["q"], r["st"], r["info"]
        has = st["n"] or info["ev_files"] or info["work_dirs"]
        verdict = "有实质投入" if has else "**零留痕**"
        L.append(f"| {q['title']} | `{q['id']}` | {q.get('cls')} | {q.get('solved_teams')} | {st['n']} | "
                 f"{len(info['ev_files'])} | {verdict} | [`EVIDENCE.md`]({q['title']}/EVIDENCE.md) |")
    zero = [r["q"]["title"] for r in opened if not (r["st"]["n"] or r["info"]["ev_files"] or r["info"]["work_dirs"])]
    L += ["", "## C. 复盘口径", "",
          "1. **零留痕的题**（" + (f"{len(zero)} 题：{'、'.join(zero)}" if zero else "无") + "）"
          "不是「做不出来」，是「没派单/没留痕」。复盘时单列，别混进失败清单。",
          "2. **限流 ≠ 判错**：`result=null` 的候选必须单独成列，CMB 那次正确的段序就在 190 条限流未判里。",
          "3. **有提交无证据**的题（判错很多但没留 artifact）说明判据链断了，属流程缺陷。",
          "4. 已解出但**我方无提交记录**的题 = 队友提交（`frozen`/`cwp`/`ezphp`/`ezcms`/…），其证据在队友手里，本卡只记我方留痕。",
          "5. **台账里另有 12 条被限流却记成 `result=false`** 的提交（`vmshare`，10-31 09:09 段）：任何按 `result=false` 去重的扫描器都会把它们当「已判错」。",
          "6. 方法论总结与「下次开赛检查表」：`notes/methods/POST-MORTEM-QWB2026.md`（P1–P8，每条都有证据）。",
          ""]
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只校验不写")
    ap.add_argument("--only", default="", help="只处理某个题号")
    args = ap.parse_args()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    qs = load_questions()
    if args.only:
        qs = [q for q in qs if q["id"] == args.only or q["title"] == args.only]
        if not qs:
            sys.exit(f"[!] 没找到题目 {args.only}")
    subs = load_submits()
    rows = []
    missing = []
    for q in qs:
        info = collect(q)
        st = submit_stats(subs.get(q["id"], []))
        rows.append({"q": q, "info": info, "st": st})
        tdir = TEAM / q["title"]
        f = tdir / "EVIDENCE.md"
        text = render(q, info, st, now, f.read_text(encoding="utf-8", errors="replace") if f.exists() else None)
        if args.check:
            if not f.exists():
                missing.append(q["title"])
            else:
                old = f.read_text(encoding="utf-8", errors="replace")
                if AUTO_START not in old or MAN_START not in old:
                    missing.append(q["title"] + "（缺标记段）")
            continue
        tdir.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")

    if args.check:
        if missing:
            print(f"[!] {len(missing)} 张证据卡有问题：")
            for m in missing:
                print("   -", m)
            return 1
        print(f"[✓] {len(qs)} 张证据卡齐全且带 AUTO/MANUAL 标记")
        return 0

    idx = "team/EVIDENCE-INDEX.md"
    (WS / idx).write_text(master_index(load_questions(), rows, now), encoding="utf-8")
    zero = [r["q"]["title"] for r in rows if not r["q"]["_status"]
            and not (r["st"]["n"] or r["info"]["ev_files"] or r["info"]["work_dirs"])]
    print(f"[✓] 生成/刷新证据卡 {len(rows)} 张 → team/<题名>/EVIDENCE.md")
    print(f"[✓] 总索引 → {idx}")
    print(f"[i] 零留痕未解题：{len(zero)} 题" + ("：" + "、".join(zero) if zero else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
