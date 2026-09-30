#!/usr/bin/env python3
"""Aggregate every confirmed flag into notes/FLAGS.md (idempotent, re-runnable)."""
import json, os, datetime

ROOT = os.path.expanduser("~/ctf-2026")
idx = {r["id"]: r for r in json.load(open(f"{ROOT}/work/platform/index.json"))}

best = {}
for line in open(f"{ROOT}/evidence/submit-log.jsonl"):
    try:
        r = json.loads(line)
    except Exception:
        continue
    res = r.get("result") or {}
    if not isinstance(res, dict):
        continue
    cid = int(r["challenge_id"])
    if res.get("code") == 200 and (res.get("data") or {}).get("result"):
        best[cid] = {"flag": r["flag"], "status": "ACCEPTED", "at": r.get("time")}
    elif cid not in best:
        best[cid] = {"flag": r["flag"], "status": f'rejected: {res.get("msg")}', "at": r.get("time")}

acc = {k: v for k, v in best.items() if v["status"] == "ACCEPTED"}
lines = [
    "# 0xGame2026 · Flag 汇总",
    "",
    f"- 生成时间: {datetime.datetime.now().isoformat(timespec='seconds')}",
    f"- **已确认通过: {len(acc)} / {len(idx)} 题**",
    "",
    "## ✅ 已提交并被平台接受",
    "",
    "| id | 题名 | 分类 | 分值 | flag |",
    "|---:|---|---|---:|---|",
]
for cid in sorted(acc):
    m = idx[cid]
    lines.append(f"| {cid} | {m['name']} | {','.join(m['tags'])} | {m['score']} | `{acc[cid]['flag']}` |")

rej = {k: v for k, v in best.items() if v["status"] != "ACCEPTED"}
if rej:
    lines += ["", "## ⚠️ 被拒绝的提交（待重解）", "", "| id | 题名 | 提交内容 | 结果 |", "|---:|---|---|---|"]
    for cid in sorted(rej):
        lines.append(f"| {cid} | {idx[cid]['name']} | `{rej[cid]['flag']}` | {rej[cid]['status']} |")

pend = sorted(set(idx) - set(acc))
lines += ["", f"## ⏳ 未解出（{len(pend)}）", "", "| id | 题名 | 分类 | 分值 | 解出人数 | 容器 |",
          "|---:|---|---|---:|---:|---|"]
for cid in pend:
    m = idx[cid]
    lines.append(f"| {cid} | {m['name']} | {','.join(m['tags'])} | {m['score']} | {m['solves']} | "
                 f"{'是' if m['docker'] else '否'} |")

os.makedirs(f"{ROOT}/notes", exist_ok=True)
open(f"{ROOT}/notes/FLAGS.md", "w").write("\n".join(lines) + "\n")
print("\n".join(lines[:14]))
print(f"...\n未解出 {len(pend)}: {pend}")
