#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""12:00 第二批分诊：列出新增题目 + 分值/解出数/是否需要容器/附件名，并给出派单建议。
用法: python3 scripts/batch-triage.py [基线文件]
"""
import importlib.util, json, re, sys, concurrent.futures as cf
from pathlib import Path
WS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("y", str(WS/"scripts/ycb.py"))
y = importlib.util.module_from_spec(spec); spec.loader.exec_module(y)
conf = y.cfg(type("A", (), {"base": None, "token": None, "match": None, "stage": None})())

js = y.http("GET", f"{y.API}/player/ctf/exercise-list", conf=conf,
            params={"matchId": conf["match"], "stageId": "3241"})
rows = y.norm_challenges(y.unwrap(js, "list"))
cur = {r["id"]: r for r in rows}

base = {}
if len(sys.argv) > 1:
    base = {str(x["id"]): x for x in json.loads(Path(sys.argv[1]).read_text())}
else:
    cands = sorted(WS.glob("work/baseline-*.json"))
    if cands:
        base = {str(x["id"]): x for x in json.loads(cands[-1].read_text())}

new = [r for i, r in cur.items() if i not in base]

def detail(r):
    try:
        js = y.http("GET", f"{y.API}/player/ctf/exercise", conf=conf,
                    params={"matchId": conf["match"], "exerciseId": r["id"], "stageId": "3241"})
        d = y.parse_maybe_json(y.unwrap(js, "detail")) or {}
        sc = str(d.get("score") or "")
        m = re.search(r"已答出(\d+)次.*?当前分值([\d.]+)", sc)
        att = d.get("attachment") or {}
        eps = d.get("endpoints") or []
        return {
            "id": r["id"], "name": d.get("name") or r["name"],
            "cat": r["category"] or d.get("corpusClassify") or "",
            "diff": d.get("difficulty") or "", "solved": int(m.group(1)) if m else -1,
            "score": m.group(2) if m else "?", "attach": att.get("name") or "",
            "need_init": d.get("isNeedInit"), "ep_type": d.get("endpointType"),
            "has_ep": bool(eps),
        }
    except SystemExit as e:
        return {"id": r["id"], "name": r["name"], "cat": r["category"], "err": str(e)[:80]}

with cf.ThreadPoolExecutor(max_workers=4) as ex:
    det = list(ex.map(detail, new)) if new else []

print(f"# 第二批分诊：当前 {len(cur)} 题，基线 {len(base)} 题，**新增 {len(det)} 题**\n")
# 规则随表输出：让每张 triage 表自带判据，不依赖读者记得 RULES.md
print("> **排序不是按分值** —— 本场数据反着说：500 分的题解出数 0，200 分的题解出 7 道。")
print("> **优先级 = 类型清晰度 ÷ 预计验证轮次**（分值只在同清晰度内做 tiebreak）")
print("> 类型清晰度 := 我能不能在 5 分钟内写出第一条能证伪它的实验\n")
print("> **三条硬规则**：")
print("> 1. **每题 30 秒粗分**（`type / needs_env / 附件 / 第一条证伪实验`），不要精分；")
print("> 2. **立刻为 4 道（= 实测槽位数）申请环境**，不等精分；")
print("> 3. **连续 2 轮（≤20min/轮）无新 artifact ⇒ 强制 park**，写 `missing / next_action / revisit_at`。\n")
if det:
    print("| id | 名称 | 分类 | 难度 | 解出 | 当前分 | 附件 | 容器 | 建议 |")
    print("|---|---|---|---|---|---|---|---|---|")
    for d in sorted(det, key=lambda x: (x.get("solved", 99), x["id"])):
        if "err" in d:
            print(f"| {d['id']} | {d['name']} | {d['cat']} | ? | ? | ? | ? | ? | 详情失败: {d['err']} |")
            continue
        need = "要" if d["has_ep"] or d["need_init"] else "不要"
        # 建议：静态优先；容器题看槽位
        sugg = "立即派（静态）" if need == "不要" else "排队（占槽）"
        print(f"| {d['id']} | {d['name']} | {d['cat']} | {d['diff']} | {d['solved']} | "
              f"{d['score']} | {d['attach'] or '无'} | {need} | {sugg} |")
else:
    print("（还没有新题；12:00 后再跑一次）")
