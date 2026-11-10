#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对比题目清单基线，找出 12:00 第二批新增的题。
用法: python3 scripts/batch-diff.py [--save]
  --save  把当前列表存为基线 work/baseline-<HHMM>.json
"""
import importlib.util, json, sys
from pathlib import Path
WS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("y", str(WS/"scripts/ycb.py"))
y = importlib.util.module_from_spec(spec); spec.loader.exec_module(y)
conf = y.cfg(type("A", (), {"base": None, "token": None, "match": None, "stage": None})())
js = y.http("GET", f"{y.API}/player/ctf/exercise-list", conf=conf,
            params={"matchId": conf["match"], "stageId": "3241"})
rows = y.norm_challenges(y.unwrap(js, "list"))
cur = {r["id"]: r for r in rows}
base_file = sorted(WS.glob("work/baseline-*.json"))[-1] if list(WS.glob("work/baseline-*.json")) else None
base = {}
if base_file and "--save" not in sys.argv:
    base = {str(x["id"]): x for x in json.loads(base_file.read_text())}
new = [r for i, r in cur.items() if i not in base]
print(f"当前 {len(cur)} 题；基线 {len(base) if base else '(无)'} 题；新增 {len(new)} 题")
for r in new:
    print(f"NEW  {r['id']}\t{r['category']}\t{r['name']}")
if "--save" in sys.argv:
    p = WS/"work"/f"baseline-{__import__('datetime').datetime.now():%H%M}.json"
    p.write_text(json.dumps([{"id": r["id"], "name": r["name"], "cat": r["category"]} for r in rows],
                            ensure_ascii=False, indent=1))
    print("已存基线:", p)
