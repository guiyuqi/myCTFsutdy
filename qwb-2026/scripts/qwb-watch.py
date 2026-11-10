#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""qwb-watch.py —— 等题目放出（后台任务用，禁止在回合内 sleep 轮询）

为什么单独一个脚本：AGENTS.md 硬规则 #1 禁止"回合内 sleep / 轮询外部状态"，
要等就交给后台 job（完成事件会叫回父代理）。本脚本就是那个后台 job 的本体。

用法：
  python3 scripts/qwb-watch.py                  # 每 60s 轮询，拿到非空题单即退出
  python3 scripts/qwb-watch.py --interval 30 --deadline '09:05'
  python3 scripts/qwb-watch.py --watch-notice    # 顺带盯公告（容器数量口径）

退出码：0 = 看到题目（或公告有新内容）；4 = 到 deadline 仍没看到。
输出：发现时的题单摘要，方便父代理直接派单。
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import time
from datetime import datetime
from pathlib import Path

WS = Path(__file__).resolve().parent.parent


def load_client():
    spec = importlib.util.spec_from_file_location("qwb", WS / "scripts" / "qwb.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


LIST_PAYLOAD = {"category_id": 0, "child_id": 0, "type_ids": "", "is_brief": 1,
                "page_index": 1, "page_size": ""}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=int, default=60, help="轮询间隔秒（默认 60）")
    ap.add_argument("--deadline", default="09:05", help="HH:MM 截止（默认 09:05）")
    ap.add_argument("--watch-notice", action="store_true", help="同时盯公告")
    ap.add_argument("--baseline", default=None,
                    help="已知题号基线：board=读 work/team-board.json；否则当文件（JSON 数组或每行一个 id）。"
                         "给了它就是「等第二批放题」模式：只有出现基线外的题号才算放出")
    args = ap.parse_args(argv)

    q = load_client()
    cf = q.conf()

    known: set[str] = set()
    if args.baseline:
        if args.baseline == "board":
            bd = json.loads((WS / "work" / "team-board.json").read_text(encoding="utf-8"))
            for key in ("solved_by_us", "open"):
                for row in bd.get(key) or []:
                    if row.get("id"):
                        known.add(str(row["id"]))
        else:
            raw = Path(args.baseline).read_text(encoding="utf-8").strip()
            try:
                data = json.loads(raw)
                known = {str(x) for x in (data if isinstance(data, list) else data.get("ids", []))}
            except json.JSONDecodeError:
                known = {ln.strip() for ln in raw.splitlines() if ln.strip()}
        print(f"[watch] 基线 {len(known)} 题：{','.join(sorted(known))}", flush=True)
    now = datetime.now()
    hh, mm = (int(x) for x in args.deadline.split(":"))
    end = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if end < now:                      # 跨天保护
        end = end.replace(day=now.day + 1)

    print(f"[watch] 开始 {datetime.now():%H:%M:%S}，间隔 {args.interval}s，"
          f"截止 {end:%H:%M}", flush=True)
    last_note = None
    n = 0
    while datetime.now() < end:
        n += 1
        try:
            d = q.unwrap(q.http("/match/question/lists", LIST_PAYLOAD, cf=cf),
                         "题目列表", allow=(116,))
            rows = d if isinstance(d, list) else (
                (d.get("lists") if isinstance(d, dict) else []) or [])
        except SystemExit as e:
            print(f"[{n}] {datetime.now():%H:%M:%S} 拉取失败（继续）：{str(e).splitlines()[0]}",
                  flush=True)
            rows = []

        fresh = [r for r in rows if str(r.get("id")) not in known] if known else rows

        if rows and fresh:
            print(f"\n[✓] {datetime.now():%H:%M:%S} 题目放出！共 {len(rows)} 题，"
                  f"其中基线外新增 {len(fresh)} 题", flush=True)
            for r in (fresh if known else rows):
                print(f"    id={r.get('id'):<8} [{r.get('class_name') or ''}] "
                      f"{r.get('title')}  score={r.get('score')} "
                      f"solved={r.get('solved')} type_id={r.get('type_id')}", flush=True)
            print("\n--- 原始 JSON（首题，供校准字段）---", flush=True)
            print(json.dumps(fresh[0] if known else rows[0], ensure_ascii=False, indent=1)[:1500],
                  flush=True)
            return 0

        if rows and known and n % 10 == 1:
            print(f"[{n}] {datetime.now():%H:%M:%S} 仍是基线内 {len(rows)} 题，无新增", flush=True)

        if args.watch_notice:
            try:
                nt = q.http("/match/notice/lists",
                            {"type": 1, "page_index": 1, "page_size": 20}, cf=cf)
                body = json.dumps(nt, ensure_ascii=False)
                if nt.get("code") == 0 and body != last_note:
                    last_note = body
                    print(f"\n[公告] {datetime.now():%H:%M:%S} 有新公告：", flush=True)
                    print(body[:1200], flush=True)
            except SystemExit:
                pass

        if not rows and n % 5 == 1:
            print(f"[{n}] {datetime.now():%H:%M:%S} 题单为空（code=116 未放出）", flush=True)
        time.sleep(args.interval)

    print(f"[watch] 到 {end:%H:%M} 仍未见题目，退出", flush=True)
    return 4


if __name__ == "__main__":
    sys.exit(main())
