#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""qwb-board.py —— 团队态势板 + 「队友已解出就停手」的判据

为什么有它（2026-10-31 队长要求）：
  团队赛里最贵的浪费是「两个人同时打同一道题」。
  父代理必须能回答两个问题，并且是**可验证**而不是靠猜：
    1. 哪道题已经被**本队其他人**解出了？（⇒ 立刻停掉正在打这题的代理）
    2. 哪道题卡住了、卡在哪？（⇒ 汇总给团队）

判据来源（全部来自平台，已核对字段名）：
  - `/match/question/lists` 每题带 `red_solved.is_solved` = **本队是否解出**
                            `solved` / `solved_number` = 平台解出队数（判断"多少人做出来了"）
  - `/match/flag/submit_lists` `{question_id, page_index, page_size}` 提交记录
                            字段 `user_name` / `create_time` ⇒ **谁解的、什么时候**
  - `/match/team/users` 每个队员 `total_number`（解出数）`total_score`
  - `/match/team/info` 队伍总分 / 排名

用法：
  python3 scripts/qwb-board.py                  # 刷新并打印态势板
  python3 scripts/qwb-board.py --write          # 刷新 + 写 work/TEAM-BOARD.md / team-board.json
  python3 scripts/qwb-board.py --check 20261    # 判据：本队已解出 → 退出码 10（该停手）
  python3 scripts/qwb-board.py --stale 600      # 列出"我派了代理但队友已解出"的题（供父代理停手）

退出码：0 正常/可继续；10 本队已解出（停手）；4 数据不足（未开赛/拿不到题单）。

★ 纪律：本脚本**只读平台**，不做任何提交。/ 只读轮询由父代理按需调用，
  不要在回合内 sleep 轮询（用 `--check` 单次判定）。
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime
from pathlib import Path

WS = Path(__file__).resolve().parent.parent
WORK = WS / "work"
BOARD_MD = WORK / "TEAM-BOARD.md"
BOARD_JSON = WORK / "team-board.json"
AGENT_MAP = WORK / "agent-map.json"        # 父代理维护：题号 → 正在跑的 agent id


def load_client():
    spec = importlib.util.spec_from_file_location("qwb", WS / "scripts" / "qwb.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def truthy(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    return str(v).lower() in {"1", "true", "yes", "y"}


def fetch_questions(q, cf) -> list[dict]:
    """全部题目（is_brief=1 拿精简字段足够判状态）。"""
    js = q.http("/match/question/lists",
                {"category_id": 0, "child_id": 0, "type_ids": "",
                 "is_brief": 0, "page_index": 1, "page_size": ""}, cf=cf)
    if js.get("code") == 116:
        return []
    d = q.unwrap(js, "题目列表", allow=(116,))
    rows = d if isinstance(d, list) else ((d or {}).get("lists") or [])
    return rows


def fetch_team(q, cf) -> tuple[dict, list[dict]]:
    info = q.http("/match/team/info", {}, cf=cf)
    users = q.http("/match/team/users", {}, cf=cf)
    ti = (info.get("data") or {}) if info.get("code") == 0 else {}
    ul = ((users.get("data") or {}).get("lists") or []) if users.get("code") == 0 else []
    return ti, ul


def fetch_submits(q, cf, qid) -> list[dict]:
    js = q.http("/match/flag/submit_lists",
                {"question_id": str(qid), "page_index": 1, "page_size": 20}, cf=cf)
    if js.get("code") != 0:
        return []
    d = js.get("data")
    rows = d if isinstance(d, list) else ((d or {}).get("lists") or [])
    return rows if isinstance(rows, list) else []


def normalize(row: dict) -> dict:
    """把题目行压成态势板需要的形状（字段名做了容错）。"""
    rs = row.get("red_solved") or {}
    solved_by_us = truthy(rs.get("is_solved")) if isinstance(rs, dict) else False
    CATS = {4796: "Misc", 4797: "Crypto", 4798: "Reverse", 4799: "PWN", 4800: "Web",
            4801: "安全知识"}
    cid = row.get("category_id")
    return {
        "id": str(row.get("id")),
        "title": row.get("title") or "",
        "cls": row.get("class_name") or row.get("category_name") or CATS.get(cid, ""),
        "kind": "容器" if row.get("type_id") == 2 else "静态",
        "answer_limit": row.get("answer_limit"),
        "dyn_flag": row.get("is_dynamic_flag"),
        "score": row.get("score"),
        # ★ red_solved.solved_number = **平台解出队数**（不是本队计数，2026-10-31 核实）
        # 注意 0 是有效值（0 队解出），不能用 `or` 兜底
        "solved_teams": (rs.get("solved_number") if isinstance(rs, dict)
                         else row.get("solved", row.get("solved_number"))),
        "solved_by_us": solved_by_us,
        "solved_time": rs.get("solved_time") if isinstance(rs, dict) else None,
        "ours": row.get("ours_first") or rs.get("solved_number") if isinstance(rs, dict) else None,
        "type_id": row.get("type_id"),
        # 需要容器 / 附件的线索（字段名容错）
        "need_docker": truthy(row.get("is_docker") or row.get("docker_status") or 0),
    }


def load_agent_map() -> dict:
    if AGENT_MAP.exists():
        try:
            return json.loads(AGENT_MAP.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return {}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="团队态势板 / 队友已解出判据")
    ap.add_argument("--write", action="store_true", help="写 work/TEAM-BOARD.md + team-board.json")
    ap.add_argument("--check", default="", metavar="题号", help="判据：本队已解出 → 退出码 10")
    ap.add_argument("--stale", type=int, default=0, metavar="秒",
                    help="列出「已派代理但队友已解出」的题（配合 agent-map.json）")
    ap.add_argument("--submits", action="store_true", help="对已解出的题拉提交记录（谁解的）")
    args = ap.parse_args(argv)

    q = load_client()
    cf = q.conf()
    rows = fetch_questions(q, cf)
    if not rows:
        print("[!] 拿不到题单（未开赛 / 无题目 / payload 变了）—— 用 qwb.py list --raw 核对")
        return 4

    qs = [normalize(r) for r in rows]
    ti, users = fetch_team(q, cf)
    amap = load_agent_map()

    solved = [x for x in qs if x["solved_by_us"]]
    open_ = [x for x in qs if not x["solved_by_us"]]

    if args.check:
        tgt = next((x for x in qs if x["id"] == str(args.check)), None)
        if tgt is None:
            print(f"[?] 题号 {args.check} 不在题单里")
            return 4
        if tgt["solved_by_us"]:
            print(f"[10] {tgt['id']} {tgt['title']} —— 本队已解出，**该停手**")
            return 10
        print(f"[0] {tgt['id']} {tgt['title']} —— 本队尚未解出，可继续"
              f"（平台已解出 {tgt['solved_teams']} 队）")
        return 0

    # ---------- 打印态势 ----------
    print(f"== 团队态势板  {datetime.now():%m-%d %H:%M:%S} ==")
    print(f"队伍 {ti.get('team_name')}  总分 {ti.get('total_score')}  "
          f"解出 {ti.get('total_number')} 题  排名 {ti.get('team_rank')}")
    print(f"题目 {len(qs)} 道：本队已解出 {len(solved)}，未解 {len(open_)}")
    print()
    if solved:
        print("── ★ 本队已解出（其他人做了→别再派人）──")
        for x in solved:
            who = ""
            if args.submits:
                subs = fetch_submits(q, cf, x["id"])
                if subs:
                    s0 = subs[0]
                    who = f"  提交者={s0.get('user_name')} @ {s0.get('create_time')}"
            print(f"  {x['id']:<8} [{x['cls']}] {x['title']}  平台{x['solved_teams']}队解出{who}")
        print()
    print("── 未解出（可派单）──")
    for x in sorted(open_, key=lambda r: (r["solved_teams"] or 0)):
        flag = ""
        if x["id"] in amap:
            # 注意：agent-map 只记「派过谁」，不代表此刻在跑。
            # 子代理做完一个回合就回到 ready（storage 里可续），进程随之消失 ⇒ 不 send_message 就是死的。
            # 2026-10-31 踩过：板子打了 5 行「正在跑」，实际 32 个代理全是 ready、只有 1 个父会话作业活着。
            flag = f"  ← 已派 {amap[x['id']]}（**不=在跑**，需 send_message / 父会话后台作业续命）"
        print(f"  {x['id']:<8} [{x['cls']}] {x['title']:<22} "
              f"平台{x['solved_teams']}队解出  score={x['score']}{flag}")
    print()

    # ---------- 队员贡献 ----------
    if users:
        print("── 队员（解出数）──")
        for u in users:
            mark = "✅" if (u.get("total_number") or 0) > 0 else "  "
            print(f"  {mark} {u.get('user_name'):<8} 解出={u.get('total_number')} "
                  f"first={u.get('total_first')} score={u.get('total_score')} "
                  f"登录={'是' if u.get('is_login') == 1 else '否'}")
        print()

    # ---------- 停手提醒 ----------
    if args.stale:
        stale = [x for x in solved if x["id"] in amap]
        if stale:
            print("★★ 需要立刻停手（我派人打的题，本队已经解出）:")
            for x in stale:
                print(f"   {x['id']} {x['title']} → interrupt_agent {amap[x['id']]}")
        else:
            print("[i] 没有「我派了代理但队友已解出」的题")

    # ---------- 落盘 ----------
    if args.write:
        WORK.mkdir(parents=True, exist_ok=True)
        BOARD_JSON.write_text(json.dumps(
            {"time": datetime.now().isoformat(timespec="seconds"),
             "team": {"name": ti.get("team_name"), "score": ti.get("total_score"),
                      "solved": ti.get("total_number"), "rank": ti.get("team_rank")},
             "solved_by_us": solved, "open": open_, "agents": amap},
            ensure_ascii=False, indent=1), encoding="utf-8")
        md = [f"# 团队态势板 · {datetime.now():%Y-%m-%d %H:%M}", "",
              f"- 队伍：**{ti.get('team_name')}**　总分 {ti.get('total_score')}　"
              f"解出 {ti.get('total_number')} 题　排名 {ti.get('team_rank')}",
              f"- 题单：{len(qs)} 道；本队已解出 **{len(solved)}**；未解 {len(open_)}", "",
              "## ★ 本队已解出（别再派人 / 立刻停手）", ""]
        if solved:
            md += ["| 题号 | 分类 | 题名 | 平台解出队数 | 我方代理 |", "|---|---|---|---|---|"]
            for x in solved:
                md.append(f"| {x['id']} | {x['cls']} | {x['title']} | "
                          f"{x['solved_teams']} | {amap.get(x['id'], '—')} |")
        else:
            md.append("（还没有）")
        md += ["", "## 未解出（可派）", "",
               "| 题号 | 分类 | 题名 | 平台解出队数 | 分值 | 我方代理 |",
               "|---|---|---|---|---|---|"]
        for x in sorted(open_, key=lambda r: (r["solved_teams"] or 0)):
            md.append(f"| {x['id']} | {x['cls']} | {x['title']} | {x['solved_teams']} | "
                      f"{x['score']} | {amap.get(x['id'], '—')} |")
        stuck = WORK / "STUCK.md"
        if stuck.exists():
            md += ["", "## 卡点（做题代理回报，父代理维护 work/STUCK.md）", "",
                   stuck.read_text(encoding="utf-8").strip()]
        md += ["", "## 队员", "", "| 队员 | 解出 | 一血 | 分数 | 登录 |", "|---|---|---|---|---|"]
        for u in users:
            md.append(f"| {u.get('user_name')} | {u.get('total_number')} | "
                      f"{u.get('total_first')} | {u.get('total_score')} | "
                      f"{'是' if u.get('is_login') == 1 else '否'} |")
        BOARD_MD.write_text("\n".join(md) + "\n", encoding="utf-8")
        print(f"[✓] 已写 {BOARD_MD.relative_to(WS)} / {BOARD_JSON.relative_to(WS)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
