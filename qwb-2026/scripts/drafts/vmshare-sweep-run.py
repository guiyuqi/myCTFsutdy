#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vmshare (brz2pZwJzt8gV8r6) 256-前像候选的顺序扫描器。

每个候选必须先过 verify-flag.py check 门禁，再走 qwb.py submit --via red。
限流（"太过频繁"）不算 flag 错、不占次数：指数退避后重试同一候选。
成功 / 额度用尽 / 限流久不缓解 → 立即停并写结果文件。

用法（后台跑，不要在回合里 sleep）：
  nohup python3 work/vmshare-sweep-run.py --budget 48 > /dev/null 2>&1 &
"""
import argparse
import json
import os
import random
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

WS = Path("~/ctf-2026")
CID = "brz2pZwJzt8gV8r6"
EVIDENCE = "evidence/brz2pZwJzt8gV8r6-vmshare/verify.txt"
PROGRESS = WS / "evidence" / "vmshare-sweep-log.jsonl"
RESULT = WS / "evidence" / "vmshare-sweep-result.json"

# 已经真被判为"答案错误"的串（不重复提交，不浪费次数）
DONE_WRONG = {
    "flag{0174812_01AF718}",
    "flag{0174812_11AF718}",
}


def order_candidates():
    """排序理由（先验基本是平的，只有两类弱先验）：
    1) 两半低 24 bit 都以 '1' 开头（0x174812 / 0x1AF718），同时出现的概率 1/256
       —— 若作者是「1 + 6 位随机」补足 7 位，真值就是 h1=h2=1。先试对称。
    2) 首位相同的对称串（作者可能成对生成）。
    3) 其余按 (h1, h2) 字典序。
    """
    hexd = "0123456789ABCDEF"
    out = []

    def add(h1, h2):
        f = f"flag{{{h1}174812_{h2}1AF718}}"
        if f not in DONE_WRONG and f not in out:
            out.append(f)

    # tier 1: 前缀 '1' 假说
    add("1", "1")
    # tier 2: 对称
    for h in hexd:
        add(h, h)
    # tier 3: 至少一半是 '1'
    for h in hexd:
        add("1", h)
        add(h, "1")
    # tier 4: 其余
    for h1 in hexd:
        for h2 in hexd:
            add(h1, h2)
    return out


def run(cmd, timeout=180):
    return subprocess.run(cmd, cwd=str(WS), capture_output=True, text=True, timeout=timeout)


def append(rec):
    PROGRESS.parent.mkdir(parents=True, exist_ok=True)
    with PROGRESS.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=48, help="最多消耗多少次「真判定」")
    ap.add_argument("--base-delay", type=float, default=15.0, help="两次提交间隔秒数")
    ap.add_argument("--start-index", type=int, default=0)
    ap.add_argument("--candidates", help="显式候选文件（每行一个 flag）；缺省用内置先验排序")
    args = ap.parse_args()

    if args.candidates:
        cands = [ln.strip() for ln in Path(args.candidates).read_text().splitlines() if ln.strip()]
    else:
        cands = order_candidates()
    todo = cands[args.start_index:]
    print(f"[i] 候选 {len(cands)} 个，本轮从 #{args.start_index} 开始，预算 {args.budget} 次真判定")

    judged = 0          # 真被平台判定（成功/答案错误）
    throttles = 0
    base = args.base_delay      # 自适应基距：一旦限流就抬升且不回落
    streak = 0                  # 连续限流计数
    idx = args.start_index
    started = time.time()

    env = dict(os.environ, CTF_AGENT="submitter")

    while idx < len(cands) and judged < args.budget:
        flag = cands[idx]
        # ---- 1) 门禁：出票（必须先生成，票一次性 300s）
        g = run([sys.executable, "scripts/verify-flag.py", "check", CID, flag,
                 "--evidence", EVIDENCE, "--agent", "submitter", "--parent-override"])
        if g.returncode != 0:
            rec = {"t": datetime.now().astimezone().isoformat(timespec="seconds"),
                   "flag": flag, "event": "GATE_FAIL", "rc": g.returncode,
                   "out": (g.stdout + g.stderr)[-800:]}
            append(rec)
            print(f"[!] 门禁失败 {flag}: {(g.stdout + g.stderr)[-300:]}")
            break
        # ---- 2) 提交
        s = run([sys.executable, "scripts/qwb.py", "submit", CID, flag,
                 "--via", "red", "--force"], timeout=240)
        out = s.stdout + s.stderr
        now = datetime.now().astimezone().isoformat(timespec="seconds")
        if s.returncode == 0:
            rec = {"t": now, "flag": flag, "event": "SOLVED", "rc": 0, "out": out[-1500:]}
            append(rec)
            RESULT.write_text(json.dumps({"result": "SOLVED", "flag": flag,
                                          "judged": judged + 1, "throttles": throttles,
                                          "elapsed_s": round(time.time() - started, 1),
                                          "log": str(PROGRESS)}, ensure_ascii=False, indent=1))
            print(f"[✓] SOLVED {flag}")
            return 0
        if s.returncode == 3 or "频繁" in out:
            throttles += 1
            streak += 1
            # 父代理策略：8s 起，一犯退 15s，再犯退 30s，之后翻倍封顶 60s；基距只升不降
            if streak == 1:
                base = max(base, 15.0)
            elif streak == 2:
                base = max(base, 30.0)
            else:
                base = min(base * 2, 60.0)
            retry = min(30.0 * streak, 150.0)
            append({"t": now, "flag": flag, "event": "THROTTLE", "retry_wait": retry,
                    "base_next": base, "streak": streak, "throttles": throttles})
            print(f"[~] 限流 #{throttles}（连续 {streak}），退避 {retry:.0f}s 重试同一候选，基距→{base:.0f}s {flag}")
            if throttles >= 40 and time.time() - started > 600:
                append({"t": now, "event": "ABORT", "why": "限流持续不缓解"})
                RESULT.write_text(json.dumps({"result": "FAILED", "why": "throttle_persist",
                                              "judged": judged, "throttles": throttles},
                                             ensure_ascii=False, indent=1))
                return 4
            time.sleep(retry)
            continue                     # 同一候选重试，不前进
        if s.returncode == 2 or "答案错误" in out:
            judged += 1
            streak = 0                   # 恢复判定节奏，但基距不回落（防反复限流）
            append({"t": now, "flag": flag, "event": "WRONG", "judged": judged,
                    "throttles": throttles})
            print(f"[x] 答案错误 ({judged}/{args.budget}) {flag}")
            idx += 1
            if judged < args.budget and idx < len(cands):
                time.sleep(base + random.uniform(0, 3))
            continue
        # ---- 3) 其它：规则变了 / 额度用尽 / 鉴权问题 —— 立刻停，交父代理
        rec = {"t": now, "flag": flag, "event": "ANOMALY", "rc": s.returncode, "out": out[-1500:]}
        append(rec)
        RESULT.write_text(json.dumps({"result": "FAILED", "why": "anomaly", "rc": s.returncode,
                                      "out": out[-800:], "judged": judged,
                                      "throttles": throttles}, ensure_ascii=False, indent=1))
        print(f"[!] 异常回包（规则可能变了），停止：{out[-400:]}")
        return 5

    RESULT.write_text(json.dumps({"result": "FAILED", "why": "budget_or_list_exhausted",
                                  "judged": judged, "throttles": throttles,
                                  "next_index": idx,
                                  "elapsed_s": round(time.time() - started, 1),
                                  "log": str(PROGRESS)}, ensure_ascii=False, indent=1))
    print(f"[=] 结束：judged={judged} throttles={throttles} next_index={idx}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
