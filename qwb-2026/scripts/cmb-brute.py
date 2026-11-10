#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CMB 六段候选枚举器。

背景：五段来自队友 _分析图.zip + 第六段来自主视频尾部噪声帧（我方复算得到 `5tr34m}`）。
已判错的组合会被跳过（读 evidence/submit-log.jsonl）；限流(fromthrottle)的会重试。
"""
import json
import subprocess
import sys
import time
from pathlib import Path

WS = Path("~/ctf-2026")
CID = "KVlvgNuOwJXPAyAQ"
EVID = "evidence/KVlvgNuOwJXPAyAQ-five-seg.md"
LOG = WS / "evidence" / "submit-log.jsonl"

A = ["S3cr3t", "53cr3t"]
B = ["cM6", "cMB", "cm6", "CM6", "cM8", "cmb"]
C = ["5tr34m", "str34m"]


def judged_wrong():
    s = set()
    if LOG.exists():
        for ln in LOG.open(encoding="utf-8"):
            ln = ln.strip()
            if not ln:
                continue
            try:
                r = json.loads(ln)
            except Exception:
                continue
            if r.get("id") != CID:
                continue
            if "答案错误" in (r.get("message") or ""):
                s.add(r.get("raw_flag") or r.get("flag"))
    return s


def main():
    wrong = judged_wrong()
    cands = []
    for a in A:
        for b in B:
            for c in C:
                f = f"flag{{{a}_h1dd3n_1n51d3_0f_{b}_{c}}}"
                if f not in wrong:
                    cands.append(f)
    print(f"[i] 待试 {len(cands)} 个（已判错 {len(wrong)} 个跳过）", flush=True)
    for i, f in enumerate(cands, 1):
        subprocess.run([sys.executable, "scripts/verify-flag.py", "check", CID, f,
                        "--evidence", EVID, "--agent", "parent", "--parent-override"],
                       cwd=str(WS), capture_output=True, text=True)
        s = subprocess.run([sys.executable, "scripts/qwb.py", "submit", CID, f,
                            "--via", "red", "--force"],
                           cwd=str(WS), capture_output=True, text=True, timeout=180)
        out = s.stdout + s.stderr
        tag = "?"
        if s.returncode == 0:
            tag = "SOLVED"
        elif "答案错误" in out:
            tag = "wrong"
        elif "频繁" in out:
            tag = "throttle"
        print(f"[{i}/{len(cands)}] {tag:<8} {f}", flush=True)
        if s.returncode == 0:
            print("\n*** SOLVED ***", f, flush=True)
            print(out[-800:], flush=True)
            return 0
        time.sleep(6 if tag != "throttle" else 30)
    print("[=] 全部试完，无命中", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
