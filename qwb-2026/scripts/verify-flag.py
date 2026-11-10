#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify-flag.py —— 提交前的双签闸门 + 负结论闸门

它只做**判定**，不发提交请求。目的是把两条纪律变成可执行的检查：

  1. **提交双签**（`check`）：flag 必须能指向一个**存在的**证据 artifact；
     同题同 flag 不重复；失败次数超过纪律上限就拒提。
  2. **负结论三重对照**（`verdict`）：写"不存在 / 不可解 / 无端点"之前，
     必须先读平台「已答出 N 次」；**N > 0 直接拒绝**，
     并且必须附上正向对照 + 负向对照两份证据。

用法：
  # 提交前
  python3 scripts/verify-flag.py check 12080 'y0u_f0und_th3_treasure_f8427e' \
      --evidence work/12080_jammed/hmac_hit.txt --agent pwn-12080

  # 写负结论前
  python3 scripts/verify-flag.py verdict 12062 --claim no-endpoint \
      --forward  evidence/12062-scanner-selftest.txt \
      --negative evidence/12062-vary-one-var.txt

  # 只看解出数
  python3 scripts/verify-flag.py verdict 12062 --claim info

退出码：0 通过 / 2 拒绝（硬性）/ 3 证据不足（补材料再跑）

依据（2026-10-24 羊城杯）：
  - 6 次"判死"全部被解出数推翻（12062/12079×2/12086/12073）；
  - 12083 因"把解密口令当 flag + 包外壳"白烧 8 次额度；
  - 12073 出现一次"本地无法复现的假 SOLVED"。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import sys
import time
from pathlib import Path

WS = Path(__file__).resolve().parent.parent
LOG = Path(__file__).resolve().parent.parent / "evidence" / "submit-log.jsonl"
TOKEN = Path(__file__).resolve().parent.parent / "work" / ".submit-token.json"
SHELL_RE = re.compile(r"(?i)^(flag|dasctf|ycb|ctfshow|flag\w*)\{([^{}]*)\}$")

# 纪律上限（团队自定 3 次；平台硬上限 50、45 次告警）
TEAM_MAX_FAIL = 3
PLATFORM_MAX = 50
PLATFORM_WARN = 45

NEGATIVE_CLAIMS = {"not-exists", "unsolvable", "no-endpoint", "dead", "unreachable"}


# ---------------------------------------------------------------- 工具

def read_log() -> list[dict]:
    out = []
    if LOG.exists():
        for ln in LOG.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
    return out


def detail_path(cid: str) -> Path | None:
    for p in (WS / "notes" / "ch-meta" / f"ch_{cid}" / "detail.json",
              WS / "work" / f"ch_{cid}" / "detail.json"):
        if p.exists():
            return p
    return None


def solved_count(cid: str) -> tuple[int | None, str]:
    """从 detail.json 的 score 串里读「已答出 N 次」。"""
    p = detail_path(cid)
    if not p:
        return None, f"找不到 {cid} 的 detail.json（先 `ycb.py detail {cid}`）"
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return None, f"detail.json 解析失败: {e}"
    sc = str(d.get("score") or "")
    m = re.search(r"已答出\s*(\d+)\s*次", sc)
    if not m:
        m2 = re.search(r"solvedCount\"?\s*[:=]\s*(\d+)", json.dumps(d, ensure_ascii=False))
        if not m2:
            return None, f"score 串里没有解出数: {sc[:80]!r}"
        return int(m2.group(1)), sc
    return int(m.group(1)), sc


def sha256_of(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def require_artifact(path_str: str, what: str) -> Path | None:
    p = Path(path_str)
    if not p.is_absolute():
        p = (WS / path_str)
    if not p.exists():
        print(f"[2] {what} 证据不存在: {p}")
        return None
    if p.is_file() and p.stat().st_size == 0:
        print(f"[2] {what} 证据是空文件: {p}")
        return None
    return p


# ---------------------------------------------------------------- check

def cmd_check(args) -> int:
    cid, flag = str(args.id), args.flag
    fails = 0
    for r in read_log():
        if str(r.get("id")) != cid:
            continue
        if r.get("result") is True:
            if r.get("flag") == flag:
                print(f"[i] 同题同 flag 已提交成功过，无需重复（{r.get('time')}）")
                return 0
            print(f"[2] {cid} 已解出（平台 result:true），再提交不同 flag 会被拒。"
                  f"已通过: {r.get('flag')!r}")
            return 2
        # 失败计数只算「flag 错」。换场次后成功码/错误码会变
        # （羊城杯 00000=成功；强网杯 0=成功、100/114=未登录、101=参数错），
        # 所以新版客户端在台账里写 kind=ok/auth/param/wrong，优先按 kind 判。
        kind = r.get("kind")
        if kind == "wrong":
            fails += 1
        elif kind is None and r.get("result") is False \
                and r.get("resp_code") not in (None, "", "00000"):
            fails += 1

    if fails >= TEAM_MAX_FAIL and not args.parent_override:
        print(f"[2] {cid} 已失败 {fails} 次（团队纪律上限 {TEAM_MAX_FAIL}）。"
              f"停止猜测；--parent-override 只能由父代理/人类决定。")
        return 2
    if fails >= PLATFORM_WARN:
        print(f"[!] 平台额度告警：{cid} 已用 {fails}/{PLATFORM_MAX}")

    # flag 形态：★ 各平台要求相反，票里两种摘要都存，由客户端按本平台语义校验
    #   羊城杯 DASCTF：只收 {} 内的内容（要剥壳）
    #   强网杯 i春秋 ：要 flag{} 整串（不剥壳）——见 notes/methods/qwb-manual-2026.md §4.1
    body = flag
    stripped = flag
    if "{" in flag and flag.rstrip().endswith("}"):
        stripped = flag[flag.index("{") + 1: flag.rstrip().rindex("}")]
        print(f"[i] flag 带壳：整串 {flag!r} / 去壳 {stripped!r}")
        print("    → 羊城杯式平台提交去壳内容；强网杯提交整串。以本场平台文档为准。")
    if not stripped.strip():
        print("[2] flag 为空")
        return 2
    if re.search(r"\s", stripped):
        print("[!] flag 内含空白字符，确认不是复制粘贴带进来的换行/空格")

    # 证据 artifact（双签核心）
    art = require_artifact(args.evidence, "来源")
    if art is None:
        print("    → 提交前必须能指向一个 artifact（解密明文 / 程序输出 / 服务端回显）")
        return 2

    print("=" * 60)
    print(f"[0] 双签通过  {cid}")
    print(f"    flag     : {body}")
    print(f"    来源     : {art}  sha256={sha256_of(art)[:16]}…"
          if art.is_file() else f"    来源     : {art}/")
    print(f"    已失败   : {fails} 次（纪律上限 {TEAM_MAX_FAIL}，平台上限 {PLATFORM_MAX}）")
    print(f"    提交者   : {args.agent or 'parent'}")
    print("    → 现在可以: CTF_AGENT=<名> python3 scripts/qwb.py submit %s '%s'" % (cid, body))
    print("     （羊城杯老流程用 ycb.py submit；强网杯用 qwb.py submit）")

    # ★ 出票：客户端会校验它（票绑定具体串，一次性，300s）
    m = SHELL_RE.match(stripped)
    norm = m.group(2) if m else stripped
    TOKEN.parent.mkdir(parents=True, exist_ok=True)
    TOKEN.write_text(json.dumps({
        "id": cid,
        "flag_sha256": hashlib.sha256(norm.encode()).hexdigest(),        # 去壳（ycb 语义）
        "flag_sha256_raw": hashlib.sha256(body.encode()).hexdigest(),     # 整串（qwb 语义）
        "evidence": str(art),
        "ts": time.time(),
        "nonce": secrets.token_hex(8),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"    票   : {TOKEN}（300s 内有效，一次性）")
    print("=" * 60)
    return 0


# ---------------------------------------------------------------- verdict

def cmd_verdict(args) -> int:
    cid = str(args.id)
    n, raw = solved_count(cid)
    if args.claim == "info":
        print(f"{cid}: 已答出 {n if n is not None else '?'} 次    ({raw[:100]})")
        return 0

    if args.claim not in NEGATIVE_CLAIMS:
        print(f"[2] --claim 只能是 {sorted(NEGATIVE_CLAIMS)} 或 info")
        return 2
    if n is None:
        print(f"[3] 无法判定：{raw}")
        print("    负结论不允许在缺解出数的情况下写出。")
        return 3
    if n > 0:
        print(f"[2] 负结论被拒：{cid} 平台显示**已答出 {n} 次**。")
        print("    N > 0 ⇒ 你的「%s」必错。回去补覆盖矩阵，不要写结论。" % args.claim)
        print(f"    原始 score 串: {raw[:120]}")
        return 2

    # N == 0：仍要求两份对照证据
    miss = []
    fwd = require_artifact(args.forward, "正向对照") if args.forward else None
    neg = require_artifact(args.negative, "负向对照") if args.negative else None
    if not fwd:
        miss.append("--forward（把已知为真的样本喂给判据，证明判据没坏）")
    if not neg:
        miss.append("--negative（只改一个变量，证明判据会翻转）")
    if miss:
        print("[3] 证据不足，还不能写负结论：")
        for m in miss:
            print("    - " + m)
        print(f"    （已答出 {n} 次，外部反证这一关过了；还缺两关。）")
        return 3

    print("=" * 60)
    print(f"[0] 负结论三重对照通过  {cid}  claim={args.claim}")
    print(f"    外部反证: 已答出 {n} 次")
    print(f"    正向对照: {fwd}")
    print(f"    负向对照: {neg}")
    print("    措辞必须是：「在我枚举的 N 个候选里不存在」，不是「不存在」。")
    print("=" * 60)
    return 0


# ---------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description="提交双签 + 负结论闸门（不发请求）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("check", help="提交前双签")
    p.add_argument("id")
    p.add_argument("flag")
    p.add_argument("--evidence", required=True, help="flag 来源 artifact（必须存在）")
    p.add_argument("--agent", help="提交者名（写进台账对账）")
    p.add_argument("--parent-override", action="store_true",
                   help="超过团队失败上限仍要提交（只能父代理/人类用）")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("verdict", help="负结论闸门")
    p.add_argument("id")
    p.add_argument("--claim", required=True,
                   help="not-exists|unsolvable|no-endpoint|dead|unreachable|info")
    p.add_argument("--forward", help="正向对照证据文件")
    p.add_argument("--negative", help="负向对照证据文件")
    p.set_defaults(func=cmd_verdict)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
