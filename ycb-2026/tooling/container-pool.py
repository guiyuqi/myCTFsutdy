#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""container-pool.py —— 容器槽位的**唯一写者**（single writer）

为什么需要它（2026-10-24 羊城杯实测）：
  - 全队 116 次真实 `env` 调用，**父代理 69 次 + 15 个子代理各自调用** →
    同一个槽位被不同代理互相 start/stop 踩掉；
  - 4 台"幽灵态"：start 成功、stop 成功、`endpoints` 恒空；
  - "销毁不回落名额" 实测两次（stop 后仍占槽）；
  - `check-exercise-env` 的 `data:false` **没有判别力**（活靶机也是 false）。
  => 取址/释放必须收敛到一个脚本里，用固定判据 + 状态表 + 单写者锁。

判据（来自真实 detail.json 的 endpoints 结构）：
    就绪 := endpoints[*].status=="running"
            and endpoints[*].serviceStatus=="UP"
            and endpoints[*].exposeIps 非空
    地址 := endpoints[*].exposeIps[0]（例 "<target>:22234"）；
            http 类用 `http://<exposeIps[0]>/`，nc 类直接连该 host:port。

用法：
  python3 scripts/container-pool.py status
  python3 scripts/container-pool.py acquire <题号> [--timeout 90] [--max 4]
  python3 scripts/container-pool.py release <题号>
  python3 scripts/container-pool.py health  <题号>
  python3 scripts/container-pool.py blacklist
  python3 scripts/container-pool.py unblacklist <题号>

退出码：0 成功 / 3 幽灵（已拉黑）/ 4 超时 / 5 stop 后名额未回落 / 6 槽位已满

规则（写进 RULES.md §0.05 / §0.07）：
  - **其它任何角色禁止直接调 `env.*`**，只能通过本脚本申请/释放；
  - 探活**只允许单 keep-alive**，禁止并发新连接（本场 24–30 并发新连接曾把整机打下线）。
"""
from __future__ import annotations

import argparse
import fcntl
import importlib.util
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

WS = Path(__file__).resolve().parent.parent
POOL = WS / "work" / ".pool.json"
LOCK = WS / "work" / ".pool.lock"
POLL_SEC = 5          # 前端 checkEndpointInterval 默认 5s
GHOST_AFTER = 90      # 超过这个秒数还没 running 就判幽灵


# ---------------------------------------------------------------- ycb 桥

def _load_ycb():
    spec = importlib.util.spec_from_file_location("y", str(WS / "scripts" / "ycb.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


y = _load_ycb()


class _A:
    """给 ycb.cfg() 用的最小参数壳。"""
    def __init__(self, api=None, base=None, token=None, match=None, stage=None):
        self.api, self.base, self.token, self.match, self.stage = api, base, token, match, stage


def conf(args) -> dict:
    return y.cfg(_A(api=getattr(args, "api", None),
                    base=getattr(args, "base", None),
                    token=getattr(args, "token", None),
                    match=getattr(args, "match", None),
                    stage=getattr(args, "stage", None)))


# ---------------------------------------------------------------- 状态表

def now_s() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_state() -> dict:
    if POOL.exists():
        try:
            return json.loads(POOL.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return {"slots": {}, "blacklist": {}, "unreleased": {}, "updated": now_s()}


def save_state(st: dict) -> None:
    POOL.parent.mkdir(parents=True, exist_ok=True)
    st["updated"] = now_s()
    tmp = POOL.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(POOL)


class _Lock:
    """单写者：所有会改变 state/平台的操作用同一把锁串行化。"""
    def __enter__(self):
        POOL.parent.mkdir(parents=True, exist_ok=True)
        self.f = open(LOCK, "w")
        fcntl.flock(self.f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()


# ---------------------------------------------------------------- 平台操作

def get_detail(conf_, sid, cid):
    js = y.http("GET", f"{y.API}/player/ctf/exercise", conf=conf_,
                params={"matchId": conf_["match"], "exerciseId": str(cid), "stageId": sid})
    return y.parse_maybe_json(y.unwrap(js, f"detail {cid}")) or {}


def endpoint_ready(d) -> dict | None:
    """按真实结构判就绪；返回 {addr, ports, expire, raw} 或 None。"""
    eps = d.get("endpoints") or []
    if not isinstance(eps, list):
        return None
    for ep in eps:
        if not isinstance(ep, dict):
            continue
        if str(ep.get("status", "")).lower() != "running":
            continue
        if str(ep.get("serviceStatus", "")).upper() not in ("UP", ""):
            continue
        addrs = ep.get("exposeIps") or ep.get("proxyIps") or []
        if not addrs:
            continue
        return {"addr": addrs[0], "ports": ep.get("ports") or [],
                "exposeIps": addrs, "expire": ep.get("expireTime"), "raw": ep}
    return None


def start_env(conf_, sid, cid):
    return y.http("POST", f"{y.API}/player/ctf/build-exercise-env", conf=conf_,
                  body={"matchId": conf_["match"], "exerciseId": str(cid), "stageId": sid},
                  timeout=120)


def stop_env(conf_, sid, cid):
    return y.http("POST", f"{y.API}/player/ctf/recover-exercise-env", conf=conf_,
                  body={"stageId": sid, "exerciseId": str(cid)})


# ---------------------------------------------------------------- 命令

def cmd_status(args):
    st = load_state()
    slots = st.get("slots", {})
    print(f"# 容器池状态（更新于 {st.get('updated')}）")
    print(f"占用槽位: {len(slots)}/{args.max}\n")
    if not slots:
        print("（空）")
    else:
        print("| 题号 | 地址 | 端口 | 取得于 | 到期 | 取得者 |")
        print("|---|---|---|---|---|---|")
        for cid, s in sorted(slots.items()):
            exp = s.get("expire")
            exp_s = (datetime.fromtimestamp(exp / 1000, timezone.utc).strftime("%H:%M:%SZ")
                     if isinstance(exp, (int, float)) else "?")
            print(f"| {cid} | {s.get('addr')} | {','.join(s.get('ports') or [])} | "
                  f"{s.get('acquired_at')} | {exp_s} | {s.get('by')} |")
    if st.get("unreleased"):
        print("\n## ⚠️ stop 后名额未回落（平台缺陷，需换题/找运维）")
        for cid, u in st["unreleased"].items():
            print(f"- {cid}: {u.get('at')} — {u.get('note')}")
    if st.get("blacklist"):
        print("\n## 黑名单（幽灵容器）")
        for cid, b in st["blacklist"].items():
            print(f"- {cid}: {b.get('at')} — {b.get('reason')}")
    return 0


def cmd_acquire(args):
    cid = str(args.id)
    conf_ = conf(args)
    sid = y.ensure_stage(conf_)

    with _Lock():
        st = load_state()
        if cid in st.get("blacklist", {}):
            b = st["blacklist"][cid]
            print(f"[!] {cid} 已在黑名单（{b.get('reason')}）。换题，别重试。")
            return 3
        slots = st.setdefault("slots", {})
        if cid in slots:
            print(f"[=] {cid} 已持有：{slots[cid]['addr']}")
            return 0
        if len(slots) >= args.max:
            print(f"[!] 槽位已满 {len(slots)}/{args.max}："
                  f"{hint_slots(slots)}。先 release 再 acquire。")
            return 6

        # 1) 已有活靶机就不重复 start（避免被不同代理踩掉）
        d = get_detail(conf_, sid, cid)
        ep = endpoint_ready(d)
        started = False
        if not ep:
            start_env(conf_, sid, cid)
            started = True
            print(f"[*] {cid}: 已发出 start，开始轮询（{POLL_SEC}s × 最长 {args.timeout}s）")

        # 2) 轮询 detail，直到就绪或超时
        t0 = time.time()
        while True:
            if not ep:
                time.sleep(POLL_SEC)
                d = get_detail(conf_, sid, cid)
                ep = endpoint_ready(d)
            if ep:
                break
            if time.time() - t0 > args.timeout:
                st.setdefault("blacklist", {})[cid] = {
                    "at": now_s(),
                    "reason": f"start 后 {args.timeout}s 内 endpoints 未 running（幽灵容器）"
                              f"{'（本轮刚 start）' if started else ''}",
                }
                save_state(st)
                print(f"[3] {cid} 判幽灵：{args.timeout}s 未就绪，已拉黑。换题。")
                print("    endpoints 原始值: " +
                      json.dumps((d.get("endpoints") if isinstance(d, dict) else None),
                                 ensure_ascii=False)[:300])
                return 3

        slots[cid] = {"addr": ep["addr"], "ports": ep["ports"], "exposeIps": ep["exposeIps"],
                      "expire": ep["expire"], "acquired_at": now_s(),
                      "by": os.environ.get("CTF_AGENT", "parent")}
        save_state(st)

    url = ""
    if any(p.startswith("http") for p in (ep["ports"] or [])) or args.assume_http:
        url = f"http://{ep['addr']}/"
    print(f"[+] {cid} 就绪: {ep['addr']}  端口={ep['ports']}")
    if url:
        print(f"    目标 URL: {url}")
    return 0


def cmd_release(args):
    cid = str(args.id)
    conf_ = conf(args)
    sid = y.ensure_stage(conf_)
    with _Lock():
        st = load_state()
        slots = st.setdefault("slots", {})
        was = slots.pop(cid, None)
        stop_env(conf_, sid, cid)

        # ★ 复核名额是否回落：stop 成功 != 名额释放（本场实测两次）
        time.sleep(args.settle)
        d = get_detail(conf_, sid, cid)
        still = endpoint_ready(d)
        if still:
            st.setdefault("unreleased", {})[cid] = {
                "at": now_s(),
                "note": f"stop 后 endpoints 仍为 {still['addr']}（名额可能未回落）",
            }
            save_state(st)
            print(f"[5] {cid}: stop 已发出，但 endpoints 仍指向 {still['addr']} —— 名额可能未回落。")
            return 5
        st.get("unreleased", {}).pop(cid, None)
        save_state(st)
    print(f"[+] {cid} 已释放（原地址 {was['addr'] if was else '未持有'}），名额已回落。")
    return 0


def cmd_health(args):
    cid = str(args.id)
    st = load_state()
    s = st.get("slots", {}).get(cid)
    if not s:
        print(f"[!] {cid} 不在池里")
        return 6
    ports = s.get("ports") or []
    url = f"http://{s['addr']}/" if any(p.startswith("http") for p in ports) else None
    if not url:
        print(f"[i] {cid} 非 http（端口 {ports}），用 nc 单连接探活: nc -zv {s['addr'].rsplit(':',1)[0]} ...")
        return 0
    # ★ 只允许单 keep-alive 探活，禁止并发（并发新连接会触发平台惩罚）
    try:
        req = urllib.request.Request(url, headers={"user-agent": "ctf-pool-health/1"})
        with urllib.request.urlopen(req, timeout=args.timeout) as r:
            print(f"[+] {cid} 健康: HTTP {r.status}  {url}")
            return 0
    except urllib.error.HTTPError as e:
        print(f"[~] {cid} 有响应但非 2xx: HTTP {e.code}  {url}")
        return 0
    except Exception as e:
        print(f"[!] {cid} 探活失败: {e}  {url}")
        return 4


def cmd_blacklist(args):
    st = load_state()
    if not st.get("blacklist"):
        print("（黑名单为空）")
        return 0
    for cid, b in st["blacklist"].items():
        print(f"- {cid}: {b['at']}  {b['reason']}")
    return 0


def cmd_unblacklist(args):
    with _Lock():
        st = load_state()
        if st.get("blacklist", {}).pop(str(args.id), None):
            save_state(st)
            print(f"[+] {args.id} 已移出黑名单")
            return 0
    print(f"[i] {args.id} 不在黑名单")
    return 0


def hint_slots(slots) -> str:
    if not slots:
        return "无"
    return ", ".join(f"{k}@{v.get('addr')}" for k, v in slots.items())


# ---------------------------------------------------------------- main

def main() -> int:
    # 全局选项用 parents 同时挂到主命令和每个子命令上（两处都能写），
    # 并用 SUPPRESS 作默认值，避免子解析器把主解析器已设的值覆盖成 None。
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--api", default=argparse.SUPPRESS,
                        help="API 前缀（换场次时覆盖，同 ycb.py）")
    common.add_argument("--base", default=argparse.SUPPRESS,
                        help="平台 base（默认取 creds / 内置；接 mock 时用）")
    common.add_argument("--token", default=argparse.SUPPRESS, help="token（一般不传，走 creds）")
    common.add_argument("--match", default=argparse.SUPPRESS, help="matchId（默认取 creds）")
    common.add_argument("--stage", default=argparse.SUPPRESS, help="stageId（默认自动解析）")
    common.add_argument("--max", type=int, default=4,
                        help="并发槽位数（开局实测，默认 4）")

    ap = argparse.ArgumentParser(description="容器槽位唯一写者（羊城杯/DASCTF）", parents=[common])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("status", parents=[common]); p.set_defaults(func=cmd_status)
    p = sub.add_parser("acquire", parents=[common]); p.add_argument("id")
    p.add_argument("--timeout", type=int, default=GHOST_AFTER)
    p.add_argument("--assume-http", action="store_true")
    p.set_defaults(func=cmd_acquire)
    p = sub.add_parser("release", parents=[common]); p.add_argument("id")
    p.add_argument("--settle", type=int, default=5, help="stop 后等待秒数再复核名额")
    p.set_defaults(func=cmd_release)
    p = sub.add_parser("health", parents=[common]); p.add_argument("id")
    p.add_argument("--timeout", type=int, default=10)
    p.set_defaults(func=cmd_health)
    p = sub.add_parser("blacklist", parents=[common]); p.set_defaults(func=cmd_blacklist)
    p = sub.add_parser("unblacklist", parents=[common]); p.add_argument("id")
    p.set_defaults(func=cmd_unblacklist)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
