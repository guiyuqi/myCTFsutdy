#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第十届强网杯（2026）平台客户端 —— match.ichunqiu.com / apiterminator.ichunqiu.com

平台事实来自 2026-10-30 赛前静态逆向（18 个 brotli chunk）+ 匿名只读实测，
完整依据见 notes/methods/platform-qwb-ichunqiu.md。**开赛先跑 `creds` 回源复核。**

与上一场（羊城杯 DASCTF）的关键差异 —— 照着 ycb.py 的用法打会全错：
  - API 宿主   : https://apiterminator.ichunqiu.com   （不是页面同源！）
  - 方法       : 一律 POST，body 是 JSON（前端 axios 默认序列化）
  - 鉴权       : body 里的 token（登录态）+ k（比赛 url_key）
                 __jsluid_s 只是加速乐反爬 cookie，**不是登录态**
  - 签名       : 头 SIGN = sha1("&".join(sorted("k=v")) + "&" + SALT)
                 SALT = 7637b08bdb0b29e08300a976b24ca672
                 body 里另补 k / stamp / token / rs（rs = md5(时间戳+随机+"icq")）
  - 成功码     : code == 0    （羊城杯是字符串 "00000"）
  - 错误码     : 100/114 未登录、101 参数/无法访问、116 无数据、201 比赛未开始
  - 容器       : /match/docker/{info,apply,process,delay,close}
                 配额 team_docker_limit=3、user_docker_limit=1（赛前快照）
  - 提交       : /match/red/submit（答题页按钮实际走的路径，见文档 §6）

用法：
  python3 scripts/qwb.py creds                # 凭据 + 连通性自检（脱敏）
  python3 scripts/qwb.py detail               # 比赛详情（公开，含容器配额）
  python3 scripts/qwb.py surplus              # 距开赛/剩余时间
  python3 scripts/qwb.py classes              # 题目分类（公开）
  python3 scripts/qwb.py list [--raw]         # 题目清单（需登录）
  python3 scripts/qwb.py get <id> [--download]# 单题详情（+ 拉附件到 firmware/）
  python3 scripts/qwb.py submit <id> '<flag>' # 走 verify-flag 门禁 + 台账
  python3 scripts/qwb.py docker info|apply|close|log   # 默认拒绝，见下
  python3 scripts/qwb.py call <path> '<json>' # 调试：任意端点原始回包
  python3 scripts/qwb.py log                  # 提交台账
  python3 scripts/qwb.py set-token            # 从 stdin 读 token 写入 creds.env（0600）

★ 容器纪律：本脚本的 `docker` 子命令**默认拒绝执行**，必须走
  `python3 scripts/container-pool.py acquire|release <题号>`（全队唯一写者）。
  确需绕过：QWB_ALLOW_DOCKER=1 或在 work/.gate-override 写理由（会被记账）。

★ 提交纪律：必须先用
  `python3 scripts/verify-flag.py check <题号> '<flag>' --evidence <artifact> --agent <角色>`
  拿到一次性票（票绑定 flag 摘要，300 秒有效，用后即焚）。
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

WS = Path(__file__).resolve().parent.parent
CREDS = Path(os.environ.get("CTF_CREDS", Path.home() / ".config" / "ctf" / "creds.env"))
BASE = (os.environ.get("QWB_BASE") or "https://apiterminator.ichunqiu.com").rstrip("/")
SALT = "7637b08bdb0b29e08300a976b24ca672"      # 前端拦截器硬编码
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/<target> Safari/537.36 Edg/<target>")

LOG = Path(os.environ.get("QWB_SUBMIT_LOG", WS / "evidence" / "submit-log.jsonl"))
LOCK = WS / "work" / ".submit.lock"
FIRMWARE = WS / "firmware"
GATE_TOKEN = WS / "work" / ".submit-token.json"   # verify-flag.py check 产出，一次性
GATE_OVERRIDE = WS / "work" / ".gate-override"    # 破窗：首行写理由
GATE_LOG = WS / "evidence" / "gate-log.jsonl"
TOKEN_TTL = 300
MAX_SUBMIT = 50                                    # 平台每题上限（队内共享）
WARN_SUBMIT = 45

LAST_URL = ""


# ---------------------------------------------------------------- 凭据

def load_creds() -> dict:
    c = {}
    if CREDS.exists():
        for ln in CREDS.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#") or "=" not in ln:
                continue
            k, _, v = ln.partition("=")
            c[k.strip()] = v.strip().strip('"').strip("'")
    return c


def conf(args=None) -> dict:
    c = load_creds()
    k = str(getattr(args, "k", "") or c.get("QWB_K") or os.environ.get("QWB_K") or "").strip()
    token = str(getattr(args, "token", "") or c.get("QWB_TOKEN") or
                os.environ.get("QWB_TOKEN") or "").strip()
    jsluid = str(c.get("QWB_JSLUID") or os.environ.get("QWB_JSLUID") or "").strip()
    return {"k": k, "token": token, "jsluid": jsluid, "base": BASE}


def mask(s: str, keep: int = 6) -> str:
    if not s:
        return "（空）"
    if len(s) <= keep * 2:
        return s[:keep] + "…"
    return f"{s[:keep]}…{s[-4:]}（长度 {len(s)}）"


# ---------------------------------------------------------------- 签名 + HTTP

def js_str(v) -> str:
    """JS 的 `${v}` / String(v) 语义（真/假是小写）。"""
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return "null"
    return str(v)


def sign(data: dict) -> str:
    joined = "&".join(sorted(f"{k}={js_str(v)}" for k, v in data.items()))
    return hashlib.sha1((joined + "&" + SALT).encode()).hexdigest()


def http(path: str, body: dict | None = None, *, cf: dict, timeout: int = 30,
         retries: int = 4, raw: bool = False) -> dict:
    """POST 到 apiterminator，自动补 k/stamp/token/rs 并算 SIGN。"""
    global LAST_URL
    url = cf["base"] + path
    LAST_URL = url
    d = dict(body or {})
    if cf.get("k") and "k" not in d:
        d["k"] = cf["k"]
    d["stamp"] = int(time.time() * 1000)
    d["token"] = cf.get("token") or ""
    d["rs"] = hashlib.md5(
        (str(time.time() * 1000) + str(random.random()) + "icq").encode()).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "SIGN": sign(d),
        "X-Lang": "zh-CN",
        "Origin": "https://match.ichunqiu.com",
        "Referer": "https://match.ichunqiu.com/",
        "User-Agent": UA,
    }
    if cf.get("jsluid"):
        headers["Cookie"] = f"__jsluid_s={cf['jsluid']}"

    payload = json.dumps(d, ensure_ascii=False).encode()
    last_exc = None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                rb = r.read()
                ctype = r.headers.get("content-type", "")
            break
        except urllib.error.HTTPError as e:
            rb = e.read()
            ctype = e.headers.get("content-type", "")
            if e.code in (401, 403):
                raise SystemExit(f"[!] HTTP {e.code} 被网关拒绝（多半是 SIGN 或 k 不对）\n"
                                 f"    {rb[:300].decode('utf-8', 'replace')}")
            break
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            last_exc = e
            time.sleep(1 + attempt * 1.5)
    else:
        raise SystemExit(f"[!] 网络失败（重试 {retries} 次）：{last_exc}\n"
                         f"    实际请求: {url}")

    if raw:
        return {"_raw": rb, "_ctype": ctype}
    try:
        return json.loads(rb.decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"_raw": rb[:2000].decode("utf-8", "replace"), "_ctype": ctype}


ERRS = {
    100: "请登录平台（token 缺失/失效）",
    101: "参数错误 / 无法访问比赛（k 或 payload 不对，**不是** flag 错）",
    114: "请登录平台（token 缺失/失效）",
    116: "暂无数据",
    130: "需要人脸认证（本场已关，见到说明环境变了）",
    201: "比赛未开始",
}


def unwrap(js: dict, what: str = "", *, allow=()) -> object:
    if not isinstance(js, dict):
        raise SystemExit(f"[!] {what} 回包异常：{str(js)[:200]}\n    实际请求: {LAST_URL}")
    if "_raw" in js:
        raise SystemExit(f"[!] {what} 返回非 JSON（{js.get('_ctype')}）：{str(js['_raw'])[:300]}\n"
                         f"    实际请求: {LAST_URL}")
    code = js.get("code")
    if code == 0 or code in allow:
        return js.get("data")
    msg = js.get("message") or js.get("msg") or ""
    hint = ERRS.get(code, "")
    detail = f"\n    → {hint}" if hint else ""
    raise SystemExit(f"[!] {what} 失败 code={code} message={msg}{detail}\n"
                     f"    实际请求: {LAST_URL}")


# ---------------------------------------------------------------- 门禁

def _gate_log(event: str, **kw) -> None:
    try:
        GATE_LOG.parent.mkdir(parents=True, exist_ok=True)
        rec = {"time": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
               "event": event, **kw}
        with GATE_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def require_submit_token(cid: str, flag: str) -> None:
    """提交门：必须持有 verify-flag.py 产出的一次性票（与 ycb.py 同款失败关闭）。"""
    if GATE_OVERRIDE.exists():
        reason = ""
        try:
            reason = GATE_OVERRIDE.read_text(encoding="utf-8").splitlines()[0][:120]
        except OSError:
            pass
        print(f"[!] 门禁破窗：{GATE_OVERRIDE} 存在（理由：{reason or '未写'}）→ 放行",
              file=sys.stderr)
        _gate_log("submit_override", id=str(cid),
                  flag_sha=hashlib.sha256(flag.encode()).hexdigest()[:16], reason=reason)
        return

    want = hashlib.sha256(flag.encode()).hexdigest()
    if not GATE_TOKEN.exists():
        raise SystemExit(
            "[2] 提交被门禁拒绝：缺少一次性票。\n"
            f"    先跑：python3 scripts/verify-flag.py check {cid} '<flag>' --evidence <来源文件>\n"
            "    （票 = flag 摘要 + 证据 artifact + 时间戳，300 秒内有效且一次性）\n"
            f"    确需绕过：把理由写进 {GATE_OVERRIDE}（会被记账）")
    try:
        t = json.loads(GATE_TOKEN.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise SystemExit(f"[2] 票文件损坏：{GATE_TOKEN}（重新跑 verify-flag.py check）")
    if str(t.get("id")) != str(cid):
        raise SystemExit(f"[2] 票的题号是 {t.get('id')}，与本次提交 {cid} 不符")
    if t.get("flag_sha256") != want and t.get("flag_sha256_raw") != want:
        raise SystemExit("[2] 票与 flag 不符：check 时用的不是这个串（票故意绑定具体 flag）")
    age = time.time() - float(t.get("ts") or 0)
    if age > TOKEN_TTL:
        raise SystemExit(f"[2] 票已过期（{int(age)}s > {TOKEN_TTL}s），重新 check")
    ev = Path(str(t.get("evidence") or ""))
    if not str(ev) or not ev.exists():
        raise SystemExit(f"[2] 票里的证据 artifact 不存在：{ev}")
    GATE_TOKEN.unlink(missing_ok=True)
    _gate_log("submit_token_ok", id=str(cid), flag_sha=want[:16], evidence=str(ev), age=int(age))
    print(f"[+] 门禁放行（票有效 {int(age)}s，证据 {ev}）", file=sys.stderr)


def require_container_channel() -> None:
    """容器门：只有 container-pool.py 能写容器槽位（唯一写者）。"""
    if os.environ.get("QWB_ALLOW_DOCKER") == "1":
        print("[!] QWB_ALLOW_DOCKER=1：绕过容器门（仅供单点排障）", file=sys.stderr)
        _gate_log("docker_override", via="env")
        return
    if GATE_OVERRIDE.exists():
        reason = ""
        try:
            reason = GATE_OVERRIDE.read_text(encoding="utf-8").splitlines()[0][:120]
        except OSError:
            pass
        print(f"[!] 门禁破窗：{reason or '未写'}", file=sys.stderr)
        _gate_log("docker_override", via="gate-override", reason=reason)
        return
    raise SystemExit(
        "[3] 容器操作被门禁拒绝：容器槽位只能在 container-pool.py 里申请/释放。\n"
        "    python3 scripts/container-pool.py status\n"
        "    python3 scripts/container-pool.py acquire <题号>\n"
        "    python3 scripts/container-pool.py release <题号>\n"
        "    （多代理直接调 env/docker 会互踩槽位 —— 上一场实测 4 台幽灵态）\n"
        f"    确需绕过：work/.gate-override 写理由，或 QWB_ALLOW_DOCKER=1")


# ---------------------------------------------------------------- 台账

def read_log() -> list[dict]:
    out = []
    if LOG.exists():
        for ln in LOG.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if ln:
                try:
                    out.append(json.loads(ln))
                except json.JSONDecodeError:
                    pass
    return out


def append_log(rec: dict) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------- 命令

def cmd_creds(args) -> int:
    cf = conf(args)
    print(f"API      : {cf['base']}")
    print(f"K        : {mask(cf['k'], 10)}")
    print(f"TOKEN    : {mask(cf['token'])}")
    print(f"JSLUID   : {mask(cf['jsluid'])}")
    print(f"凭据文件 : {CREDS}  ({'存在' if CREDS.exists() else '不存在'})")
    print()
    ok = True
    # 1) 公开端点：验证 SIGN 是否正确
    js = http("/match/detail", {"url_key": cf["k"], "is_encrypt": 1}, cf=cf)
    code = js.get("code")
    if code == 0:
        d = js.get("data") or {}
        print(f"[OK]  匿名读取比赛详情：{d.get('title')}")
        print(f"      开赛 {d.get('start_time')} → 结束 {d.get('end_time')}")
        print(f"      容器配额：全队 {d.get('team_docker_limit')} 台 / 每人 {d.get('user_docker_limit')} 台")
        print(f"      s_source_id={d.get('s_source_id')}（localStorage 存 token 的键）")
    else:
        ok = False
        print(f"[FAIL] 公开端点 code={code} {js.get('message')}")
        print("       → SIGN/参数结构可能变了，重新逆 assets/index.*.js 的拦截器")
    # 2) 登录态
    js2 = http("/match/team/info", {}, cf=cf)
    c2 = js2.get("code")
    if c2 == 0:
        t = js2.get("data") or {}
        print(f"[OK]  登录态有效：队伍 {t.get('name') or t.get('team_name') or '（见原始回包）'}")
    elif c2 in (100, 114):
        ok = False
        print(f"[--]  登录态缺失（code={c2}）：跑 `python3 scripts/qwb.py set-token` 贴 token")
        print('       浏览器 Console: JSON.parse(localStorage["9FZ4dGtRk0I"]).token')
    elif c2 == 116:
        print("[--]  已登录但暂无队伍信息（code=116，常见于未开赛/未组队）")
    else:
        print(f"[??]  team/info code={c2} {js2.get('message')}")
    return 0 if ok else 2


def cmd_detail(args) -> int:
    cf = conf(args)
    d = unwrap(http("/match/detail", {"url_key": cf["k"], "is_encrypt": 1}, cf=cf), "比赛详情")
    print(json.dumps(d, ensure_ascii=False, indent=1))
    return 0


def cmd_surplus(args) -> int:
    cf = conf(args)
    js = http("/match/surplus_time", {}, cf=cf)
    code = js.get("code")
    d = js.get("data") or {}
    mt = d.get("match_time")
    if code == 201:
        print(f"比赛未开始，距开赛 {mt} 秒（{fmt_dur(mt)}）")
    elif code == 0:
        print(f"比赛进行中，剩余 {mt} 秒（{fmt_dur(mt)}）  round_now={d.get('round_now')}")
    else:
        print(f"code={code} {js.get('message')}")
    print(json.dumps(d, ensure_ascii=False))
    return 0


def fmt_dur(s) -> str:
    try:
        s = int(s)
    except (TypeError, ValueError):
        return "?"
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h}小时{m}分{sec}秒"


def cmd_classes(args) -> int:
    cf = conf(args)
    d = unwrap(http("/match/question/class", {"is_hidden": 0, "show_num": ""}, cf=cf), "分类")
    for c in d or []:
        print(f"  id={c.get('id'):<6} base={c.get('base_id')} attribute={c.get('attribute')} "
              f"title={c.get('title')}  题数={((c.get('question') or {}).get('total'))}")
    return 0


def cmd_team(args) -> int:
    """队伍信息 / 队员 / 分类得分（本队状态，只读）。"""
    cf = conf(args)
    what = args.what
    if what == "info":
        d = unwrap(http("/match/team/info", {}, cf=cf), "队伍信息") or {}
        for k in ("team_name", "school", "team_id", "team_rank", "total_score",
                  "total_number", "total_first", "red_score", "blue_score"):
            print(f"  {k:<12} = {d.get(k)}")
        tok = str(d.get("token") or "")
        print(f"  teamtoken    = {tok[:6]}…（长度 {len(tok)}）" if tok else "  teamtoken    = （无）")
    elif what == "users":
        d = unwrap(http("/match/team/users", {}, cf=cf), "队员") or {}
        for u in d.get("lists") or []:
            print(f"  {u.get('user_name'):<10} score={u.get('total_score')} "
                  f"number={u.get('total_number')} first={u.get('total_first')} "
                  f"login={u.get('is_login')}")
        print(f"  共 {d.get('total')} 人")
    elif what == "point":
        d = unwrap(http("/match/team/point", {}, cf=cf), "分类得分") or []
        for c in d:
            print(f"  {c.get('title'):<12} 得分={c.get('real_score')} "
                  f"解出={c.get('solved_total')}/{c.get('real_total')}")
    else:
        raise SystemExit("[!] team 子命令：info|users|point")
    return 0


def cmd_notice(args) -> int:
    """比赛公告。★ 容器数量、WriteUp 队数等官方口径都发在这里，开赛先看。"""
    cf = conf(args)
    js = http("/match/notice/lists", {"type": args.type, "page_index": 1,
                                      "page_size": args.limit}, cf=cf)
    if js.get("code") == 116:
        print(f"（暂无公告：{js.get('message')}）—— 开赛前后再拉一次")
        return 0
    d = unwrap(js, "公告")
    rows = d if isinstance(d, list) else (d.get("lists") if isinstance(d, dict) else [])
    if not rows:
        print("（空）")
        return 0
    for n in rows:
        print(f"  [{n.get('create_time') or n.get('time')}] {n.get('title')}")
        body = (n.get("content") or "").strip()
        if body:
            import re as _re
            body = _re.sub(r"<[^>]+>", "", body)
            print("      " + body[:600].replace("\n", "\n      "))
    return 0


def cmd_list(args) -> int:
    cf = conf(args)
    body = json.loads(args.data) if args.data else {
        "category_id": 0, "child_id": 0, "type_ids": "", "is_brief": 1,
        "page_index": 1, "page_size": "",
    }
    js = http("/match/question/lists", body, cf=cf)
    if args.raw:
        print(json.dumps(js, ensure_ascii=False, indent=1))
        return 0
    d = unwrap(js, "题目列表", allow=(116,))          # 116 = 未开赛/暂无题目
    rows = d if isinstance(d, list) else (d.get("lists") if isinstance(d, dict) else [])
    if not rows:
        print("（空：可能未开赛，或 payload 形状变了 —— 用 `qwb.py list --raw` 看原始回包）")
        return 0
    for q in rows:
        print(f"  id={q.get('id'):<6} [{q.get('class_name') or q.get('category_name') or ''}] "
              f"{q.get('title')}  score={q.get('score')} solved={q.get('solved')} "
              f"type_id={q.get('type_id')}")
    print(f"\n共 {len(rows)} 题")
    return 0


def _walk_urls(obj, out, path="") -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            _walk_urls(v, out, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _walk_urls(v, out, f"{path}[{i}]")
    elif isinstance(obj, str):
        if re.match(r"^https?://", obj) and len(obj) > 12:
            out.append((path, obj))


def cmd_get(args) -> int:
    cf = conf(args)
    # ★ 必须 is_brief=0：is_brief=1 时平台**不返回 content**，
    #   而附件直链恰恰嵌在 content 的 <a href> 里 ⇒ 用 1 拿不到附件（2026-10-31 实测）
    body = json.loads(args.data) if args.data else {
        "category_id": 0, "child_id": 0, "type_ids": "", "is_brief": 0,
        "page_index": args.page, "page_size": "",
    }
    d = unwrap(http("/match/question/lists", body, cf=cf), "题目列表", allow=(116,))
    rows = d if isinstance(d, list) else (d.get("lists") if isinstance(d, dict) else [])
    hit = [q for q in rows if str(q.get("id")) == str(args.id)]
    if not hit:
        raise SystemExit(f"[!] 题目 {args.id} 不在第 {args.page} 页（共 {len(rows)} 条）；"
                         f"用 `qwb.py get {args.id} --page N` 或 `--data` 指定 payload")
    q = hit[0]
    print(json.dumps(q, ensure_ascii=False, indent=1))
    # ★ 附件直链嵌在 content 的 HTML 里（`<p><a href="https://...">`），
    #   所以不能只匹配"以 http 开头的字符串"，要对整个 JSON 做正则扫描
    # ★ 附件直链嵌在 content 的 HTML 里（<p><a href="https://...">），
    #   所以不能只匹配"以 http 开头的字符串"，要对整个 JSON 做正则扫描
    urls = []
    _walk_urls(q, urls)
    for u in re.findall(r"""https?://[^\s"'<>\\]+""", json.dumps(q, ensure_ascii=False)):
        if u.endswith((".css", ".js")):
            continue
        if u.rstrip("/").endswith("/url"):
            continue
        urls.append(("content", u))
    seen = set()
    dedup = []
    for pth, u in urls:
        if u not in seen:
            seen.add(u)
            dedup.append((pth, u))
    urls = dedup
    if urls:
        print("\n--- 附件/链接候选 ---")
        for p, u in urls:
            print(f"  {p}: {u}")
    if args.download:
        slug = re.sub(r"[^\w\-]+", "_", str(q.get("title") or args.id))[:40] or str(args.id)
        outdir = FIRMWARE / f"qwb{args.id}_{slug}"
        outdir.mkdir(parents=True, exist_ok=True)
        if not urls:
            print("[!] 没有找到 http 链接 —— 附件字段名可能不同，先看上面的原始 JSON")
            return 3
        for p, u in urls:
            name = os.path.basename(u.split("?")[0]) or "attach.bin"
            dest = outdir / name
            print(f"[↓] {u}\n    → {dest}")
            try:
                req = urllib.request.Request(u, headers={"User-Agent": UA,
                                                        "Referer": "https://match.ichunqiu.com/"})
                with urllib.request.urlopen(req, timeout=120) as r, dest.open("wb") as f:
                    f.write(r.read())
                print(f"    {dest.stat().st_size} 字节")
            except Exception as e:                     # noqa: BLE001
                print(f"    [!] 下载失败：{e}")
    return 0


def cmd_submit(args) -> int:
    cf = conf(args)
    flag = (args.flag or "").strip()
    if not flag:
        raise SystemExit("[!] flag 为空")
    raw_flag = flag
    # 本平台前端就是按 flag{...} 整串提交的（不存在羊城杯那种剥壳规则）
    require_submit_token(args.id, flag)

    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open("w") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        recs = [r for r in read_log()
                if str(r.get("id")) == str(args.id) and r.get("transport") != "error"]
        if args.force:
            print("[!] --force：绕过本地闸门（只有父代理/人类该用）", file=sys.stderr)
            recs = []
        ok = [r for r in recs if r.get("result") is True]
        if ok:
            prev = ok[-1].get("flag", "")
            if prev == flag:
                print("[=] 该题已用这个 flag 提交成功过，跳过（不占额度）")
                return 0
            raise SystemExit(f"[!] 该题已解出（flag={prev}），拒绝提交不同 flag（确需强推：--force）")
        if len(recs) >= MAX_SUBMIT:
            raise SystemExit(f"[!] 该题已提交 {len(recs)} 次，达到上限 {MAX_SUBMIT}，停止。")
        if len(recs) >= WARN_SUBMIT:
            print(f"[!] 警告：已提交 {len(recs)} 次（上限 {MAX_SUBMIT}）", file=sys.stderr)
        same = [r for r in recs if r.get("flag") == flag]
        if same:
            print(f"[=] 同一 flag 已提交过（{same[-1].get('time')}），跳过（不占额度）")
            return 0

        via = args.via
        if args.body:
            # ★ 原样重放浏览器抓到的真实请求体：body 必须是 JSON；
            #   若里面没有本次 flag，就把它填进 _flag 占位符（方便复用一份模板）。
            path = args.path or "/match/red/submit"
            raw = args.body.replace("__FLAG__", flag)
            try:
                body = json.loads(raw)
            except json.JSONDecodeError as e:
                raise SystemExit(f"[!] --body 不是合法 JSON：{e}\n    收到：{raw[:200]}")
            if not isinstance(body, dict):
                raise SystemExit("[!] --body 必须是 JSON 对象")
            if flag not in json.dumps(body, ensure_ascii=False):
                print(f"[!] 警告：--body 里没出现本次 flag 串，确认不是漏填", file=sys.stderr)
            via = f"raw:{path}"
        elif via == "red":
            body = {"question_id": str(args.id), "answer": flag,
                    "img_url": "f97fae4e1ffdb1ee3b65231aa693ea85"}   # 无人脸时的死值
            path = "/match/red/submit"
        elif via == "flag":
            body = {"question_id": str(args.id), "flag": flag}
            path = "/match/flag/submit"
        elif via == "against":
            body = {"answer_str": flag}
            path = "/match/against/submit"
        else:
            raise SystemExit(f"[!] 未知 --via {via}（red|flag|against）")

        print(f"[i] POST {path}  via={via}", file=sys.stderr)
        rec = {"time": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
               "id": str(args.id), "flag": flag, "raw_flag": raw_flag, "via": via, "path": path,
               "agent": os.environ.get("CTF_AGENT", "parent")}
        try:
            js = http(path, body, cf=cf)
        except SystemExit as e:
            rec.update({"result": None, "message": str(e), "transport": "error"})
            append_log(rec)
            raise
        rec["resp_code"] = js.get("code")
        rec["message"] = js.get("message") or js.get("msg") or ""
        rec["data"] = js.get("data")
        # ★ 本平台判定：code==0 才算成功；其余一律「未成功」，但**不等于 flag 错**
        code = js.get("code")
        rec["result"] = True if code == 0 else False
        # ★ 限流不是"flag 错"：平台会回「对不起，您的操作太过频繁！」
        #   之前把它记成 result=False 会污染失败计数与后续判断（2026-10-31 实测）
        if "频繁" in str(rec["message"]):
            rec["result"] = None
            rec["kind"] = "throttle"
            append_log(rec)
            print("\n[!] 被平台限流（非 flag 错、不占次数）——退避后重试", file=sys.stderr)
            return 3
        # kind 给 verify-flag.py 数「失败次数」用：只有 wrong 才算 flag 错
        if code == 0:
            rec["kind"] = "ok"
        elif "答案" in str(rec["message"]) or "错误" in str(rec["message"]):
            rec["kind"] = "wrong"          # ★「答案错误」也是 code 101，必须按文案区分
        elif code in (100, 114):
            rec["kind"] = "auth"
        elif code == 101:
            rec["kind"] = "param"
        else:
            rec["kind"] = "wrong"
        append_log(rec)
        print(json.dumps(js, ensure_ascii=False, indent=1))
        if rec["result"]:
            print(f"\n[✓] 提交成功：{rec['message']}")
            return 0
        if code in (100, 114):
            print("\n[!] 未登录 —— 换 token，别当 flag 错", file=sys.stderr)
        elif code == 101:
            print("\n[!] 参数类错误 —— payload 形状可能不对。"
                  "抓一次浏览器真实提交（Copy as cURL）校准 --via，别连点浪费次数", file=sys.stderr)
        return 2


def cmd_docker(args) -> int:
    cf = conf(args)
    require_container_channel()
    action = args.action
    if action == "info":
        print(json.dumps(unwrap(http("/match/docker/info", {"question_id": str(args.id)},
                                    cf=cf), "docker/info"), ensure_ascii=False, indent=1))
    elif action == "apply":
        print(json.dumps(unwrap(http("/match/docker/apply", {"question_id": str(args.id)},
                                    cf=cf), "docker/apply"), ensure_ascii=False, indent=1))
    elif action == "close":
        print(json.dumps(unwrap(http("/match/docker/close",
                                    {"uuid": args.uuid, "close_type": args.close_type},
                                    cf=cf), "docker/close"), ensure_ascii=False, indent=1))
    elif action == "log":
        print(json.dumps(unwrap(http("/match/team/docker_log", {}, cf=cf), "docker_log"),
                         ensure_ascii=False, indent=1))
    else:
        raise SystemExit("[!] docker 子命令：info|apply|close|log")
    return 0


def cmd_call(args) -> int:
    cf = conf(args)
    body = json.loads(args.body) if args.body else {}
    js = http(args.path, body, cf=cf)
    print(json.dumps(js, ensure_ascii=False, indent=1))
    return 0


def cmd_log(args) -> int:
    for r in read_log():
        mark = "OK " if r.get("result") is True else ("ERR" if r.get("result") is False else "???")
        print(f"{r.get('time')} [{mark}] #{r.get('id'):<6} via={r.get('via', '-'):<8} "
              f"code={r.get('resp_code')} {r.get('message')}  flag={r.get('flag')}")
    return 0


def cmd_set_token(args) -> int:
    if sys.stdin.isatty():
        import getpass
        tok = getpass.getpass("粘贴 token（无回显）：").strip()
    else:
        tok = sys.stdin.readline().strip()
    tok = tok.strip().strip('"').strip("'").replace("Bearer ", "").replace(" ", "")
    if len(tok) < 16:
        raise SystemExit(f"[!] token 太短（{len(tok)} 字符），没粘对？")
    lines = []
    if CREDS.exists():
        lines = CREDS.read_text(encoding="utf-8", errors="replace").splitlines()
    out, seen = [], set()
    for ln in lines:
        m = re.match(r"^\s*([A-Z0-9_]+)\s*=", ln)
        if m and m.group(1) == "QWB_TOKEN":
            out.append(f"QWB_TOKEN={tok}")
            seen.add("QWB_TOKEN")
        else:
            out.append(ln)
    if "QWB_TOKEN" not in seen:
        out.append(f"QWB_TOKEN={tok}")
    CREDS.parent.mkdir(parents=True, exist_ok=True)
    CREDS.write_text("\n".join(out).rstrip("\n") + "\n", encoding="utf-8")
    os.chmod(CREDS, 0o600)
    print(f"[✓] 已写入 {CREDS}（0600）  QWB_TOKEN={mask(tok)}")
    print("→ 立刻验证： python3 scripts/qwb.py creds")
    return 0


# ---------------------------------------------------------------- CLI

def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="第十届强网杯平台客户端（i春秋）")
    p.add_argument("--k", help="覆盖比赛 url_key")
    p.add_argument("--token", help="覆盖登录 token")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("creds", help="凭据 + 连通性自检")
    sp.set_defaults(fn=cmd_creds)
    sp = sub.add_parser("detail", help="比赛详情")
    sp.set_defaults(fn=cmd_detail)
    sp = sub.add_parser("surplus", help="剩余时间")
    sp.set_defaults(fn=cmd_surplus)
    sp = sub.add_parser("classes", help="题目分类")
    sp.set_defaults(fn=cmd_classes)

    sp = sub.add_parser("team", help="本队状态：info|users|point")
    sp.add_argument("what", nargs="?", default="info", choices=["info", "users", "point"])
    sp.set_defaults(fn=cmd_team)

    sp = sub.add_parser("notice", help="比赛公告（容器数量等官方口径）")
    sp.add_argument("--type", type=int, default=1)
    sp.add_argument("--limit", type=int, default=20)
    sp.set_defaults(fn=cmd_notice)

    sp = sub.add_parser("list", help="题目清单")
    sp.add_argument("--raw", action="store_true", help="打印原始回包")
    sp.add_argument("--data", help="直接给 payload JSON")
    sp.set_defaults(fn=cmd_list)

    sp = sub.add_parser("get", help="单题详情/拉附件")
    sp.add_argument("id")
    sp.add_argument("--page", type=int, default=1)
    sp.add_argument("--data", help="题目列表 payload JSON")
    sp.add_argument("--download", action="store_true", help="把题面里的 http 链接拉到 firmware/")
    sp.set_defaults(fn=cmd_get)

    sp = sub.add_parser("submit", help="提交 flag（门禁 + 台账）")
    sp.add_argument("id")
    sp.add_argument("flag")
    sp.add_argument("--via", default="red", choices=["red", "flag", "against"],
                    help="red=答题页真实路径(默认) / flag=/match/flag/submit / against=批量")
    sp.add_argument("--force", action="store_true", help="绕过本地闸门（父代理/人类专用）")
    sp.add_argument("--body", help="原样重放：浏览器抓到的真实请求体 JSON（可用 __FLAG__ 占位符）")
    sp.add_argument("--path", help="配合 --body 指定端点（默认 /match/red/submit）")
    sp.set_defaults(fn=cmd_submit)

    sp = sub.add_parser("docker", help="容器（默认拒绝，走 container-pool.py）")
    sp.add_argument("action", choices=["info", "apply", "close", "log"])
    sp.add_argument("id", nargs="?", default="")
    sp.add_argument("--uuid", default="")
    sp.add_argument("--close-type", default="1")
    sp.set_defaults(fn=cmd_docker)

    sp = sub.add_parser("call", help="调试：任意端点")
    sp.add_argument("path")
    sp.add_argument("body", nargs="?", default="{}")
    sp.set_defaults(fn=cmd_call)

    sp = sub.add_parser("log", help="提交台账")
    sp.set_defaults(fn=cmd_log)
    sp = sub.add_parser("set-token", help="从 stdin 读 token 写 creds.env")
    sp.set_defaults(fn=cmd_set_token)

    args = p.parse_args(argv)
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
