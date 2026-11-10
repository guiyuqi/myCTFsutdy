#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""羊城杯（DASCTF / slab-match）平台客户端。

⚠️ **端点前缀是"参考"，不是永久规则**：`/slab-match/api/v1` 里的 `slab-match`
   是**本场（match 1750）专属 slug**。换一场比赛、甚至换一个分组（ycb-dz/qy/gz）几乎肯定不同。
   开赛先用 `python3 scripts/ycb.py creds` 回源复核；前缀不符时用 `--api` 或 `YCB_API` 覆盖。
   **不要因为 404/非 00000 就判定"平台没这个功能 / 题目不可解"** —— 那是本场 5 次假结论的同一类错误。
   （依据：2026-10-23 对本场 app.js 的静态逆向，来源 notes/methods/platform-ycb-bk.dasctf.com.md）

平台事实来自 2026-10-23 对 app.js 的静态逆向 + 未授权探测（见 notes/methods/platform-ycb-bk.dasctf.com.md）：
  - API 前缀      : https://ycb-bk.dasctf.com/slab-match/api/v1/
  - 鉴权          : 请求头 authorization: <token>（浏览器 localStorage 的 jwtToken / cookie Authorization）
                    请求头 matchId: <competeCode>（本站 = 1750）
  - 成功码        : code == "00000"；未登录 → {"code":"40401","message":"未能读取到有效Token"}
  - 提交          : POST player/answer-panel/answer  {matchId, exerciseId, flag}
                    随后 GET player/answer-panel/monitor-answer-result {matchId, eventId, stageId} 取分数
  - 题目列表      : GET player/ctf/exercise-list {matchId, stageId}
  - 题目详情      : GET player/ctf/exercise {matchId, exerciseId, stageId}
  - 容器          : POST player/ctf/build-exercise-env {exerciseId, stageId}
                    GET  player/ctf/check-exercise-env  {exerciseId, stageId}
                    POST player/ctf/expire-exercise-env {stageId, exerciseId}

平台规则：每题最多 50 次提交（本客户端硬编码同样上限，并在 45 次时告警）。
本地纪律：同题同 flag 不重复提交；提交串行化（flock）+ 间隔限速；全部记账到 evidence/submit-log.jsonl。

用法：
  python3 scripts/ycb.py creds               # 凭据状态 + 鉴权连通性（脱敏）
  python3 scripts/ycb.py stages              # 拿 stageId（比赛阶段）
  python3 scripts/ycb.py list                # 题目清单
  python3 scripts/ycb.py detail <id>         # 题目详情（含附件/靶机信息）
  python3 scripts/ycb.py download <id>       # 拉附件到 firmware/<id>_<slug>/
  python3 scripts/ycb.py env start|status|stop <id>
  python3 scripts/ycb.py submit <id> '<flag>'
  python3 scripts/ycb.py notice              # 公告
  python3 scripts/ycb.py watch --interval 20 # 新题发现
  python3 scripts/ycb.py log                 # 提交台账
  python3 scripts/ycb.py probe               # 调试：只读端点原始响应（首次接平台用）
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

WS = Path(__file__).resolve().parent.parent
CREDS = Path(os.environ.get("CTF_CREDS", Path.home() / ".config" / "ctf" / "creds.env"))
# ⚠️ 比赛/分组专属：`slab-match` 是本场 slug。换场次用 --api 或 YCB_API 覆盖（见文件头）。
API = (os.environ.get("YCB_API") or "/slab-match/api/v1").strip().rstrip("/")
if API and not API.startswith("/"):
    API = "/" + API
LAST_URL = ""   # 最近一次请求的完整 URL；仅用于错误信息（区分"路径写错"与"功能不存在"）

LOG = Path(os.environ.get("YCB_SUBMIT_LOG", WS / "evidence" / "submit-log.jsonl"))
LOCK = WS / "work" / ".submit.lock"
STAGE_CACHE = WS / "work" / ".stage.json"
DEFAULT_BASE = "https://ycb-bk.dasctf.com"
DEFAULT_MATCH = "1750"
MAX_SUBMIT = 50
WARN_SUBMIT = 45
# ---- 门禁（L2：失败关闭）
GATE_TOKEN = WS / "work" / ".submit-token.json"   # verify-flag.py check 产出，一次性
GATE_OVERRIDE = WS / "work" / ".gate-override"    # 破窗：首行写理由，门禁放行并记账
GATE_LOG = WS / "evidence" / "gate-log.jsonl"
TOKEN_TTL = 300                                    # 票有效期（秒）


# ---------------------------------------------------------------- 凭据与配置

def load_creds() -> dict:
    d: dict[str, str] = {}
    if CREDS.exists():
        for ln in CREDS.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln or ln.startswith("#") or "=" not in ln:
                continue
            k, _, v = ln.partition("=")
            d[k.strip()] = v.strip().strip('"').strip("'")
    return d


def cfg(args) -> dict:
    global API
    c = load_creds()
    # API 前缀优先级：--api > YCB_API(已在模块加载时生效) > creds 的 CTF_API > 本场默认
    api = (getattr(args, "api", None) or c.get("CTF_API") or "").strip()
    if api:
        api = api.rstrip("/")
        API = api if api.startswith("/") else "/" + api
    base = (getattr(args, "base", None) or c.get("CTFD_BASE") or DEFAULT_BASE).rstrip("/")
    token = (getattr(args, "token", None) or c.get("CTFD_TOKEN") or c.get("MATCH_TOKEN") or "").strip()
    # 该平台 SPA 发的是 "Bearer <jwt>"（localStorage 里就带前缀）。
    # 兼容三种常见脏值：裸 JWT / "BearereyJ"（丢了空格）/ "Bearer Bearer …"
    if token:
        t = re.sub(r"\s+", "", token)
        while t.lower().startswith("bearer"):
            t = t[6:]
        token = "Bearer " + t
    match = str(getattr(args, "match", None) or c.get("MATCH_ID") or DEFAULT_MATCH)
    stage = str(getattr(args, "stage", None) or c.get("STAGE_ID") or "")
    return {"base": base, "token": token, "match": match, "stage": stage}


# ---------------------------------------------------------------- HTTP

def http(method: str, path: str, *, conf: dict, params=None, body=None,
         timeout=30, raw=False):
    global LAST_URL
    url = conf["base"] + path
    if params:
        params = {k: v for k, v in params.items() if v not in (None, "")}
        if params:
            url += "?" + urllib.parse.urlencode(params)
    LAST_URL = url
    headers = {
        "accept": "application/json, text/plain, */*",
        "authorization": conf["token"],
        "matchid": conf["match"],
        "origin": conf["base"],
        "referer": f'{conf["base"]}/compete/{conf["match"]}/detail',
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/140.0 Safari/537.36",
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["content-type"] = "application/json;charset=UTF-8"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    last_exc = None
    for attempt in range(5):                     # 开赛瞬间平台会 RST/超时，重试是必须的
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw_body = r.read()
                ctype = r.headers.get("content-type", "")
                rheaders = dict(r.headers)
            break
        except urllib.error.HTTPError as e:
            raw_body = e.read()
            ctype = e.headers.get("content-type", "")
            rheaders = dict(e.headers)
            if e.code in (401, 403):
                raise SystemExit(f"[!] HTTP {e.code} 鉴权失败：token 可能过期/不属于本组。"
                                 f"响应：{raw_body[:300].decode('utf-8', 'replace')}")
            break
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            last_exc = e
            time.sleep(1 + attempt * 1.5)
    else:
        raise SystemExit(f"[!] 网络失败（重试 5 次）：{last_exc}（平台可能被打满，稍等再试）")

    if raw:
        return {"_raw": raw_body, "_ctype": ctype, "_headers": rheaders}
    # 平台会把 JSON 错误体回成 text/plain（实测 40401 就是），所以不看 content-type，先试着解析
    try:
        js = json.loads(raw_body.decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"_raw": raw_body[:4000], "_ctype": ctype, "_headers": rheaders}
    return js


def unwrap(js, what=""):
    """校验 code=00000；返回 data（可能是 dict 或 JSON 字符串）。

    报错时一律带上"实际请求的 URL"——换场次后 slug 变了会对所有端点 404，
    没有 URL 就很容易把"路径写错"误判成"平台没这个功能/题目不可解"。
    """
    if not isinstance(js, dict):
        raise SystemExit(f"[!] {what} 返回非 JSON 对象：{str(js)[:200]}\n"
                         f"    实际请求: {LAST_URL}\n"
                         f"    → 若这是 HTML/404，先复核 API 前缀（当前 {API}）：换场次时 slug 会变，用 --api / YCB_API 覆盖")
    code = str(js.get("code", ""))
    if code != "00000":
        msg = js.get("message") or js.get("msg") or ""
        if code == "40401":
            raise SystemExit(f"[!] 未登录/Token 无效（40401: {msg}）→ 跑 scripts/set-token.sh 重贴 token\n"
                             f"    实际请求: {LAST_URL}")
        raise SystemExit(f"[!] {what} 失败 code={code} message={msg}\n"
                         f"    实际请求: {LAST_URL}\n"
                         f"    → 若为 404/非 00000，先复核 API 前缀（当前 {API}）：换场次时 slug 会变，用 --api / YCB_API 覆盖")
    return parse_maybe_json(js.get("data"))


def parse_maybe_json(d):
    if isinstance(d, str):
        s = d.strip()
        if s[:1] in "[{":
            try:
                return json.loads(s)
            except json.JSONDecodeError:
                return d
    return d


# ---------------------------------------------------------------- 阶段 / 列表

def resolve_stages(conf: dict, quiet=False):
    """拿阶段：info-list 给 name/startTime/endTime，status-list 给 status/countdown。
    2026-10-23 实测真实形状：
      info-list   → [{"id":3241,"name":"CTF夺旗赛","startTime":...,"endTime":...,"mode":"CTF"}]
      status-list → [{"id":3241,"status":"PENDING","startCountdown":46797}]
    ★ 不做磁盘缓存（曾被 mock 数据污染过；多一次请求换正确性）。
    """
    info, status = [], []
    try:
        js = http("GET", f"{API}/player/stage/info-list", conf=conf,
                  params={"matchId": conf["match"]})
        d = unwrap(js, "stage/info-list")
        info = d if isinstance(d, list) else (d.get("list") if isinstance(d, dict) else []) or []
    except SystemExit as e:
        if not quiet:
            print(f"[i] info-list 失败：{e}", file=sys.stderr)
    try:
        js = http("GET", f"{API}/player/stage/status-list", conf=conf,
                  params={"matchId": conf["match"], "relationId": conf["match"],
                          "relationType": "slab-match"})
        d = unwrap(js, "stage/status-list")
        status = d if isinstance(d, list) else (d.get("list") if isinstance(d, dict) else []) or []
    except SystemExit as e:
        if not quiet:
            print(f"[i] status-list 失败：{e}", file=sys.stderr)

    by_id: dict[str, dict] = {}
    for it in status:
        if isinstance(it, dict) and it.get("id") is not None:
            sid = str(it["id"])
            by_id[sid] = {"id": sid, "name": "", "status": it.get("status", ""),
                          "countdown": it.get("startCountdown"), "start": None, "end": None,
                          "mode": "", "raw": it}
    for it in info:
        if isinstance(it, dict) and it.get("id") is not None:
            sid = str(it["id"])
            rec = by_id.setdefault(sid, {"id": sid, "status": "", "raw": it})
            rec.update({"name": it.get("name", ""), "mode": it.get("mode", ""),
                        "start": it.get("startTime"), "end": it.get("endTime")})
    stages = [v for v in by_id.values() if v["id"]]
    if not stages:
        raise SystemExit("[!] 拿不到 stageId（info-list/status-list 都空）。可 --stage <id> 手动指定。")
    if not quiet:
        for st in stages:
            cd = st.get("countdown")
            cd_s = f"，倒计时 {cd}s（≈{cd/3600:.1f}h）" if isinstance(cd, (int, float)) and cd else ""
            print(f'[+] 阶段 {st["id"]} 「{st["name"] or "?"}」 status={st["status"] or "?"}{cd_s}',
                  file=sys.stderr)
    return stages


def ensure_stage(conf: dict) -> str:
    if conf["stage"]:
        return conf["stage"]
    stages = resolve_stages(conf, quiet=True)
    # 优先 RUNNING/STARTED 的，否则取第一个（未开赛时是 PENDING，题目列表会空，正常）
    run = [s for s in stages if str(s.get("status", "")).upper() in
           ("RUNNING", "STARTED", "START", "OPEN", "PROCESSING", "UNDERWAY")]
    pick = run[0] if run else stages[0]
    conf["stage"] = pick["id"]
    return pick["id"]


OPEN_STATES = ("RUNNING", "STARTED", "START", "OPEN", "PROCESSING", "UNDERWAY")


def stage_info(conf: dict, sid: str) -> dict:
    for st in resolve_stages(conf, quiet=True):
        if st["id"] == sid:
            return st
    return {}


def assert_stage_open(conf: dict, sid: str):
    """★ 2026-10-23 实测：开赛前拉 exercise-list 会返回
    `阶段未开始无法获取赛题列表，用户非法请求赛题列表已记录`。
    所以未开赛一律不打这个端点（连 watch 也不许），只轮询 stage 状态。"""
    st = stage_info(conf, sid)
    status = str(st.get("status", "")).upper()
    if status and status not in OPEN_STATES:
        cd = st.get("countdown")
        cd_s = f"（倒计时 {cd}s ≈ {cd/60:.0f} 分钟）" if isinstance(cd, (int, float)) and cd else ""
        raise SystemExit(f"[!] 阶段 {sid} 当前 {status}：**未开赛**，平台会把拉题记为非法请求，"
                         f"已阻止本次调用{cd_s}。开赛后重跑；或 `watch` 让它自己等。")


def norm_challenges(data) -> list[dict]:
    """把 exercise-list 的结果归一化。字段名按实际返回做兼容。"""
    if isinstance(data, dict):
        for k in ("list", "tbody", "records", "items", "exerciseList", "data"):
            if isinstance(data.get(k), list):
                data = data[k]
                break
    if not isinstance(data, list):
        return []
    out = []
    for it in data:
        if not isinstance(it, dict):
            continue
        # 分组结构（area → children）
        # 真实结构（2026-10-24 实测）：[{id, name:"WEB", order, corpus:[{id,name,order,isOpen,hasSolved}]}]
        for gkey in ("corpus", "exerciseList"):
            if isinstance(it.get(gkey), list) and it[gkey]:
                for ch in it[gkey]:
                    if isinstance(ch, dict):
                        ch = dict(ch)
                        ch["_group"] = it.get("name") or it.get("groupName") or ""
                        out.append(ch)
                break
        else_keys = None
        if isinstance(it.get("corpus"), list):
            continue
        if isinstance(it.get("children"), list) and it["children"]:
            for ch in it["children"]:
                if isinstance(ch, dict):
                    out.append(ch)
            continue
        out.append(it)
    norm = []
    for it in out:
        cid = (it.get("exerciseId") or it.get("corpusId") or it.get("topicId")
               or it.get("id"))
        mine = it.get("hasSolved")
        if mine is None:
            mine = it.get("isSolved")
        norm.append({
            "id": str(cid) if cid is not None else "",
            "name": (it.get("name") or it.get("title") or it.get("topicName")
                     or it.get("exerciseName") or ""),
            "category": (it.get("_group") or it.get("corpusClassify") or it.get("classify")
                         or it.get("type") or it.get("classifyName") or ""),
            "difficulty": (it.get("corpusDifficulty") or it.get("difficulty")
                           or it.get("difficultyName") or ""),
            "score": (it.get("score") or it.get("integral") or it.get("currentScore")
                      or it.get("originScore") or ""),
            "solved": (it.get("solvedCount") or it.get("solveCount")
                       or it.get("answerCount") or it.get("solvedNum") or ""),
            "mine": "✓" if mine else "",
            "isOpen": it.get("isOpen", ""),
            "open": it.get("isOpen", ""),
            "status": (it.get("status") or it.get("answerStatus")
                       or it.get("exerciseStatus") or ""),
            "raw": it,
        })
    return norm


def cmd_list(args):
    conf = cfg(args)
    sid = ensure_stage(conf)
    assert_stage_open(conf, sid)
    js = http("GET", f"{API}/player/ctf/exercise-list", conf=conf,
              params={"matchId": conf["match"], "stageId": sid})
    data = unwrap(js, "exercise-list")
    raw_path = WS / "work" / "triage-raw.json"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    rows = norm_challenges(data)
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0
    if not rows:
        print(f"[!] 没有题目（阶段 {sid}）。比赛未开始/未到本阶段是正常的。")
        print("    原始响应已可加 --json 查看。")
        return 0
    rows.sort(key=lambda r: (str(r["category"]), str(r["name"])))
    print(f"# 题目清单（match={conf['match']} stage={sid}，共 {len(rows)} 题）\n")
    print("| id | 名称 | 分类 | 难度 | 分值 | 解出 | 我 | 状态 |")
    print("|---|---|---|---|---|---|---|---|")
    for r in rows:
        print(f"| {r['id']} | {r['name']} | {r['category']} | {r['difficulty']} | "
              f"{r['score']} | {r['solved']} | {r.get('mine', '')} | {r['status']} |")
    print(f"\n> 原始 JSON: {raw_path}（结构不符预期时按它微调 norm_challenges）")
    return 0


def cmd_detail(args):
    conf = cfg(args)
    sid = ensure_stage(conf)
    js = http("GET", f"{API}/player/ctf/exercise", conf=conf,
              params={"matchId": conf["match"], "exerciseId": args.id, "stageId": sid})
    data = unwrap(js, "exercise")
    d = WS / "work" / f"ch_{args.id}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "detail.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0
    it = data if isinstance(data, dict) else {}
    print(f"# {it.get('name') or it.get('title') or ('题 ' + args.id)}")
    for k in ("corpusClassify", "corpusDifficulty", "score", "solvedCount", "status",
              "answerModel", "flagType", "attachmentCode", "relatedSceneVersion", "endpointType"):
        if it.get(k) not in (None, "", [], {}):
            print(f"- {k}: {it.get(k)}")
    desc = it.get("description") or ""
    if desc:
        print("\n## 描述\n")
        print(desc)
    print(f"\n> 原始 JSON: {d / 'detail.json'}")
    return 0


# ---------------------------------------------------------------- 下载

def cmd_download(args):
    conf = cfg(args)
    sid = ensure_stage(conf)
    js = http("GET", f"{API}/player/ctf/exercise", conf=conf,
              params={"matchId": conf["match"], "exerciseId": args.id, "stageId": sid})
    data = unwrap(js, "exercise")
    it = data if isinstance(data, dict) else {}
    name = it.get("name") or f"ch{args.id}"
    slug = re.sub(r"[^\w\u4e00-\u9fff.-]+", "_", str(name))[:40]
    out = WS / "firmware" / f"{args.id}_{slug}"
    out.mkdir(parents=True, exist_ok=True)

    saved = []
    # 0) 首选：detail.attachment.url（OSS 直链，2026-10-24 实测可用；ctf-download 会报"无此权限"）
    att = it.get("attachment") if isinstance(it, dict) else None
    if isinstance(att, dict) and att.get("url"):
        url = att["url"]
        fname = att.get("name") or os.path.basename(urllib.parse.urlparse(url).path) or "attachment.bin"
        try:
            with urllib.request.urlopen(url, timeout=600) as r:
                p2 = out / fname
                with p2.open("wb") as f:
                    while True:
                        chunk = r.read(1 << 20)
                        if not chunk:
                            break
                        f.write(chunk)
            saved.append(p2)
            print(f"[+] {p2}  ({p2.stat().st_size} B)  ← attachment.url")
        except Exception as e:  # noqa: BLE001
            print(f"[i] attachment.url 下载失败：{type(e).__name__}: {e}", file=sys.stderr)

    # 1) 再试 ctf-download（平台自带打包下载；部分赛制无权限）
    try:
        r = http("POST", f"{API}/exercise/ctf-download", conf=conf,
                 body={"matchId": conf["match"], "exerciseId": args.id, "stageId": sid},
                 timeout=1800, raw=True)
        if "_raw" in r and r["_raw"]:
            ctype = r.get("_ctype", "")
            if "json" in ctype:
                js2 = json.loads(r["_raw"].decode("utf-8", "replace"))
                print("[i] ctf-download 返回 JSON：", json.dumps(js2, ensure_ascii=False)[:400])
            else:
                fname = "attachment.bin"
                cd = r["_headers"].get("content-disposition", "") or r["_headers"].get("Content-Disposition", "")
                m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)', cd)
                if m:
                    fname = urllib.parse.unquote(m.group(1))
                p = out / fname
                p.write_bytes(r["_raw"])
                saved.append(p)
    except SystemExit as e:
        print(f"[i] ctf-download 不可用：{e}", file=sys.stderr)

    # 2) 详情里出现的附件引用（url / oss / file）
    for k, v in (it.items() if isinstance(it, dict) else []):
        if not isinstance(v, str) or len(v) < 8:
            continue
        if not re.search(r"attach|file|download|\.zip|\.rar|\.tar|\.7z|/oss/|http", str(k) + " " + v, re.I):
            continue
        if v.startswith("http"):
            try:
                with urllib.request.urlopen(v, timeout=120) as r:
                    fname = os.path.basename(urllib.parse.urlparse(v).path) or f"{k}.bin"
                    p = out / fname
                    p.write_bytes(r.read())
                    saved.append(p)
            except Exception as e:  # noqa: BLE001
                print(f"[i] 直链下载失败 {k}: {e}", file=sys.stderr)

    if saved:
        for p in saved:
            print(f"[+] {p}  ({p.stat().st_size} B)")
    else:
        print(f"[!] 没拉到附件。详情字段：{sorted(it.keys())}")
        print(f"    原始 JSON 见 work/ch_{args.id}/detail.json（attachmentCode={it.get('attachmentCode')}）")
    return 0


# ---------------------------------------------------------------- 提交

def read_log() -> list[dict]:
    if not LOG.exists():
        return []
    out = []
    for ln in LOG.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            pass
    return out


def append_log(rec: dict):
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _gate_log(event: str, **kw) -> None:
    """门禁放行/拒绝都记一笔，便于赛后审计。"""
    try:
        GATE_LOG.parent.mkdir(parents=True, exist_ok=True)
        rec = {"time": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
               "event": event, **kw}
        with GATE_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def require_submit_token(cid: str, flag: str) -> None:
    """提交门：必须持有 verify-flag.py 产出的一次性票，否则拒绝。

    这是 L2「失败关闭」——不靠提示词，直接让默认路径跑不通。
    破窗：work/.gate-override 存在时放行，但会打警告 + 记账。
    """
    import hashlib as _h

    if GATE_OVERRIDE.exists():
        reason = ""
        try:
            reason = GATE_OVERRIDE.read_text(encoding="utf-8").splitlines()[0][:120]
        except OSError:
            pass
        print(f"[!] 门禁破窗：{GATE_OVERRIDE} 存在（理由：{reason or '未写'}）→ 放行",
              file=sys.stderr)
        _gate_log("submit_override", id=str(cid), flag_sha=_h.sha256(flag.encode()).hexdigest()[:16],
                  reason=reason)
        return

    want = _h.sha256(flag.encode()).hexdigest()
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
    if t.get("flag_sha256") != want:
        raise SystemExit(
            "[2] 票与 flag 不符：verify-flag.py check 时用的 flag 不是这个。\n"
            "    （这是故意设计的：票绑定具体串，防止「过了闸门再换 flag」）")
    age = time.time() - float(t.get("ts") or 0)
    if age > TOKEN_TTL:
        raise SystemExit(f"[2] 票已过期（{int(age)}s > {TOKEN_TTL}s），重新跑 verify-flag.py check")
    ev = Path(str(t.get("evidence") or ""))
    if not str(ev) or not ev.exists():
        raise SystemExit(f"[2] 票里的证据 artifact 不存在：{ev}")

    GATE_TOKEN.unlink(missing_ok=True)          # 一次性：消费掉，防复用
    _gate_log("submit_token_ok", id=str(cid), flag_sha=want[:16],
              evidence=str(ev), age=int(age))
    print(f"[+] 门禁放行（票有效 {int(age)}s，证据 {ev}）", file=sys.stderr)


def cmd_submit(args):
    conf = cfg(args)
    sid = ensure_stage(conf)
    flag = args.flag.strip()
    if not flag:
        raise SystemExit("[!] flag 为空")
    # ★ 2026-10-24 实测：平台只接受 {} 内的内容（提交 flag{xxx} 会 40001）。
    # 这里自动剥壳并记下原串，避免队友把整串提交浪费额度。
    raw_flag = flag
    m = re.fullmatch(r"(?i)(flag|dasctf|ycb|ctfshow|flag\w*)\{([^{}]*)\}", flag)
    if m:
        flag = m.group(2)
        print(f"[i] 已自动剥壳：{raw_flag} → 提交内容 {flag}", file=sys.stderr)

    # ★ 门禁：必须是 verify-flag.py 放行过的那个串
    require_submit_token(args.id, flag)

    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open("w") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)          # 多子代理串行，避免并发烧额度
        all_recs = [r for r in read_log() if str(r.get("id")) == str(args.id)]
        # 传输失败（没到平台）不计入额度，也不参与"同 flag 已提过"的判定
        recs = [r for r in all_recs if r.get("transport") != "error"]
        if args.force:
            print("[!] --force：绕过本地闸门（只有父代理/人类该用）", file=sys.stderr)
            recs_for_guard = []
        else:
            recs_for_guard = recs
        ok = [r for r in recs_for_guard if r.get("result") is True]
        if ok:
            prev = ok[-1].get("flag", "")
            if prev == flag:
                print(f"[=] 该题已用这个 flag 提交成功过，跳过（不占额度）")
                return 0
            raise SystemExit(f"[!] 该题已解出（flag={prev}），拒绝提交不同的 flag"
                             f"（确需强推：--force）")
        if len(recs_for_guard) >= MAX_SUBMIT:
            raise SystemExit(f"[!] 该题已提交 {len(recs)} 次，达到平台上限 {MAX_SUBMIT}，停止。")
        if len(recs_for_guard) >= WARN_SUBMIT:
            print(f"[!] 警告：该题已提交 {len(recs_for_guard)} 次（上限 {MAX_SUBMIT}），"
                  f"只剩 {MAX_SUBMIT - len(recs_for_guard)} 次。", file=sys.stderr)
        same = [r for r in recs_for_guard if r.get("flag") == flag]
        if same:
            print(f"[=] 同一 flag 已提交过（{same[-1].get('time')}），跳过（不占额度）")
            return 0

        body = {"matchId": conf["match"], "exerciseId": str(args.id), "flag": flag}
        rec = {"time": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
               "id": str(args.id), "flag": flag, "raw_flag": raw_flag,
               "agent": os.environ.get("CTF_AGENT", "parent"), "stage": sid}
        try:
            js = http("POST", f"{API}/player/answer-panel/answer", conf=conf, body=body)
        except SystemExit as e:
            rec.update({"result": None, "message": str(e), "transport": "error"})
            append_log(rec)
            raise
        rec["resp_code"] = str(js.get("code", ""))
        rec["message"] = js.get("message") or js.get("msg") or ""
        data = parse_maybe_json(js.get("data"))
        rec["data"] = data
        # 判定顺序很重要：data.result 显式为 false 就是错，不要被后续轮询覆盖；
        # 只有"没说对错但有 eventId"时才查 monitor-answer-result 确认。
        # 平台语义（2026-10-24 实测）：
        #   错 flag → code=40001 "提交flag错误，请重新提交（当前还有49次提交机会）"
        #   ⇒ code != 00000 就是**明确错误**，不能因为 data 空而当成"未判定"
        verdict = None
        eid = None
        if rec["resp_code"] and rec["resp_code"] != "00000":
            verdict = False
        if isinstance(data, dict):
            # 平台成功体实际是 {"isCorrect":true,"correct":true,"eventId":…}，没有 result 字段
            if data.get("result") is True or data.get("isCorrect") is True or data.get("correct") is True:
                verdict = True
            elif data.get("result") is False or data.get("isCorrect") is False:
                verdict = False
            eid = data.get("eventId")
        if verdict is not True and eid:
            try:
                mon = http("GET", f"{API}/player/answer-panel/monitor-answer-result",
                           conf=conf, params={"matchId": conf["match"],
                                              "eventId": eid, "stageId": sid})
                md = unwrap(mon, "monitor-answer-result")
                rec["monitor"] = md
                if isinstance(md, dict):
                    if md.get("result") is True or md.get("score") not in (None, "", 0):
                        verdict = True
                    elif md.get("result") is False:
                        verdict = False
            except SystemExit as e:
                rec["monitor_error"] = str(e)
        rec["result"] = verdict
        append_log(rec)
        print(json.dumps({"code": rec["resp_code"], "message": rec["message"],
                          "result": rec["result"], "data": data}, ensure_ascii=False, indent=2))
        if verdict is True:
            print("[✓] 判定：正确", file=sys.stderr)
            return 0
        if verdict is False:
            print("[✗] 判定：错误（flag 不对，或该题有动态判定）", file=sys.stderr)
            return 1
        print("[?] 判定：平台已受理但未给出对错（有 eventId，分数待出）。"
              "不要重复提交，等 5–10 秒再查或问父代理。", file=sys.stderr)
        return 2


# ---------------------------------------------------------------- 容器

def cmd_env(args):
    # ★ 门禁：容器只能由 container-pool.py 管理（唯一写者）。
    if os.environ.get("YCB_ALLOW_ENV") != "1" and not GATE_OVERRIDE.exists():
        raise SystemExit(
            "[2] 容器操作被门禁拒绝：请用唯一写者\n"
            f"    python3 scripts/container-pool.py acquire <题号>\n"
            f"    python3 scripts/container-pool.py release <题号>\n"
            "    （直接 env 会让多个代理互踩槽位；确需绕过：work/.gate-override）")
    conf = cfg(args)
    sid = ensure_stage(conf)
    if args.action == "start":
        js = http("POST", f"{API}/player/ctf/build-exercise-env", conf=conf,
                  body={"matchId": conf["match"], "exerciseId": str(args.id), "stageId": sid},
                  timeout=120)
        print(json.dumps(js, ensure_ascii=False, indent=2))
    elif args.action == "status":
        js = http("GET", f"{API}/player/ctf/check-exercise-env", conf=conf,
                  params={"exerciseId": str(args.id), "stageId": sid})
        print(json.dumps(js, ensure_ascii=False, indent=2))
    elif args.action == "stop":
        # ★ 前端语义（2026-10-24 实测更正）：
        #   destoryEndpoint（销毁）→ recoverCTFBreakScene → POST player/ctf/recover-exercise-env
        #   delayEndpoint（续期）  → expireCTFBreakScene  → POST player/ctf/expire-exercise-env
        js = http("POST", f"{API}/player/ctf/recover-exercise-env", conf=conf,
                  body={"stageId": sid, "exerciseId": str(args.id)})
        print(json.dumps(js, ensure_ascii=False, indent=2))
    elif args.action == "delay":
        js = http("POST", f"{API}/player/ctf/expire-exercise-env", conf=conf,
                  body={"stageId": sid, "exerciseId": str(args.id)})
        print(json.dumps(js, ensure_ascii=False, indent=2))
    else:
        raise SystemExit("action 只能是 start|status|stop")
    return 0


# ---------------------------------------------------------------- 其它

def cmd_notice(args):
    conf = cfg(args)
    js = http("GET", f"{API}/player/match/notice/now-list", conf=conf,
              params={"matchId": conf["match"]})
    data = unwrap(js, "notice/now-list")
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


def cmd_watch(args):
    conf = cfg(args)
    sid = ensure_stage(conf)
    print(f"[*] watch：match={conf['match']} stage={sid}", file=sys.stderr)

    # 阶段 1：等开赛（只轮询 stage 状态，绝不打 exercise-list）
    while True:
        st = stage_info(conf, sid)
        status = str(st.get("status", "")).upper()
        if status in OPEN_STATES:
            print(f"[*] 阶段已开始（{status}），转入题目轮询", file=sys.stderr)
            break
        cd = st.get("countdown")
        cd_s = f"{cd/60:.0f} 分钟" if isinstance(cd, (int, float)) and cd else "未知"
        wait = 10 if isinstance(cd, (int, float)) and 0 < cd <= 180 else 60
        print(f"[*] 未开赛（{status or '?'}），还剩 {cd_s}；{wait}s 后再看", file=sys.stderr)
        time.sleep(wait)

    # 阶段 2：按平台建议的 exerciseListInterval（实测 10s）轮询
    seen: set[str] = set()
    while True:
        try:
            js = http("GET", f"{API}/player/ctf/exercise-list", conf=conf,
                      params={"matchId": conf["match"], "stageId": sid})
            rows = norm_challenges(unwrap(js, "exercise-list"))
        except SystemExit as e:
            print(f"[!] {e}", file=sys.stderr)
            rows = []
        for r in rows:
            if r["id"] and r["id"] not in seen:
                seen.add(r["id"])
                print(f"NEW\t{r['id']}\t{r['name']}\t{r['category']}\t{r['score']}", flush=True)
        time.sleep(min(args.interval, 10) if args.interval else 10)


def cmd_log(args):
    recs = read_log()
    for r in recs:
        if str(r.get("resp_code", "")) not in ("", "00000") and r.get("result") is None:
            r["result"] = False
    by: dict[str, list[dict]] = {}
    for r in recs:
        by.setdefault(str(r.get("id")), []).append(r)
    print(f"# 提交台账（{LOG}，共 {len(recs)} 条 / {len(by)} 题）\n")
    print("| 题 | 次数 | 结果 | 最近时间 | flag |")
    print("|---|---|---|---|---|")
    for cid, rs in sorted(by.items()):
        ok = [r for r in rs if r.get("result") is True]
        wrong = [r for r in rs if str(r.get("resp_code", "")) not in ("", "00000") and r.get("result") is None]
        if wrong and not ok:
            for r in wrong:
                r["result"] = False
        if ok:
            res = "✅ 通过"
        elif any(r.get("transport") == "error" for r in rs) and all(r.get("result") is None for r in rs):
            res = "↯ 传输失败（不计额度）"
        elif any(r.get("result") is False for r in rs):
            res = "⚠️ 未通过"
        else:
            res = "?"
        last = rs[-1]
        print(f"| {cid} | {len(rs)}/{MAX_SUBMIT} | {res} | {last.get('time', '')} | "
              f"`{(ok[-1] if ok else last).get('flag', '')[:60]}` |")
    return 0


def cmd_stages(args):
    conf = cfg(args)
    stages = resolve_stages(conf)
    print(json.dumps(stages, ensure_ascii=False, indent=2))
    return 0


PII_KEYS = {"phone", "idCard", "idcard", "email", "loginIp", "loginip", "password",
            "realname", "mobile", "address"}


def scrub_pii(obj):
    """落盘前脱敏：选手手机号/身份证/邮箱/登录 IP 不能进工作区。"""
    if isinstance(obj, dict):
        return {k: ("<REDACTED>" if k in PII_KEYS and v not in (None, "", [], {}) else scrub_pii(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub_pii(x) for x in obj]
    return obj


def cmd_probe(args):
    """只读端点原始响应：首次接平台时看清真实字段（不做任何写操作）。"""
    conf = cfg(args)
    if not conf["token"]:
        raise SystemExit("[!] 没有 token，先跑 scripts/set-token.sh")
    out = WS / "evidence" / f"probe-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    res: dict[str, object] = {}
    sid = ""
    for path, params in [
        ("player/stage/status-list", {"matchId": conf["match"], "relationId": conf["match"],
                                      "relationType": "slab-match"}),
        ("player/stage/info-list", {"matchId": conf["match"]}),
        ("player/match-stage/console/bootstrap", {"matchId": conf["match"]}),
        ("player/answer-panel/overview", {"matchId": conf["match"]}),
        ("player/match/user/detail", {"matchId": conf["match"]}),
        ("player/match/team/detail", {"matchId": conf["match"]}),
        ("player/match/notice/now-list", {"matchId": conf["match"]}),
    ]:
        try:
            res[path] = http("GET", f"{API}/{path}", conf=conf, params=params)
        except SystemExit as e:
            res[path] = {"_error": str(e)}
        print(f"[probe] {path} → ok", file=sys.stderr)
    # 有 stageId 后再探题目列表
    try:
        stages = resolve_stages(conf, quiet=True)
        sid = conf["stage"] or (stages[-1]["id"] if stages else "")
        if sid:
            for path, params in [
                ("player/answer-panel/overview", {"matchId": conf["match"], "stageId": sid}),
                ("player/ctf/exercise-list", {"matchId": conf["match"], "stageId": sid}),
            ]:
                res[f"{path}?stageId={sid}"] = http("GET", f"{API}/{path}", conf=conf, params=params)
                print(f"[probe] {path} (stage {sid}) → ok", file=sys.stderr)
    except SystemExit as e:
        res["_stage"] = {"_error": str(e)}
    res = scrub_pii(res)
    out.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] 原始响应已存 {out}")
    return 0


def cmd_creds(args):
    conf = cfg(args)
    tok = conf["token"]
    print(f"  凭据文件: {CREDS}  {'存在' if CREDS.exists() else '不存在'}")
    if CREDS.exists():
        print(f"  权限    : {oct(CREDS.stat().st_mode & 0o777)}")
    print(f"  CTFD_BASE  = {conf['base']}")
    print(f"  MATCH_ID   = {conf['match']}")
    print(f"  STAGE_ID   = {conf['stage'] or '（未设置，运行时自动解析）'}")
    print(f"  CTFD_TOKEN = {(tok[:6] + '…' + tok[-4:]) if len(tok) > 12 else '（未设置）'}"
          f"  长度 {len(tok)}")
    if not tok:
        print("\n[!] 没有 token。让人类跑： bash scripts/set-token.sh")
        return 1
    print("\n[*] 鉴权连通性测试（只读）…")
    try:
        js = http("GET", f"{API}/player/match/user/detail", conf=conf,
                  params={"matchId": conf["match"]})
    except SystemExit as e:
        print(f"[!] {e}")
        return 1
    code = str(js.get("code", "")) if isinstance(js, dict) else "?"
    if code == "00000":
        d = parse_maybe_json(js.get("data"))
        name = ""
        if isinstance(d, dict):
            name = d.get("nickname") or d.get("username") or d.get("name") or ""
        print(f"[✓] 鉴权通过（code=00000）{'用户: ' + str(name) if name else ''}")
        return 0
    print(f"[!] 鉴权未通过：code={code} message={js.get('message') if isinstance(js, dict) else js}")
    return 1


# ---------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description="羊城杯 DASCTF 平台客户端")
    ap.add_argument("--base")
    ap.add_argument("--token")
    ap.add_argument("--match")
    ap.add_argument("--stage")
    ap.add_argument("--api", help="API 前缀（默认 /slab-match/api/v1，本场专属；换场次必须覆盖）")
    ap.add_argument("--json", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("creds")
    sub.add_parser("stages")
    sub.add_parser("probe")
    sub.add_parser("notice")
    sub.add_parser("log")

    p = sub.add_parser("list"); p.set_defaults(func=cmd_list)

    p = sub.add_parser("detail")
    p.add_argument("id"); p.set_defaults(func=cmd_detail)

    p = sub.add_parser("download")
    p.add_argument("id"); p.set_defaults(func=cmd_download)

    p = sub.add_parser("submit")
    p.add_argument("id")
    p.add_argument("flag")
    p.add_argument("--force", action="store_true",
                   help="越过本地闸门（已解出冲突/额度用尽）；只有父代理/人类能用")
    p.set_defaults(func=cmd_submit)

    p = sub.add_parser("env")
    p.add_argument("action", choices=["start", "status", "stop", "delay"])
    p.add_argument("id")
    p.set_defaults(func=cmd_env)

    p = sub.add_parser("watch")
    p.add_argument("--interval", type=int, default=20)
    p.set_defaults(func=cmd_watch)

    args = ap.parse_args()
    fn = getattr(args, "func", None)
    if fn is None:
        fn = {"creds": cmd_creds, "stages": cmd_stages, "probe": cmd_probe,
              "notice": cmd_notice, "log": cmd_log}[args.cmd]
    return fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())
