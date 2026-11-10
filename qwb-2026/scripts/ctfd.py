#!/usr/bin/env python3
"""ctfd.py —— CTFd 平台客户端（list / detail / download / start / stop / submit / watch / log）

来源与设计依据
--------------
* **CTFd poller 自动发现**：借自 verialabs/ctf-agent（MIT）——url+token、轮询拉题、
  发现新题即回报，避免"等人类喂题"。见 ~/ctf/AI-AGENT-ECOSYSTEM.md §2.D / §4.3。
* **限速提交 + 滚动日志 + 排队不拒绝**：借自 AGENTS.md「提交纪律」与
  KICKOFF-PROMPT 阶段 3 —— ① 读 evidence/submit-log.jsonl 做滚动 60 秒计数；
  ② 满额时 flock 排队等待而不是拒绝（否则子代理会把限速误判成 flag 错）；
  ③ 每次提交追加一行 JSON。
* 端点：默认按 **CTFd 官方 API v1**；国内平台（DASCTF 等）多数是 CTFd 衍生或自带插件，
  容器接口差异最大 → 用 `--start-path/--stop-path` 或配置文件覆盖，不要改本脚本。

用法（都从工作区根跑）
----------------------
    # 0) 凭据放【工作区外面】的文件里，避免泄漏进 wp.md / notes / 交付物：
    #    ~/.config/ctf/creds.env（本脚本会 chmod 600）
    #    可用键：CTFD_BASE / CTFD_TOKEN / CTFD_COOKIE / CTFD_USER / CTFD_PASS
    python3 scripts/ctfd.py creds                    # 看当前配置（脱敏）
    python3 scripts/ctfd.py login --user <用户名>     # 账号密码 → 自动换 session cookie
    python3 scripts/ctfd.py list
    python3 scripts/ctfd.py detail 12
    python3 scripts/ctfd.py download 12            # 存到 firmware/12_<slug>/
    python3 scripts/ctfd.py start 12               # 起本队容器，回 address
    python3 scripts/ctfd.py stop 12
    python3 scripts/ctfd.py submit 12 'flag{...}'  # 内置限速/排队/日志
    python3 scripts/ctfd.py watch --interval 5     # 轮询发现新题（Ctrl-C 停）
    python3 scripts/ctfd.py log                    # 汇总提交日志

配置优先级：CLI 参数 > 环境变量 > `~/.config/ctf/creds.env`（`--creds` 改路径）> `scripts/ctfd-config.json`。
**凭据绝不写进本工作区**；遇 401/403 时，若 creds 里有 USER/PASS 会**自动重登一次再重试**。
"""
from __future__ import annotations

import argparse
import fcntl
import getpass
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

def _resolve_ws() -> Path:
    """定位比赛工作区。

    ⚠️ 不能直接用 `Path(__file__).parent.parent`：本文件的「修正版」放在 ~/ctf/tools/，
    那样会算成 ~/ctf，产物（firmware/ evidence/）就落到错地方了。
    优先级：$CTF_WORKSPACE > 当前目录（含 work/ 或 firmware/）> 脚本上级目录。
    """
    env = os.environ.get("CTF_WORKSPACE")
    if env:
        return Path(env).expanduser()
    cwd = Path.cwd()
    if (cwd / "work").is_dir() or (cwd / "firmware").is_dir():
        return cwd
    return Path(__file__).resolve().parent.parent


WS = _resolve_ws()
LOG = WS / "evidence" / "submit-log.jsonl"
LOCK = WS / "evidence" / ".submit.lock"
CFG = Path(__file__).resolve().parent / "ctfd-config.json"
CREDS = Path(os.environ.get("CTF_CREDS") or (Path.home() / ".config" / "ctf" / "creds.env"))

RATE_LIMIT = 10          # 次
RATE_WINDOW = 60.0       # 秒
MAX_FAILS = 2            # 同题允许自行失败到第 3 次提交；到上限脚本自动拒提、转人工

_CREDS_KEYS = ("CTFD_BASE", "CTFD_TOKEN", "CTFD_COOKIE", "CTFD_USER", "CTFD_PASS")


# --------------------------------------------------------------------------- 配置
def read_creds(path: "Path | None" = None) -> dict:
    """读 KEY=VALUE 形式的凭据文件。**不做 shell 求值**（防注入），只做最小解析。

    ⚠️ 这里不能用 `path: Path = CREDS` 当默认值：函数默认值在 import 时就绑定，
    那样 `--creds` 覆盖会被忽略（实测踩过：登录写到了真实默认路径）。
    """
    path = path or CREDS
    out: dict = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        if k.startswith("export "):
            k = k[len("export "):].strip()
        if k in _CREDS_KEYS:
            out[k] = v.strip().strip('"').strip("'")
    return out


def write_creds(updates: dict, path: "Path | None" = None) -> None:
    """合并写入凭据文件并 chmod 600。（同样不能用 CREDS 当默认参数）"""
    path = path or CREDS
    cur = read_creds(path)
    cur.update({k: v for k, v in updates.items() if v})
    path.parent.mkdir(parents=True, exist_ok=True)
    body = [
        "# CTF 平台凭据（由 scripts/ctfd.py 管理）",
        "# 位置刻意放在比赛工作区【外面】，避免被 wp.md / notes / 交付物带走。",
        "# 键：CTFD_BASE / CTFD_TOKEN / CTFD_COOKIE / CTFD_USER / CTFD_PASS",
        "",
    ]
    body += [f"{k}={cur[k]}" for k in _CREDS_KEYS if cur.get(k)]
    path.write_text("\n".join(body) + "\n", encoding="utf-8")
    path.chmod(0o600)


def redact(v: str) -> str:
    if not v:
        return "（未设置）"
    return f"{v[:6]}…{v[-4:]}（len={len(v)}）" if len(v) > 12 else "（已设置，值过短不显示）"


def load_cfg() -> dict:
    fc = read_creds()
    cfg = {
        "base": os.environ.get("CTFD_BASE") or fc.get("CTFD_BASE", ""),
        "token": os.environ.get("CTFD_TOKEN") or fc.get("CTFD_TOKEN", ""),
        "cookie": os.environ.get("CTFD_COOKIE") or fc.get("CTFD_COOKIE", ""),
        "user": os.environ.get("CTFD_USER") or fc.get("CTFD_USER", ""),
        "password": os.environ.get("CTFD_PASS") or fc.get("CTFD_PASS", ""),
        "paths": {
            "challenges": "/api/v1/challenges",
            "challenge": "/api/v1/challenges/{id}",
            "attempt": "/api/v1/challenges/attempt",
            "files": "/files/{path}",
            "login": "/login",
            "unlocks": "/api/v1/unlocks",
            "hint": "/api/v1/hints/{id}",
            "start": "",     # 平台容器插件，留空=未配置则 start/stop 报错退出
            "stop": "",
        },
        "rate_limit": RATE_LIMIT,
        "rate_window": RATE_WINDOW,
    }
    if CFG.exists():
        try:
            user = json.loads(CFG.read_text(encoding="utf-8"))
            cfg["paths"].update(user.pop("paths", {}))
            cfg.update(user)
        except Exception as e:                                  # noqa: BLE001
            print(f"[!] 配置文件解析失败，用默认值: {e}", file=sys.stderr)
    return cfg


_relogin_busy = False


def http(cfg: dict, url: str, data: bytes | None = None, raw: bool = False,
         timeout: int = 20):
    """一次 HTTP 调用。返回 (status, body)；body 为解析后的 JSON 或原始 bytes。

    遇到 401/403 且 creds 里有 USER/PASS 时，**自动重登一次再重试**（只重试一层，
    防止密码错时无限循环）。比赛平台 session 常在几十分钟后过期，这层让长跑脚本不用人管。
    """
    global _relogin_busy
    st, body = _http_once(cfg, url, data, raw, timeout)
    if st in (401, 403) and not _relogin_busy:
        if cfg.get("user") and cfg.get("password"):
            _relogin_busy = True
            try:
                print(f"  [auth] HTTP {st} → 用凭据文件里的账号自动重登 …", file=sys.stderr)
                if do_login(cfg, cfg["user"], cfg["password"], quiet=True):
                    st, body = _http_once(cfg, url, data, raw, timeout)
                    print(f"  [auth] 重试结果 HTTP {st}", file=sys.stderr)
            finally:
                _relogin_busy = False
        if st in (401, 403):
            # 没有可用的账号密码时给一条能直接照做的修复指令，别只丢一个 401
            print(f"  [auth] 被拒（HTTP {st}）——session 可能已过期。修复任选其一：\n"
                  f"         python3 scripts/ctfd.py login --user <用户名>              # 重新登录一次\n"
                  f"         python3 scripts/ctfd.py login --user <用户名> --save-pass  # 存密码→以后自动重登\n"
                  f"         或在 {CREDS} 里写 CTFD_TOKEN=（平台 API Token）", file=sys.stderr)
    return st, body


_CSRF_CACHE: dict = {}


def _csrf_nonce(cfg: dict) -> str:
    """ctf.show（CTFd 3.x）对 POST 强制 CSRF-Token 头，缺了就是 HTTP 403。

    nonce 嵌在任意页面（这里取 /challenges）的 `csrfNonce': "<hex>"` 里，与 session 绑定，
    同一 session 内可复用 → 进程内缓存一次即可。来源：本会话 curl 抓取 /challenges 页面。
    """
    key = cfg["base"].rstrip("/") + "|" + (cfg["cookie"] or "")[:24]
    if key in _CSRF_CACHE:
        return _CSRF_CACHE[key]
    nonce = ""
    try:
        req = urllib.request.Request(cfg["base"].rstrip("/") + "/challenges")
        req.add_header("Cookie", cfg["cookie"] or "")
        req.add_header("User-Agent", "ctfd.py/1.0 (dsh ctf workspace)")
        with urllib.request.urlopen(req, timeout=20) as r:
            html = r.read().decode("utf-8", "replace")
        m = re.search(r"csrfNonce['\"]?\s*:\s*['\"]([0-9a-fA-F]+)['\"]", html)
        if m:
            nonce = m.group(1)
    except Exception:                                            # noqa: BLE001
        pass
    _CSRF_CACHE[key] = nonce
    return nonce


def _http_once(cfg: dict, url: str, data: bytes | None, raw: bool, timeout: int):
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    req.add_header("User-Agent", "ctfd.py/1.0 (dsh ctf workspace)")
    if data:
        req.add_header("Content-Type", "application/json")
        nonce = _csrf_nonce(cfg)
        if nonce:
            req.add_header("CSRF-Token", nonce)
            req.add_header("X-CSRFToken", nonce)
    if cfg["token"]:
        req.add_header("Authorization", f"Token {cfg['token']}")
    if cfg["cookie"]:
        req.add_header("Cookie", cfg["cookie"])
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
            return r.status, (body if raw else _json(body))
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, (body if raw else _json(body))
    except Exception as e:                                       # noqa: BLE001
        return 0, {"error": f"{type(e).__name__}: {e}"}


# --------------------------------------------------------------------- 登录/凭据
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """登录时要确定性读到 302/303 的 Set-Cookie，所以不跟随重定向。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):   # noqa: D102
        return None


_no_redirect = urllib.request.build_opener(_NoRedirect)


def do_login(cfg: dict, user: str, password: str, quiet: bool = False) -> bool:
    """CTFd 表单登录：GET /login 取 nonce → POST /login → 抓 Set-Cookie 里的 session。

    返回 True 表示拿到 session 并已写回凭据文件（0600）。
    平台差异：登录表单字段/nonce 位置可能不同 → 可用 `scripts/ctfd-config.json` 的
    `paths.login` 改路径；字段名不同则要改本函数。
    """
    login_url = api(cfg, "login")
    st, page = _http_once(cfg, login_url, None, True, 20)
    nonce = ""
    if isinstance(page, (bytes, bytearray)):
        m = re.search(rb'name="nonce"[^>]*value="([^"]+)"', page) or \
            re.search(rb'id="nonce"[^>]*value="([^"]+)"', page)
        if m:
            nonce = m.group(1).decode()
    form = {"name": user, "password": password}
    if nonce:
        form["nonce"] = nonce
    req = urllib.request.Request(login_url, data=urllib.parse.urlencode(form).encode(),
                                 method="POST")
    req.add_header("User-Agent", "ctfd.py/1.0 (dsh ctf workspace)")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    headers_list: list = []
    status = 0
    try:
        with _no_redirect.open(req, timeout=20) as r:
            status = r.status
            headers_list = r.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as e:
        # 302/303 登录成功也会走到这里（我们不跟随重定向）；4xx 才是真失败
        status = e.code
        headers_list = e.headers.get_all("Set-Cookie") or [] if e.headers else []
        if not headers_list and status not in (301, 302, 303, 307, 308):
            if not quiet:
                print(f"  [!] 登录失败 HTTP {status}（字段名或 nonce 可能不同）")
            return False
    except Exception as e:                                       # noqa: BLE001
        if not quiet:
            print(f"  [!] 登录异常: {type(e).__name__}: {e}")
        return False

    cookie = "; ".join(c.split(";")[0] for c in headers_list if "session=" in c)
    if not cookie:
        if not quiet:
            print(f"  [!] HTTP {status} 但没抓到 session cookie；请改用 token 方式")
        return False
    cfg["cookie"] = cookie
    write_creds({"CTFD_COOKIE": cookie, "CTFD_BASE": cfg["base"], "CTFD_USER": user})
    if not quiet:
        print(f"  ✅ 登录成功（HTTP {status}），session 已保存: {CREDS}  (chmod 600)")
        print(f"     cookie: {redact(cookie)}")
    return True


def cmd_login(cfg, args) -> None:
    user = args.user or cfg.get("user") or os.environ.get("CTFD_USER") or ""
    if not user:
        sys.exit("[!] 需要 --user（或 creds 里已有 CTFD_USER）")
    pw = cfg.get("password") or ""
    if args.password_stdin:
        pw = sys.stdin.readline().rstrip("\n")
    elif not pw:
        pw = getpass.getpass(f"  {user} 的平台密码（不回显，也不进会话记录）: ")
    if not pw:
        sys.exit("[!] 空密码")
    ok = do_login(cfg, user, pw)
    if not ok:
        sys.exit(1)
    if args.save_pass:
        write_creds({"CTFD_PASS": pw})
        print("  ⚠️ 已按 --save-pass 保存密码（长期有效但风险更高；不保存则 session 过期后需再登一次）")
    else:
        print("  （未保存密码；session 过期时重跑本命令即可）")


def cmd_creds(cfg, args) -> None:
    print(f"  凭据文件: {CREDS}  {'存在' if CREDS.exists() else '不存在'}"
          f"{'  权限=' + oct(CREDS.stat().st_mode & 0o777) if CREDS.exists() else ''}")
    print(f"  工作区（凭据绝不该出现在这里）: {WS}")
    for k in _CREDS_KEYS:
        v = cfg.get({"CTFD_BASE": "base", "CTFD_TOKEN": "token", "CTFD_COOKIE": "cookie",
                     "CTFD_USER": "user", "CTFD_PASS": "password"}[k], "")
        print(f"    {k:<12} {redact(v) if k not in ('CTFD_BASE', 'CTFD_USER') else (v or '（未设置）')}")
    leak = [p for p in WS.rglob("*") if p.is_file() and p.suffix in (".env", ".creds")
            and "creds" in p.name.lower()]
    print(f"  工作区内疑似凭据文件: {leak if leak else '无 ✅'}")


def _json(b: bytes):
    try:
        return json.loads(b.decode("utf-8", "replace"))
    except Exception:                                            # noqa: BLE001
        return {"_raw": b[:500].decode("utf-8", "replace")}


def api(cfg: dict, key: str, **fmt) -> str:
    p = cfg["paths"][key]
    if not p:
        sys.exit(f"[!] 未配置 {key} 端点（平台容器接口需按平台填 scripts/ctfd-config.json 的 paths.{key}）")
    return cfg["base"].rstrip("/") + p.format(**fmt)


# ----------------------------------------------------------------------- 只读命令
def _fetch_challenges(cfg) -> list:
    """拉一次题目列表，返回精简后的行。list 与 watch 共用。"""
    st, body = http(cfg, api(cfg, "challenges"))
    if st != 200:
        sys.exit(f"[!] 拉题目列表失败 HTTP {st}: {json.dumps(body, ensure_ascii=False)[:300]}")
    data = body.get("data", body)
    return [{
        "id": c.get("id"), "name": c.get("name"), "category": c.get("category"),
        "value": c.get("value"), "solves": c.get("solves"),
        "solved_by_me": c.get("solved_by_me"), "type": c.get("type"),
    } for c in data]


def cmd_list(cfg, args) -> list:
    rows = _fetch_challenges(cfg)
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=1))
    else:
        for r in rows:
            mark = "✔" if r["solved_by_me"] else " "
            print(f"  [{mark}] {r['id']:>4}  {r['category'] or '?':<12} {r['value'] or 0:>5}分 "
                  f"{r['name']}  (解出 {r['solves']})")
    return rows


def cmd_detail(cfg, args) -> dict:
    st, body = http(cfg, api(cfg, "challenge", id=args.id))
    if st != 200:
        sys.exit(f"[!] detail 失败 HTTP {st}: {json.dumps(body, ensure_ascii=False)[:300]}")
    d = body.get("data", body)
    if args.json:
        print(json.dumps(d, ensure_ascii=False, indent=1))
    else:
        print(f"  题号   : {d.get('id')}\n  题名   : {d.get('name')}\n"
              f"  分类   : {d.get('category')}   分值: {d.get('value')}   "
              f"解出: {d.get('solves')}")
        print(f"  描述   :\n{_strip(d.get('description') or '')[:2000]}")
        for f in d.get("files") or []:
            print(f"  附件   : {f}")
        for h in d.get("hints") or []:
            print(f"  hint   : {_strip(str(h.get('content')))[:200]}")
        if d.get("connection_info"):
            print(f"  连接   : {d['connection_info']}")
    return d


def cmd_download(cfg, args) -> None:
    st, body = http(cfg, api(cfg, "challenge", id=args.id))
    if st != 200:
        sys.exit(f"[!] 取题目失败 HTTP {st}")
    d = body.get("data", body)
    slug = re.sub(r"[^0-9A-Za-z._-]+", "_", str(d.get("name") or "challenge"))[:40]
    out = WS / "firmware" / f"{args.id}_{slug}"
    out.mkdir(parents=True, exist_ok=True)
    files = d.get("files") or []
    if not files:
        print("  （本题无附件）")
        return
    for f in files:
        s = str(f)
        if s.startswith("http"):
            url = s
        elif s.startswith("/"):
            # 平台已经给了根相对路径（如 /files/xxx），直接用，不要再套模板
            url = cfg["base"].rstrip("/") + s
        else:
            url = cfg["base"].rstrip("/") + cfg["paths"]["files"].format(path=s)
        st, blob = http(cfg, url, raw=True, timeout=120)
        name = Path(urllib.parse.urlparse(url).path).name or "attachment.bin"
        if st == 200 and isinstance(blob, (bytes, bytearray)):
            (out / name).write_bytes(blob)
            print(f"  + {out}/{name}  ({len(blob)} B)")
        else:
            print(f"  [!] 下载失败 {url} → HTTP {st}")


# ------------------------------------------------------------ 提示与批量（2026-10-18 新增）
def _detail(cfg: dict, cid) -> dict:
    st, body = http(cfg, api(cfg, "challenge", id=cid))
    if st != 200:
        raise RuntimeError(f"detail HTTP {st}: {json.dumps(body, ensure_ascii=False)[:200]}")
    return body.get("data", body)


def _save_files(cfg: dict, d: dict) -> list:
    """把一题的附件存到 firmware/<id>_<slug>/，返回落地路径。"""
    slug = re.sub(r"[^0-9A-Za-z._-]+", "_", str(d.get("name") or "challenge"))[:40]
    out = WS / "firmware" / f"{d.get('id')}_{slug}"
    saved: list = []
    for f in d.get("files") or []:
        s = str(f)
        if s.startswith("http"):
            url = s
        elif s.startswith("/"):
            url = cfg["base"].rstrip("/") + s
        else:
            url = cfg["base"].rstrip("/") + cfg["paths"]["files"].format(path=s)
        st, blob = http(cfg, url, raw=True, timeout=120)
        name = Path(urllib.parse.urlparse(url).path).name or "attachment.bin"
        if st == 200 and isinstance(blob, (bytes, bytearray)):
            out.mkdir(parents=True, exist_ok=True)
            (out / name).write_bytes(blob)
            saved.append(str(out / name))
    return saved


def cmd_hint(cfg, args) -> None:
    """列出 hint；**自动解锁 cost==0 的免费 hint**（CTFd 的 detail 不返回未解锁内容）。"""
    d = _detail(cfg, args.id)
    hints = d.get("hints") or []
    if not hints:
        print("  （本题无 hint）")
        return
    print(f"  题目 {d.get('id')} {d.get('name')} — {len(hints)} 条 hint")
    for h in hints:
        cost = h.get("cost")
        unlocked = bool(h.get("content"))
        tag = "免费" if cost == 0 else f"{cost} 分"
        print(f"  [{h.get('id')}] cost={tag}  {'已解锁' if unlocked else '未解锁'}")
        if unlocked:
            print(f"       {_strip(str(h.get('content')))[:600]}")
    # 挑选要解锁的
    todo = []
    if not args.no_free:
        todo += [h for h in hints if h.get("cost") == 0 and not h.get("content")]
    want = set(args.unlock or [])
    todo += [h for h in hints if h.get("id") in want and not h.get("content")]
    if args.all:
        todo += [h for h in hints if not h.get("content")]
    seen: set = set()
    uniq = []
    for h in todo:
        if h["id"] not in seen:
            seen.add(h["id"]); uniq.append(h)
    todo = uniq
    for h in todo:
        payload = json.dumps({"target": h["id"], "type": "hints"}).encode()
        st, body = http(cfg, api(cfg, "unlocks"), data=payload)
        ok = isinstance(body, dict) and body.get("success")
        if not ok and st not in (200,):
            print(f"  [!] 解锁 [{h['id']}] 失败 HTTP {st}: {str(body)[:200]}")
            continue
        st2, b2 = http(cfg, api(cfg, "hint", id=h["id"]))
        c = (b2.get("data") or {}).get("content") if isinstance(b2, dict) else None
        print(f"  ★ 解锁 [{h['id']}] cost={h.get('cost')} → {_strip(str(c))[:600] if c else '（平台未返回内容）'}")


def cmd_bulk(cfg, args) -> None:
    """一次性 list+detail(+download)，并生成 triage 表，供开赛 3 分钟侦察。"""
    rows = _fetch_challenges(cfg)
    if args.category:
        rows = [r for r in rows if str(r.get("category") or "").startswith(args.category)]
    if args.type:
        rows = [r for r in rows if r.get("type") == args.type]
    if args.limit:
        rows = rows[: args.limit]
    print(f"  批量处理 {len(rows)} 题（download={args.download}）…")
    lines = ["| id | 方向 | 题名 | 分值 | 类型 | 附件 | 容器 |", "|---|---|---|---|---|---|---|"]
    got = 0
    for r in rows:
        try:
            d = _detail(cfg, r["id"])
        except Exception as e:                                    # noqa: BLE001
            print(f"  [!] {r['id']} detail 失败: {e}")
            continue
        files = d.get("files") or []
        saved = _save_files(cfg, d) if (args.download and files) else []
        if saved:
            got += len(saved)
        lines.append("| {id} | {cat} | {name} | {val} | {typ} | {f} | {c} |".format(
            id=d.get("id"), cat=r.get("category") or "?", name=str(d.get("name")).replace("|", "\\|"),
            val=d.get("value"), typ=d.get("type") or "?",
            f=(f"{len(files)} 个" + (f"（已存 {len(saved)}）" if saved else "")) if files else "无",
            c="有" if (d.get("type") == "dynamic_docker") else "无"))
    out = WS / "work" / "triage.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(f"# 题目 triage（{len(rows)} 题）\n\n" + "\n".join(lines) + "\n", encoding="utf-8")
    print(f"  → {out}" + (f"（附件 {got} 个已存 {WS}/firmware/）" if got else ""))


# ------------------------------------------------------------------- 容器与提交
def cmd_start(cfg, args) -> None:
    st, body = http(cfg, api(cfg, "start", id=args.id), data=json.dumps({"challenge_id": args.id}).encode())
    print(f"  HTTP {st}: {json.dumps(body, ensure_ascii=False)[:400]}")
    addr = _find_address(body)
    if addr:
        print(f"\n  ADDRESS: {addr}\n  用法: http://{addr}/   （★ 重启后地址会变，旧地址一律失效）")


def cmd_stop(cfg, args) -> None:
    st, body = http(cfg, api(cfg, "stop", id=args.id), data=json.dumps({"challenge_id": args.id}).encode())
    print(f"  HTTP {st}: {json.dumps(body, ensure_ascii=False)[:400]}")


def _find_address(body) -> str | None:
    for k in ("address", "host", "url", "endpoint", "ip"):
        v = _dig(body, k)
        if isinstance(v, str) and v:
            return v
    return None


def _dig(o, key):
    if isinstance(o, dict):
        if key in o:
            return o[key]
        for v in o.values():
            r = _dig(v, key)
            if r is not None:
                return r
    elif isinstance(o, list):
        for v in o:
            r = _dig(v, key)
            if r is not None:
                return r
    return None


def _journal() -> list:
    """读回整份提交流水（坏行跳过，不因一行脏数据中断）。"""
    if not LOG.exists():
        return []
    out = []
    for line in LOG.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except Exception:                                        # noqa: BLE001
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def _is_transport(rec: dict) -> bool:
    """这条记录是不是"根本没送到平台"（连接失败 / 5xx），而非平台判定 flag 错。"""
    if rec.get("transport_error"):
        return True
    st = rec.get("http")
    try:
        return int(st) == 0 or int(st) >= 500
    except (TypeError, ValueError):
        return False


def _guard_duplicate(cid: int, flag: str, force: bool) -> "tuple[bool, str]":
    """提交前的本地闸门。返回 (是否放行, 提示)。

    三条互斥判定，全部基于 evidence/submit-log.jsonl（不联网）：
    1. 同题同 flag 已成功 → **跳过**，不消耗限速额度（赛马的两个代理会算出同一个 flag）；
    2. 同题已用**另一个** flag 成功 → 拒绝（防止第二个跑者把"另一个答案"提上去）；
    3. 同题失败次数已达上限 → 拒绝，转人工（这就是"错误次数太多才上报父代理"的机器版）。
    """
    recs = _journal()
    mine = [r for r in recs if r.get("challenge_id") == cid]
    ok = [r for r in mine if r.get("result")]
    # 传输失败（st=0 或 5xx）**不算**一次错误提交：请求没到平台，不该烧额度
    fail = [r for r in mine if not r.get("result") and not _is_transport(r)]

    for r in ok:
        if str(r.get("flag")) == flag:
            return False, (f"  本题该 flag 已于 {r.get('time')} 由「{r.get('by') or '未知'}」提交成功 → "
                           f"跳过重复提交（不消耗限速额度）")
    if ok and not force:
        first = ok[0]
        return False, (f"  ⚠️ 该题已解出：{first.get('flag')}（{first.get('time')}，"
                       f"by {first.get('by') or '未知'}）。你给的 flag **不同**，"
                       f"疑似错误答案 → 已拦截。确认要提交请加 --force，或直接回报父代理。")
    if len(fail) >= MAX_FAILS and not force:
        last = fail[-1]
        return False, (f"  ⛔ 该题已失败 {len(fail)} 次（上限 {MAX_FAILS}，全平台同题 ≤3 次）。\n"
                       f"     最后一次平台返回：{str(last.get('response'))[:200]}\n"
                       f"     → **停止自行提交**，回报父代理/人类决定下一步（或加 --force 强提）。")
    return True, ""


def _recent_submits(window: float) -> list:
    """返回滚动窗口内的提交时间戳。"""
    if not LOG.exists():
        return []
    now = time.time()
    ts = []
    for line in LOG.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            ts.append(float(json.loads(line)["ts"]))
        except Exception:                                        # noqa: BLE001
            continue
    return [t for t in ts if now - t < window]


def cmd_submit(cfg, args) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    limit, window = cfg["rate_limit"], cfg["rate_window"]
    cid, flag = int(args.id), args.flag
    by = os.environ.get("CTF_AGENT") or "父代理"

    # flock：让并发的子代理串行化提交，避免各自算限速而集体超限
    with open(LOCK, "a+") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)

        allowed, why = _guard_duplicate(cid, flag, args.force)
        if not allowed:
            fcntl.flock(lk, fcntl.LOCK_UN)
            print(why)
            sys.exit(2)

        waited = 0.0
        while True:
            recent = _recent_submits(window)
            if len(recent) < limit:
                break
            sleep = window - (time.time() - min(recent)) + 0.05
            sleep = max(0.05, min(sleep, window))
            print(f"  [限速] 最近 {window:.0f}s 已提交 {len(recent)}/{limit} 次，排队等待 {sleep:.1f}s …")
            time.sleep(sleep)
            waited += sleep

        payload = {"challenge_id": cid, "submission": flag}
        st, body = http(cfg, api(cfg, "attempt"), data=json.dumps(payload).encode())
        ok = bool(_dig(body, "success")) or str(_dig(body, "status")) in ("correct", "already_solved")
        rec = {
            "ts": time.time(), "time": time.strftime("%F %T"), "challenge_id": cid,
            "flag": flag, "http": st, "result": ok, "waited_s": round(waited, 2),
            "by": by, "transport_error": st == 0 or st >= 500,
            "response": json.dumps(body, ensure_ascii=False)[:800],
        }
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        fcntl.flock(lk, fcntl.LOCK_UN)

    print(f"  HTTP {st}  result={'TRUE ✅' if ok else 'false'}  （提交者: {by}）")
    print(f"  平台返回: {json.dumps(body, ensure_ascii=False)[:600]}")
    print(f"  已记账: {LOG.relative_to(WS)}")
    if not ok:
        msg = json.dumps(body, ensure_ascii=False).lower()
        if "already" in msg or "已解出" in msg or "solved" in msg:
            print("  ↑ 这是**重复提交**，不是 flag 错（见 AGENTS.md 提交纪律）。")
        if st == 0 or st >= 500:
            print("  ↑ 传输/服务端错误（请求可能没到平台），**不计入失败次数**；先修网络或等平台恢复。")
            return
        left = MAX_FAILS - sum(1 for r in _journal()
                               if r.get("challenge_id") == cid and not r.get("result")
                               and not _is_transport(r))
        if left <= 0:
            print(f"  ⛔ 该题失败次数已用尽 → **停止自行提交**，回报父代理/人类。")
        else:
            print(f"  ⚠️ 该题还可失败 {left} 次；到上限后脚本会自动拒提，届时必须上报。")


def cmd_log(cfg, args) -> None:
    recs = _journal()
    if not recs:
        print("  （暂无提交记录）")
        return
    ok = [r for r in recs if r.get("result")]
    fails = [r for r in recs if not r.get("result")]
    print(f"  总提交 {len(recs)} 次 / 成功 {len(ok)} 次 / 失败 {len(fails)} 次；"
          f"成功题数 {len({r.get('challenge_id') for r in ok})}")
    for r in recs[-args.n:]:
        print(f"  {r.get('time')}  题{str(r.get('challenge_id')):>4}  "
              f"{'✔' if r.get('result') else '✗'}  by {str(r.get('by') or '-'):<10}"
              f"{str(r.get('flag'))[:60]}")
    # 待人工处理的题：失败但未解出 —— 对齐 MAX_FAILS 闸门
    bad: dict = {}
    for r in fails:
        cid = r.get("challenge_id")
        if cid not in {x.get("challenge_id") for x in ok}:
            bad[cid] = bad.get(cid, 0) + 1
    if bad:
        print("  ⚠️ 未解出且已失败的题（失败数 / 上限）：")
        for cid, n in sorted(bad.items()):
            flag = "  ⛔ 已到上限，须父代理决定（--force）" if n >= MAX_FAILS else ""
            print(f"     题{cid}: {n}/{MAX_FAILS}{flag}")


def cmd_watch(cfg, args) -> None:
    """VeriaLabs 式 poller：轮询题目列表，发现新题就打印（供父代理 spawn 子代理）。"""
    seen: set = set()
    first = True
    print(f"  [watch] 每 {args.interval}s 轮询一次；新题打 NEW，首轮打 INIT。Ctrl-C 停止。", flush=True)
    while True:
        rows = _fetch_challenges(cfg)
        for r in rows:
            if r["id"] not in seen:
                seen.add(r["id"])
                tag = "INIT" if first else "NEW "
                print(f"  {tag} id={r['id']} [{r['category']}] {r['name']} ({r['value']}分)", flush=True)
        first = False
        time.sleep(args.interval)


def _strip(html: str) -> str:
    txt = re.sub(r"<br\s*/?>|</p>", "\n", html or "", flags=re.I)
    return re.sub(r"<[^>]+>", "", txt).strip()


# --------------------------------------------------------------------------- main
def main() -> None:
    global CREDS
    ap = argparse.ArgumentParser(description="CTFd 平台客户端（登录/凭据 + 限速提交 + 轮询发现 + 容器管理）")
    ap.add_argument("--base", help="平台根 URL，如 https://ctf.example.com")
    ap.add_argument("--token", help="API Token（CTFd: Authorization: Token xxx）")
    ap.add_argument("--cookie", help="会话 Cookie（有些平台 token 不生效，用 cookie）")
    ap.add_argument("--user", help="平台用户名（配合 login，或让 401 后自动重登）")
    ap.add_argument("--creds", help=f"凭据文件路径（默认 {CREDS}；也可用 $CTF_CREDS）")
    ap.add_argument("--json", action="store_true", help="输出原始 JSON")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("creds", help="查看凭据配置（脱敏）"); p.set_defaults(fn=cmd_creds)
    p = sub.add_parser("login", help="账号密码登录并把 session 写进凭据文件")
    p.add_argument("--user"); p.add_argument("--password-stdin", action="store_true",
                                            help="从 stdin 读密码（用于管道）")
    p.add_argument("--save-pass", action="store_true",
                   help="同时保存密码（session 过期可自动重登；风险更高，默认不存）")
    p.set_defaults(fn=cmd_login)
    p = sub.add_parser("list", help="列题目"); p.set_defaults(fn=cmd_list)
    p = sub.add_parser("detail", help="题目详情"); p.add_argument("id"); p.set_defaults(fn=cmd_detail)
    p = sub.add_parser("download", help="下载附件到 firmware/<id>_<slug>/")
    p.add_argument("id"); p.set_defaults(fn=cmd_download)
    p = sub.add_parser("hint", help="列出 hint 并自动解锁免费的（cost=0）")
    p.add_argument("id")
    p.add_argument("--unlock", type=int, nargs="*", metavar="HINT_ID", help="指定要解锁的 hint id（花分）")
    p.add_argument("--all", action="store_true", help="解锁该题全部 hint（会花分）")
    p.add_argument("--no-free", action="store_true", help="不自动解锁免费的")
    p.set_defaults(fn=cmd_hint)
    p = sub.add_parser("bulk", help="批量 list+detail(+download) 并生成 work/triage.md")
    p.add_argument("--category", help="按板块前缀过滤，如 WEB / PWN入门")
    p.add_argument("--type", help="按类型过滤，如 dynamic_docker / standard / dynamic")
    p.add_argument("--limit", type=int, help="最多处理多少题")
    p.add_argument("--download", action="store_true", help="同时下载附件")
    p.set_defaults(fn=cmd_bulk)
    p = sub.add_parser("start", help="起本队容器"); p.add_argument("id"); p.set_defaults(fn=cmd_start)
    p = sub.add_parser("stop", help="停本队容器"); p.add_argument("id"); p.set_defaults(fn=cmd_stop)
    p = sub.add_parser("submit", help="提交 flag（限速排队 + 记账 + 防重复/防超限）")
    p.add_argument("id"); p.add_argument("flag")
    p.add_argument("--force", action="store_true",
                   help="越过本地闸门（已解出冲突 / 失败次数用尽时仍要提交）")
    p.set_defaults(fn=cmd_submit)
    p = sub.add_parser("log", help="汇总提交日志")
    p.add_argument("-n", type=int, default=10); p.set_defaults(fn=cmd_log)
    p = sub.add_parser("watch", help="轮询发现新题")
    p.add_argument("--interval", type=float, default=5.0)
    p.set_defaults(fn=cmd_watch)

    args = ap.parse_args()
    if args.creds:
        CREDS = Path(args.creds).expanduser()
    cfg = load_cfg()
    if args.base:
        cfg["base"] = args.base
    if args.token:
        cfg["token"] = args.token
    if args.cookie:
        cfg["cookie"] = args.cookie
    if args.user:
        cfg["user"] = args.user
    if not cfg["base"] and args.cmd not in ("log", "creds"):
        sys.exit("[!] 缺 --base（或设 CTFD_BASE / 写进 ~/.config/ctf/creds.env）")
    if not (cfg["token"] or cfg["cookie"]) and args.cmd in ("submit", "start", "stop", "watch"):
        sys.exit("[!] 该命令需要凭据：先 `ctfd.py login --user <u>`，或设 CTFD_TOKEN / CTFD_COOKIE")
    args.fn(cfg, args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  [watch] 已停止")
