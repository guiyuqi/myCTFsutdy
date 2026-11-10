#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wp-pack.py —— 强网杯 WriteUp 打包器 + AI 对话记录合规自检

为什么有这个脚本（裁判口径，2026-10-30）：
  「赛后 8 小时内，排名前 50 名的参赛队须上传每道成功解出赛题详细的解题报告（WriteUp）。
    各队伍赛后提交 writeup 时，需提供详细的分析过程及截图、解题脚本；
    若使用 AI 辅助解题，参赛选手需保留完整的 AI 对话记录（包括但不限于对话导出、图片、视频等形式）
    （例如 claude code 在 ~/.claude/projects/ 下，一个会话一个 .jsonl），
    并打为 zip 压缩包后上传至百度网盘。在提交 writeup 时，需将链接附在文档开头，
    同时需要附上 zip 的 md5 值。如不按规范撰写、提交，或相应的会话记录无法支撑题目解出，
    则相应赛题按作弊处理，并取消队伍排名。」

本机（DSH）的等价物：
  ~/.dsh/sessions/<工作区编码>/<会话id>/session.v3.jsonl.zstd
  —— 一个会话一个 jsonl，只是**多了一层 zstd 压缩，而且是 389 个帧的追加流**。
     ★ 不能只用 zlib.zstdDecompressSync（只解第一个帧，只能拿到 1 行）；
       必须用 7z / `7z x -so` 这种能处理 concatenated frames 的解压器。

本脚本做四件事：
  1. 把比赛窗口内的**所有会话**原样解出（raw .zstd 与可读 .jsonl 都留）；
  2. 对每道**已解出**的题做**支撑性自检**：会话里有没有真的出现过这道题的分析/工具调用，
     外加 notes/scripts/evidence 是否有对应文件 —— 这就是裁判会看的东西；
  3. 打包成 zip（含 wp.md / notes / scripts / evidence / sessions），算 md5；
  4. 生成可直接贴到 wp.md 开头的「网盘链接 + md5」占位块。

用法：
  python3 scripts/wp-pack.py --dry-run                 # 只看会打包什么、支撑性如何
  python3 scripts/wp-pack.py                           # 真打包（默认窗口 = 开赛至今）
  python3 scripts/wp-pack.py --since '2026-10-31 09:00' --out work/writeup-bundle
  python3 scripts/wp-pack.py --link 'https://pan.baidu.com/s/xxxx 密码:yyyy'

★ 凭据脱敏：会话里必然出现 token / teamtoken（我们讨论过它们）。
   本脚本默认**脱敏后再打包**，并在 REDACTION.md 里逐条记录替换了什么，
   这样对裁判仍然是"完整记录"，但不会把本队登录态泄到网盘上。
   确需原样（例如裁判要求未脱敏）：--no-redact（不推荐）。

★ 退出码（2026-10-31 修口径 · 防假绿）：
   0 = 每题都可提交（"可提交"口径成立）
   3 = 有已解出题，但支撑性不足（缺笔记 / 会话里找不到该题 ⇒ 作弊风险）
   5 = **一道已解出题都没有**（台账里没有任何 result:true）—— 这不是"通过"，
       而是"整包是空的"。历史上这里退 0，赛前预演时看起来像全通过（假绿）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

WS = Path(__file__).resolve().parent.parent
SESSIONS_ROOT = Path(os.environ.get("DSH_SESSIONS", Path.home() / ".dsh" / "sessions"))
SUBMIT_LOG = WS / "evidence" / "submit-log.jsonl"
NOTES = WS / "notes"
SCRIPTS = WS / "scripts"
EVIDENCE = WS / "evidence"
TEAM = WS / "team"
DEFAULT_OUT = WS / "work" / "writeup-bundle"
CONTEST_START = "2026-10-31 09:00"          # 本场开赛（本地时区）
CONTEST_END = "2026-11-01 12:00"

# ---------------------------------------------------------------- 脱敏规则
# 每条：(正则, 替换, 说明)。宁可多抹，也不能把登录态带上网盘。
REDACT_RULES = [
    (re.compile(r"(login:match_\d+:)[0-9a-f]{16,}"), r"\1<REDACTED-LOGIN-TOKEN>",
     "平台登录 token（拿它可冒充本队提交）"),
    (re.compile(r"\bicqa[0-9a-f]{20,}\b"), "<REDACTED-TEAMTOKEN>",
     "本队 teamtoken（题面要求提供，泄露=他人可代打）"),
    (re.compile(r"(__jsluid_s=)[0-9a-f]{16,}"), r"\1<REDACTED-CDNCookie>",
     "加速乐反爬 cookie（低危，一并抹掉更干净）"),
    (re.compile(r"\b(e826b7ac[0-9a-f]{24})\b"), "<REDACTED-CDNCookie>",
     "裸 CDN cookie 值"),
]


SECRETS: list[tuple[str, str]] = []
SECRET_RE = re.compile(r"TOKEN|SECRET|PASS|COOKIE|SESSION|JSLUID|CRED|AUTH|SID", re.I)


def load_secret_values() -> list[tuple[str, str]]:
    """按**真实值**脱敏：从 creds.env 读出凭据，连"裸值"形态一起替换。

    为什么需要这个（2026-10-30 实测踩到）：
      token 在对话里不只有 `login:match_1483:<hex>` 一种形态 ——
      我们自己排查泄漏时会把裸 `<hex>` 写进命令，纯模式匹配就会漏。
      按值替换才是可靠的，模式规则只留作兜底。
    """
    creds = Path(os.environ.get("CTF_CREDS", Path.home() / ".config" / "ctf" / "creds.env"))
    out: list[tuple[str, str]] = []
    if not creds.exists():
        return out
    for ln in creds.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#") or "=" not in ln:
            continue
        k, _, v = ln.partition("=")
        k, v = k.strip(), v.strip()
        if not v or len(v) < 8 or not SECRET_RE.search(k):
            continue                      # 比赛 key（QWB_K）不算凭据：单独它无法提交/读题
        ku = k.upper()
        if "TEAM" in ku:
            label = "TEAMTOKEN"
        elif "JSLUID" in ku or "COOKIE" in ku:
            label = "CDN-COOKIE"
        elif "TOKEN" in ku:
            label = "LOGIN-TOKEN"
        else:
            label = "SECRET"
        out.append((v, label))
        # 裸值形态也单独抹：`login:match_x:<hex>` 的冒号尾段、
        #                    `__jsluid_s=<hex>` 的等号尾段
        for sep in (":", "="):
            if sep in v:
                tail = v.rsplit(sep, 1)[-1]
                if len(tail) >= 16 and tail != v:
                    out.append((tail, f"BARE-{label}"))
    # 长的先替换，避免子串互相截断
    out.sort(key=lambda kv: -len(kv[0]))
    return out


def redact(text: str, hits: dict[str, int]) -> str:
    # ① 按真实值精确替换（最可靠）
    for val, label in SECRETS:
        if val and val in text:
            n = text.count(val)
            text = text.replace(val, f"<REDACTED-{label}>")
            hits[f"按值脱敏：{label}"] = hits.get(f"按值脱敏：{label}", 0) + n
    # ② 模式兜底（防止临时口令/未来新增格式漏网）
    for pat, repl, name in REDACT_RULES:
        text, n = pat.subn(repl, text)
        if n:
            hits[name] = hits.get(name, 0) + n
    return text




# ---------------------------------------------------------------- 解压
def decompress_zstd(path: Path) -> bytes:
    """解 DSH 的 session.v3.jsonl.zstd。

    ★ 关键坑：这个文件是 **多帧追加**（每条记录一帧），
      Node 的 zlib.zstdDecompressSync 只解第一帧（实测只拿到 1 行 / 206 字节），
      所以优先用 7z 的 `-so`（它会把所有帧拼起来）。
    """
    seven = shutil.which("7z") or shutil.which("7zz") or shutil.which("7za")
    if seven:
        p = subprocess.run([seven, "x", "-so", str(path)],
                           capture_output=True, check=False)
        if p.returncode == 0 and p.stdout:
            return p.stdout
    node = shutil.which("node")
    if node:
        # 退路：node 流式解压（逐帧喂）
        script = (
            "const fs=require('fs'),z=require('zlib');"
            "const buf=fs.readFileSync(process.argv[1]);"
            "let out=[],i=0;const M=Buffer.from([0x28,0xb5,0x2f,0xfd]);"
            "while(i<buf.length){const j=buf.indexOf(M,i+1);const end=j<0?buf.length:j;"
            "try{out.push(z.zstdDecompressSync(buf.subarray(i,end)))}catch(e){break}i=end;}"
            "process.stdout.write(Buffer.concat(out));"
        )
        p = subprocess.run([node, "-e", script, str(path)],
                           capture_output=True, check=False)
        if p.returncode == 0 and p.stdout:
            return p.stdout
    raise RuntimeError(f"解不开 zstd：{path}（需要 7z 或 node）")


# ---------------------------------------------------------------- 会话发现
def workspace_key(path: Path) -> str:
    """DSH 把工作区路径编码成目录名：/home/u/ctf-2026 → --home-u-ctf-2026--"""
    return "--" + str(path).strip("/").replace("/", "-") + "--"


def iter_sessions(since: float, until: float | None) -> list[dict]:
    root = SESSIONS_ROOT / workspace_key(WS)
    if not root.is_dir():
        raise SystemExit(f"[!] 找不到本工作区的会话目录：{root}\n"
                         f"    （DSH_SESSIONS 可覆盖根目录）")
    out = []
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        f = d / "session.v3.jsonl.zstd"
        if not f.exists():
            continue
        mtime = f.stat().st_mtime
        if mtime < since or (until and mtime > until):
            continue
        out.append({"id": d.name, "dir": d, "file": f,
                    "mtime": mtime, "size": f.stat().st_size})
    out.sort(key=lambda x: x["mtime"])
    return out


def summarize_jsonl(text: str) -> dict:
    """统计一个会话：多少轮/多少工具调用/首条用户消息/出现过哪些特征串。"""
    info = {"lines": 0, "user": 0, "assistant": 0, "tool_call": 0, "tool_result": 0,
            "first_user": "", "cwd": "", "title": ""}
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        info["lines"] += 1
        try:
            o = json.loads(ln)
        except json.JSONDecodeError:
            continue
        t = o.get("type") or ""
        if t == "session":
            info["cwd"] = o.get("cwd") or ""
        elif t == "session/title":
            d = o.get("data") or {}
            info["title"] = d.get("title") or d.get("name") or ""
        elif t == "user/message":
            info["user"] += 1
            if not info["first_user"]:
                info["first_user"] = _text_of(o)[:160].replace("\n", " ")
        elif t == "assistant/message":
            info["assistant"] += 1
        elif t == "tool/call":
            info["tool_call"] += 1
        elif t == "tool/result":
            info["tool_result"] += 1
    return info


def _text_of(rec: dict) -> str:
    d = rec.get("data") or {}
    for k in ("text", "content", "message", "prompt"):
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v
        if isinstance(v, list):
            parts = []
            for it in v:
                if isinstance(it, dict):
                    parts.append(str(it.get("text") or it.get("content") or ""))
                elif isinstance(it, str):
                    parts.append(it)
            s = " ".join(p for p in parts if p).strip()
            if s:
                return s
    return ""


# ---------------------------------------------------------------- 已解出题目
def _red_empty() -> None:
    """0 道已解出题的统一红灯文案（假绿修复 2）。

    这不是"提醒"，是"交付物是空的"：台账里没有任何 result:true，
    就没有任何一题进得了包里，此时任何"通过"读法都是错的。
    """
    print("\n" + "!" * 72)
    print("[!] 已解出题目 0 道 —— 这不是\"通过\"，而是\"整包是空的\"（台账里没有任何 result:true）")
    print("    先确认真解出过（evidence/submit-log.jsonl 里要有 result:true 的记录），"
          "再谈打包/支撑性。")
    print("!" * 72)


def solved_questions() -> dict[str, dict]:
    """从提交台账里取 result=true 的题，附带可复现性证据（notes/scripts/evidence）。"""
    got: dict[str, dict] = {}
    if SUBMIT_LOG.exists():
        for ln in SUBMIT_LOG.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                r = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if r.get("result") is True:
                qid = str(r.get("id"))
                got.setdefault(qid, {"flag": r.get("flag"), "time": r.get("time")})
    # 补齐题名（notes/<id>-<title>.md）
    for qid, rec in got.items():
        for p in NOTES.glob(f"{qid}-*.md"):
            rec["title"] = p.stem.split("-", 1)[-1]
        rec.setdefault("title", "")
        rec["notes"] = [str(p.relative_to(WS)) for p in NOTES.glob(f"{qid}-*.md")]
        rec["scripts"] = [str(p.relative_to(WS)) for p in SCRIPTS.glob(f"{qid}*")]
        rec["evidence"] = [str(p.relative_to(WS)) for p in EVIDENCE.glob(f"{qid}*")]
    return got


def support_check(qid: str, sessions: list[dict]) -> list[str]:
    """哪些会话里真的提到过这道题（题号按词边界匹配，避免 12 命中 1208）。"""
    pat = re.compile(rf"(?<![\w-]){re.escape(qid)}(?![\w-])")
    hits = []
    for s in sessions:
        if s.get("plain_text") and pat.search(s["plain_text"]):
            hits.append(s["id"])
    return hits


# ---------------------------------------------------------------- 打包
def sha_md5(path: Path) -> tuple[str, str]:
    md5, sha = hashlib.md5(), hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            md5.update(chunk)
            sha.update(chunk)
    return md5.hexdigest(), sha.hexdigest()


def copy_tree(src: Path, dst: Path, redact_hits: dict[str, int],
              do_redact: bool, only: list[Path] | None = None) -> int:
    n = 0
    if not src.exists():
        return 0
    dst.mkdir(parents=True, exist_ok=True)
    SKIP = {"__pycache__", ".git", "node_modules", ".pytest_cache", ".dsh"}
    files = only if only is not None else [
        p for p in src.rglob("*")
        if p.is_file() and not (SKIP & set(p.relative_to(src).parts))
        and p.suffix not in {".pyc", ".pyo", ".so", ".zstd"}
    ]
    for p in files:
        if not p.is_file():
            continue
        rel = p.relative_to(src)
        out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        if do_redact and p.suffix.lower() in {".md", ".txt", ".json", ".jsonl", ".py",
                                              ".sh", ".log", ".yml", ".yaml", ".js"}:
            try:
                txt = raw.decode("utf-8")
                new = redact(txt, redact_hits)
                out.write_text(new, encoding="utf-8")
            except UnicodeDecodeError:
                out.write_bytes(raw)
        else:
            out.write_bytes(raw)
        n += 1
    return n


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="WriteUp 打包 + AI 对话记录合规自检")
    ap.add_argument("--since", default=CONTEST_START, help=f"会话起始时间（默认 {CONTEST_START}）")
    ap.add_argument("--until", default="", help="会话截止时间（默认不设）")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="输出目录")
    ap.add_argument("--link", default="", help="百度网盘链接（填进 wp.md 开头）")
    ap.add_argument("--no-redact", action="store_true", help="*** 不脱敏（不推荐）")
    ap.add_argument("--dry-run", action="store_true", help="只看会打包什么 + 支撑性")
    ap.add_argument("--max-mb", type=float, default=0, help="zip 超过该大小就警告")
    args = ap.parse_args(argv)

    def ts(s: str) -> float:
        return datetime.strptime(s, "%Y-%m-%d %H:%M").astimezone().timestamp()

    since = ts(args.since)
    until = ts(args.until) if args.until else None
    out_dir = Path(args.out)
    do_redact = not args.no_redact

    print(f"[i] 工作区   : {WS}")
    print(f"[i] 会话目录 : {SESSIONS_ROOT / workspace_key(WS)}")
    print(f"[i] 时间窗口 : {args.since} → {args.until or '现在'}")
    print(f"[i] 脱敏     : {'否（不推荐！）' if not do_redact else '是'}")
    print()

    sessions = iter_sessions(since, until)
    print(f"[1] 窗口内会话：{len(sessions)} 个（解压中…）")
    global SECRETS
    SECRETS = load_secret_values()
    if do_redact:
        print(f"[i] 按值脱敏：从 creds.env 载入 {len(SECRETS)} 个凭据串（含裸值形态）")
    redact_hits: dict[str, int] = {}
    for s in sessions:
        try:
            raw = decompress_zstd(s["file"])
        except Exception as e:                                    # noqa: BLE001
            print(f"    [!] {s['id']}: 解压失败 {e}")
            continue
        s["raw_bytes"] = raw
        txt = raw.decode("utf-8", "replace")
        s["plain_text_raw"] = txt
        s["plain_text"] = redact(txt, redact_hits) if do_redact else txt
        s["info"] = summarize_jsonl(s["plain_text"])
        it = s["info"]
        print(f"    - {s['id']}  {s['size']//1024}KB→{len(raw)//1024}KB  "
              f"轮={it['assistant']:>3} 工具={it['tool_call']:>3}  "
              f"{(it['title'] or it['first_user'])[:50]}")

    # ---- 已解出题目 + 支撑性自检
    solved = solved_questions()
    print(f"\n[2] 已解出题目：{len(solved)} 道")
    support_rows = []
    for qid, rec in sorted(solved.items(), key=lambda kv: str(kv[0])):
        hits = support_check(qid, sessions)
        ok_sess = "✅" if hits else "❌"
        ok_note = "✅" if rec["notes"] else "❌"
        ok_evid = "✅" if rec["evidence"] else "⚠️"
        if hits and rec["notes"]:
            verdict = "可提交"
        elif hits:
            verdict = "缺笔记（补 notes/<题号>-<题名>.md）"
        else:
            verdict = "★ 会话里没找到该题 → 现在按作弊风险处理"
        support_rows.append((qid, rec.get("title") or "", len(hits), hits,
                             ok_note, ok_evid, verdict))
        print(f"    {qid:<8} {ok_sess} {len(hits):>2} 会话  {ok_note} 笔记  {ok_evid} 证据  → {verdict}")

    if not sessions:
        print("\n[!] 窗口内没有会话 —— 检查 --since，或确认本机确实是跑题的那台")

    if args.dry_run:
        print("\n[i] --dry-run：不写文件。去掉该参数即可真打包。")
        # ★ 假绿修复 2（2026-10-31）：这里原来是
        #     return 0 if all(... ) or not support_rows else 3
        #   `or not support_rows` 让"一道已解出题都没有"也退 0 ⇒ 屏幕上看起来
        #   "全部可提交"，实际整包是空的。空集合不是通过，是红灯 ⇒ 退出码 5。
        #   （"有题但支撑不足"仍然是 3，语义不变。）
        if not support_rows:
            _red_empty()
            return 5
        return 0 if all(r[6] == "可提交" for r in support_rows) else 3

    # ---- 落盘
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    (out_dir / "sessions" / "raw").mkdir(parents=True)
    (out_dir / "sessions" / "plain").mkdir(parents=True)

    print(f"\n[3] 写出会话 → {out_dir}/sessions/")
    for s in sessions:
        (out_dir / "sessions" / "raw" / f"{s['id']}.jsonl.zstd").write_bytes(s["file"].read_bytes())
        (out_dir / "sessions" / "plain" / f"{s['id']}.jsonl").write_text(
            s["plain_text"], encoding="utf-8")

    n_notes = copy_tree(NOTES, out_dir / "notes", redact_hits, do_redact)
    n_scr = copy_tree(SCRIPTS, out_dir / "scripts", redact_hits, do_redact)
    n_evi = copy_tree(EVIDENCE, out_dir / "evidence", redact_hits, do_redact)
    # 41 张逐题证据卡 + EVIDENCE-INDEX + 各题 README（赛后复盘主线，2026-11-01 加）
    n_team = copy_tree(TEAM, out_dir / "team", redact_hits, do_redact) if TEAM.exists() else 0
    wp = WS / "wp.md"
    if wp.exists():
        shutil.copy2(wp, out_dir / "wp.md")
        if do_redact:
            (out_dir / "wp.md").write_text(
                redact((out_dir / "wp.md").read_text(encoding="utf-8"), redact_hits),
                encoding="utf-8")
    print(f"[4] 附带：notes {n_notes} 个 / scripts {n_scr} 个 / evidence {n_evi} 个 / team {n_team} 个"
          f"{' / wp.md' if wp.exists() else '（无 wp.md）'}")

    # ---- 会话索引 + 支撑矩阵
    idx = ["# AI 对话记录索引（DSH / DeepSeek Harness）", "",
           f"- 打包时间：{datetime.now().astimezone().isoformat(timespec='seconds')}",
           f"- 会话来源：`~/.dsh/sessions/{workspace_key(WS)}/`",
           "- 原始格式：`session.v3.jsonl.zstd`（多帧追加的 JSONL，共 "
           f"{len(sessions)} 个会话）",
           "- 可读格式：`plain/*.jsonl`（已解压；脱敏见 `REDACTION.md`）", "",
           "| 会话 id | 轮次 | 工具调用 | 开始（本地） | 主题 |",
           "|---|---|---|---|---|"]
    for s in sessions:
        it = s["info"]
        when = datetime.fromtimestamp(s["mtime"]).strftime("%m-%d %H:%M")
        idx.append(f"| `{s['id']}` | {it['assistant']} | {it['tool_call']} | {when} | "
                   f"{(it['title'] or it['first_user'] or '')[:60].replace('|', '/')} |")
    idx += ["", "## 每道已解出题 ↔ 会话支撑矩阵", "",
            "| 题号 | 题名 | 提及会话数 | 会话 id | 笔记 | 证据 | 结论 |",
            "|---|---|---|---|---|---|---|"]
    for qid, title, n, hits, ok_note, ok_evid, verdict in support_rows:
        ids = ", ".join(f"`{h}`" for h in hits[:4]) + (" …" if len(hits) > 4 else "")
        idx.append(f"| {qid} | {title} | {n} | {ids or '—'} | {ok_note} | {ok_evid} | {verdict} |")
    (out_dir / "sessions" / "INDEX.md").write_text("\n".join(idx) + "\n", encoding="utf-8")

    # ---- 脱敏记录
    red_lines = ["# 脱敏记录", "",
                 "会话原文里必然出现本队凭据（我们讨论/写入过它们）。",
                 "**只抹掉凭据值，其余完整保留**，替换处写成 `<REDACTED-...>` 便于核对。", ""]
    if do_redact:
        if redact_hits:
            red_lines += ["| 被替换的内容 | 处数 | 理由 |", "|---|---|---|"]
            why = {
                "LOGIN-TOKEN": "平台登录 token（可冒充本队提交）",
                "BARE-LOGIN-TOKEN": "同上，裸值形态（没有 login:match_ 前缀）",
                "TEAMTOKEN": "本队 teamtoken（他人可代打 teamtoken 题）",
                "BARE-TEAMTOKEN": "同上，裸值形态",
                "CDN-COOKIE": "加速乐反爬 cookie（低危，一并抹掉更干净）",
                "BARE-CDN-COOKIE": "同上，裸值形态",
                "SECRET": "其它凭据",
                "平台登录 token（拿它可冒充本队提交）": "平台登录 token（可冒充本队提交）",
                "本队 teamtoken（题面要求提供，泄露=他人可代打）": "本队 teamtoken（他人可代打）",
                "加速乐反爬 cookie（低危，一并抹掉更干净）": "反爬 cookie",
                "裸 CDN cookie 值": "反爬 cookie",
            }
            for name, cnt in sorted(redact_hits.items()):
                key = name.split("：")[-1]        # 去掉「按值脱敏：」前缀再查理由
                red_lines.append(f"| {name} | {cnt} | {why.get(key, why.get(name, ''))} |")
        else:
            red_lines.append("（本次扫描未命任何凭据模式）")
    else:
        red_lines.append("**本次以 --no-redact 打包：凭据原样保留。**")
    red_lines += ["", "## 有意保留未脱敏的项", "",
                  "| 项 | 为什么不抹 |", "|---|---|",
                  "| 比赛 `k`（`url_key`，地址栏那串） | 它不是登录态：实测匿名只带 `k` "
                  "只能读比赛详情/分类，读题、起容器、提交全部 `code 100/101`。"
                  "保留它评委才看得懂请求是在打哪场比赛。 |",
                  "| 平台域名、接口路径、签名 salt | 与本题解出过程无关的公开信息，"
                  "且是复现请求所必需。 |"]
    (out_dir / "REDACTION.md").write_text("\n".join(red_lines) + "\n", encoding="utf-8")

    # ---- zip + md5
    zpath = out_dir.parent / f"qwb2026-writeup-{datetime.now().strftime('%Y%m%d-%H%M')}.zip"
    print(f"\n[5] 压包 → {zpath}")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in sorted(out_dir.rglob("*")):
            if p.is_file():
                z.write(p, arcname=str(p.relative_to(out_dir)))
    md5, sha = sha_md5(zpath)
    size_mb = zpath.stat().st_size / 1048576
    print(f"    大小 {size_mb:.1f} MB   md5 {md5}")
    if args.max_mb and size_mb > args.max_mb:
        print(f"    [!] 超过 {args.max_mb} MB：网盘上传可能慢/失败，考虑拆分")

    # ---- 可贴的 wp 头
    link = args.link or "<把百度网盘链接+提取码填这里>"
    # ★ 2026-10-31 08:42 平台公告给了**官方示例格式**，照它的字面写，别自创：
    #   会话附件百度网盘链接：https://pan.baidu.com/xxxxxx md5值：xxxxxxx
    header = (
        "<!-- ↓↓↓ 开篇必须写这一行（照平台公告的示例格式）↓↓↓ -->\n"
        f"会话附件百度网盘链接：{link} md5值：{md5}\n"
        "\n"
        f"<!-- 备用/补充信息（保留便于核对，不影响格式要求） -->\n"
        f"- 压缩包 SHA256：`{sha}`\n"
        f"- **包内文件数**：{sum(1 for p in out_dir.rglob('*') if p.is_file())}，"
        f"大小 {size_mb:.1f} MB\n"
        "- 说明：本队使用 AI 辅助解题，压缩包内含**每个会话一份完整 JSONL 对话记录**"
        "（`sessions/plain/*.jsonl`，原始 `sessions/raw/*.jsonl.zstd` 一并保留）、"
        "每题笔记、解题脚本与提交证据；脱敏范围见包内 `REDACTION.md`。\n"
        "<!-- ↑↑↑ 以上三行放进 wp.md 最顶部 ↑↑↑ -->\n"
    )
    (out_dir / "WP-HEADER.md").write_text(header, encoding="utf-8")

    print("\n" + "=" * 72)
    print(header)
    print("=" * 72)
    print(f"\n[✓] 目录：{out_dir}")
    print(f"[✓] 压缩包：{zpath}（{size_mb:.1f} MB, md5={md5}）")
    print("    下一步：")
    print("      1) 补 wp.md（每题一节，见 notes/methods/deliverables.md 的格式）")
    print("      2) 把 WP-HEADER.md 三行粘到 wp.md 最顶部，并填上网盘链接")
    print("      3) 传网盘后再跑一次本脚本 --link '<链接+提取码>'，确保 md5 与正文一致")
    # ★ 假绿修复 2（2026-10-31）：真打包路径原来末尾是
    #     if support_rows and any(...): return 3
    #     return 0
    #   support_rows 为空时同样落到 `return 0` ⇒ 整包是空的却报通过。
    #   顺序是"先判空（红灯 5），再判支撑不足（3），最后才是 0"：
    #     退出码 0 = 每题都可提交；3 = 有题但支撑不足；5 = 一道已解出题都没有。
    if not support_rows:
        _red_empty()
        return 5
    if any(r[6] != "可提交" for r in support_rows):
        print("\n[!] 有题目的支撑性不足（见 INDEX.md 的矩阵）——"
              "这类题按裁判口径有作弊风险，先补材料再交")
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
