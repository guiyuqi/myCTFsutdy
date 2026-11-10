#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""12086 · NeuralVault —— 可复现解题脚本（已实测通过 2026-10-24）
flag = DASCTF{86111530176209339321986958990035}

目标：向 /api/submit 提交三件套 {poisoned_clients, audit_key, bypass_vector}，服务端校验通过即回 flag。

完整流程：
  1) GET /api/info           契约；**每次调用都铸新 token**，后续请求带 `X-Audit-Token: <token>`
  2) GET /api/debug          诱饵：suspected_clients=[2,6] 是 **0-indexed**，提交用 1-indexed => [3,7]
  3) GET /api/detector/info + /api/detector/base_sample
                            对抗约束：eps=0.15、≤12 维；要求 base_sample 的 class0(normal) >= 0.6
  4) 解 bypass_vector        /api/detector/query 返回 probs（连续值）⇒ 有限差分 + L0/L∞ 投影梯度上升
                            实测 12 维、L∞=0.15，class0 0.2315 -> 0.7063
  5) GET /api/federation/log **关键端点（两段式前缀）** -> 1.7 MB ZIP，300 个 .npy
                            = 10 clients × 5 rounds × {dW1(32,48) dW2(48,48) dW3(48,16) db1 db2 db3(16)}
  6) 定位投毒方             末层 dW3 的**行 L2 范数**离群 => c3 / c7（hint: row-wise L2 norms … last-layer）
  7) 读 audit_key           r2 轮 c3/c7 的 dW3 **前 8 行**行范数为精确整数
                            c3=[5,12,13,16,1,16,1,16]  c7=[8,7,1,5,1,6,7,7]
                            值域 1..16 ⇒ nibble = norm-1 ⇒ "4bcf0f0f"+"76040566"="4bcf0f0f76040566"
  8) POST /api/submit      -> {"flag":"DASCTF{...}","status":"success"}

用法:
  python3 scripts/12086-solve.py --base http://<host>:<port>      # 在线全流程
  python3 scripts/12086-solve.py --zip evidence/12086-federation-log.zip   # 仅离线复算 key
"""
from __future__ import annotations

import argparse
import io
import json
import re
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

import numpy as np

WS = Path(__file__).resolve().parent.parent
EV = WS / "evidence"
UA = "curl/8.5.0"
EPS, KDIM, TARGET_P0 = 0.15, 12, 0.60
CLIENTS_1IDX = [3, 7]                 # 服务端确认口径（1-indexed）


# ------------------------------------------------------------------ HTTP
class Client:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.tok: str | None = None
        self.used = 0

    def mint(self) -> str:
        with urllib.request.urlopen(urllib.request.Request(
                self.base + "/api/info", headers={"User-Agent": UA}), timeout=15) as r:
            js = json.loads(r.read())
        self.tok, self.used = js["token"], 0
        return self.tok

    def req(self, path: str, body=None, method=None):
        if not self.tok:
            self.mint()
        data = json.dumps(body).encode() if body is not None else None
        h = {"User-Agent": UA, "Accept": "*/*", "X-Audit-Token": self.tok}
        if data:
            h["Content-Type"] = "application/json"
        r = urllib.request.Request(self.base + path, data=data, headers=h,
                                   method=method or ("POST" if data else "GET"))
        for k in range(3):
            try:
                with urllib.request.urlopen(r, timeout=90) as resp:
                    return resp.status, resp.read()
            except urllib.error.HTTPError as e:
                return e.code, e.read()
            except Exception:
                if k == 2:
                    raise
                time.sleep(1.0)

    def probs(self, x) -> np.ndarray:
        if self.used >= 380:
            self.mint()
        st, b = self.req("/api/detector/query", {"x": [float(v) for v in np.ravel(x)]})
        if st != 200:
            raise RuntimeError(f"detector HTTP {st}: {b[:120]!r}")
        self.used += 1
        return np.asarray(json.loads(b)["probs"], dtype=float)

    def submit(self, key: str, vec, clients=CLIENTS_1IDX):
        st, b = self.req("/api/submit", {"poisoned_clients": list(clients), "audit_key": key,
                                        "bypass_vector": [float(v) for v in vec]})
        return st, b.decode("utf-8", "replace")


# ------------------------------------------------- 对抗样本（bypass_vector）
def solve_bypass(c: Client, base_sample: np.ndarray, verbose=True):
    x0 = np.asarray(base_sample, dtype=float)
    p0 = float(c.probs(x0)[0])
    if verbose:
        print(f"  base_sample p(class0)={p0:.4f}")
    best, best_p = x0.copy(), p0
    for it in range(6):
        cur = float(c.probs(best)[0])
        g = np.zeros(x0.size)
        h = 0.05
        eye = np.eye(x0.size) * h
        for i in range(x0.size):
            g[i] = (float(c.probs(best + eye[i])[0]) - cur) / h
            time.sleep(0.12)
        mask = np.argsort(-np.abs(g))[:KDIM]
        d = np.zeros(x0.size)
        d[mask] = EPS * np.sign(g[mask])
        cand = x0 + d
        pc = float(c.probs(cand)[0])
        if verbose:
            print(f"  轮{it + 1}: p0={pc:.4f} dims={int((np.abs(cand - x0) > 1e-12).sum())} "
                  f"Linf={np.abs(cand - x0).max():.3f}")
        if pc > best_p:
            best, best_p = cand, pc
        if best_p >= TARGET_P0:
            break
    assert best_p >= TARGET_P0, f"未达 {TARGET_P0}（得 {best_p}）"
    return best, best_p


# -------------------------------------------- 联邦日志分析（离线核心）
def load_fedlog(zip_bytes: bytes) -> dict[tuple[int, int, str], np.ndarray]:
    out = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for name in z.namelist():
            m = re.match(r"c(\d+)_r(\d+)_(\w+)\.npy$", name)
            if not m:
                continue
            with z.open(name) as f:
                out[(int(m.group(1)), int(m.group(2)), m.group(3))] = np.load(f)
    return out


def find_poisoned(data) -> list[tuple[int, float]]:
    """末层 dW3 行范数的 max/median 比值：投毒方植入大范数行，比值远超 1。"""
    res = []
    for c in sorted({k[0] for k in data}):
        rn = np.mean([np.linalg.norm(data[(c, r, "dW3")], axis=1)
                      for r in range(5) if (c, r, "dW3") in data], axis=0)
        res.append((c, float(rn.max() / (np.median(rn) + 1e-12))))
    return sorted(res, key=lambda t: -t[1])


def extract_key(data, suspects: list[int], hexdigits="0123456789abcdef"):
    """在存在"精确整数行范数"的那一轮，从两个投毒方 dW3 的前 8 行读 nibble（norm-1）。"""
    for r in sorted({k[1] for k in data}):
        halves, detail = [], {}
        for c in suspects:
            W = data.get((c, r, "dW3"))
            if W is None:
                break
            rn = np.linalg.norm(W, axis=1)
            head = rn[:8]
            if not np.all(np.abs(head - np.round(head)) < 1e-9):
                break
            if np.any(np.round(head) < 1) or np.any(np.round(head) > 16):
                break
            if np.max(np.delete(rn, np.arange(8))) > 0.05:      # 其余行必须是噪声级
                break
            halves.append("".join(hexdigits[(int(round(v)) - 1) & 0xF] for v in head))
            detail[c] = [int(round(v)) for v in head]
        if len(halves) == 2 and len("".join(halves)) == 16:
            return "".join(halves), {"round": r, "norms": detail, "clients": suspects}
    raise RuntimeError("未在日志中找到 16 位 hex 植入结构")


# ---------------------------------------------------------------- 主流程
def run_online(base: str) -> int:
    c = Client(base)
    print("[1] /api/info …")
    st, b = c.req("/api/info")
    info = json.loads(b)
    print(f"    token={info['token']} input_dim={info['input_dim']}")
    print("[2] /api/debug（0-indexed 诱饵）…")
    st, b = c.req("/api/debug")
    print(f"    {b.decode('utf-8', 'replace')[:160]}")

    print("[3] /api/detector/info + base_sample …")
    st, b = c.req("/api/detector/info")
    print(f"    requirement: {json.loads(b)['bypass_requirement']}")
    st, b = c.req("/api/detector/base_sample")
    bs = np.asarray(json.loads(b)["base_sample"], dtype=float)

    print("[4] 解 bypass_vector …")
    vec, p0 = solve_bypass(c, bs)
    print(f"    -> p(class0)={p0:.4f}（要求 >= {TARGET_P0}）")
    EV.mkdir(exist_ok=True)
    (EV / "12086-bypass-vector.json").write_text(
        json.dumps({"base_sample": bs.tolist(), "bypass_vector": vec.tolist(),
                    "p_class0": p0}, indent=2), encoding="utf-8")

    print("[5] 下载 /api/federation/log（关键端点）…")
    st, zbytes = c.req("/api/federation/log")
    print(f"    HTTP {st}, {len(zbytes)} B")
    assert st == 200 and zbytes[:2] == b"PK", "日志下载失败（检查 X-Audit-Token / 容器 ready）"
    (EV / "12086-federation-log.zip").write_bytes(zbytes)

    print("[6] 分析联邦日志 …")
    data = load_fedlog(zbytes)
    print(f"    张量数={len(data)}（期望 10×5×6=300）")
    ranking = find_poisoned(data)
    print("    dW3 行范数比值: " + ", ".join(f"c{c}:{v:.2f}" for c, v in ranking[:4]))
    suspects = sorted(c for c, _ in ranking[:2])
    print(f"    => 投毒方（文件 0-indexed）= {suspects}；提交口径（1-indexed）= {suspects}")

    print("[7] 提取 audit_key …")
    key, detail = extract_key(data, suspects)
    print(f"    round={detail['round']} 行范数={detail['norms']}")
    print(f"    audit_key = {key}")

    print("[8] 提交三件套 …")
    st, r = c.submit(key, vec, suspects)
    print(f"    [{st}] {r}")
    m = re.search(r"[A-Za-z]+\{[^}]+\}", r)
    if m:
        print(f"\n*** FLAG = {m.group(0)}")
        (EV / "12086-submit-success.txt").write_text(r, encoding="utf-8")
        return 0
    return 1


def run_offline(zip_path: str) -> int:
    data = load_fedlog(Path(zip_path).read_bytes())
    print(f"张量数={len(data)}")
    ranking = find_poisoned(data)
    print("dW3 行范数比值: " + ", ".join(f"c{c}:{v:.2f}" for c, v in ranking))
    suspects = sorted(c for c, _ in ranking[:2])
    key, detail = extract_key(data, suspects)
    print(f"投毒方（文件标签）={suspects}  round={detail['round']}  行范数={detail['norms']}")
    print(f"audit_key = {key}")
    print("提交口径：poisoned_clients=[3,7]、audit_key 如上、bypass_vector 见 evidence/12086-bypass-vector.json")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="")
    ap.add_argument("--zip", default="")
    a = ap.parse_args()
    if a.zip:
        return run_offline(a.zip)
    if not a.base:
        print(__doc__)
        return 2
    return run_online(a.base)


if __name__ == "__main__":
    sys.exit(main())
