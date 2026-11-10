#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""planner 冒烟：证明"planner 这条链真的能规划"，不需要 muteki 后端。

它只做四件事，但做完整：
  1. 读 `<state>/_worker_config.json` 的 `llm_profiles.planner.endpoint_id`（必须形如 `account:<id>`）；
  2. 用 muteki 自己的 `runtime_env_for_engine` stage 出 `<work>/pi-agent/models.json`
     （凭据写在 models.json 的 providers.<provider>.apiKey，这是 Pi 的唯一凭据通道）；
  3. 用一份**真实录下来的 planner 输入**（`tools/planner_smoke_fixture/`）跑一次真 planner；
  4. 断言 `draft.json` 里 `committed=true` 且 operations 非空。

为什么用录制的输入而不是现造：2026-11-08 复盘时我用现造的小图试过，扩展的 open_step/commit
会因缺少真实字段报 TypeError；用真录的输入才能测到"真 planner 会不会提交"这一件事。

退出码：0 通过 / 3 失败（与 preflight 的 NO-GO 对齐）/ 2 用法或环境错。
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

EXIT_OK, EXIT_USAGE, EXIT_FAIL = 0, 2, 3


def state_root() -> Path:
    env = os.environ.get("MUTEKI_STATE_ROOT", "").strip()
    if env:
        return Path(env).expanduser()
    return Path.home() / ".ctfagent" / "state" / "muteki"


def roothome() -> Path:
    env = os.environ.get("CTFAGENT_HOME", "").strip()
    return Path(env).expanduser() if env else Path.home() / ".ctfagent"


def read_config() -> dict:
    p = state_root() / "_worker_config.json"
    if not p.is_file():
        raise SystemExit(f"[FAIL] 找不到 {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def planner_account(cfg: dict) -> tuple[str, str]:
    profile = dict((cfg.get("llm_profiles") or {}).get("planner") or {})
    endpoint = str(profile.get("endpoint_id") or profile.get("credential_id") or "").strip()
    model = str(profile.get("model") or "").strip()
    if not endpoint:
        raise SystemExit(
            "[FAIL] llm_profiles.planner.endpoint_id 为空 —— 这正是 2026-11-08 那场 planner 全灭的根因"
            "（planner 拿不到账号 ⇒ Pi 无 provider ⇒ 静默退出）")
    account = endpoint.split(":", 1)[1] if endpoint.startswith(("account:", "endpoint:")) else endpoint
    if not account:
        raise SystemExit(f"[FAIL] 无法从 endpoint_id={endpoint!r} 解析账号 id")
    return account, model


def stage_agent_dir(venv_python: Path, account: str, model: str, work: Path) -> dict:
    """调 muteki 自己的 resolver 生成 pi-agent/models.json（与 worker 同一条凭据路径）。"""
    engine_root = roothome() / "engine" / "muteki"
    code = f"""
import json, pathlib, sys
sys.path.insert(0, {str(engine_root)!r})
from muteki.solver.credential_accounts import runtime_env_for_engine
r = runtime_env_for_engine(
    "pi",
    account_root=pathlib.Path({str(state_root() / "_secrets" / "accounts")!r}),
    account_id={account!r},
    env={{}},
    agent_state_dir=pathlib.Path({str(work / "pi-agent")!r}),
    model={model!r} or None,
)
print(json.dumps({{"account": r.account_id, "env": dict(r.env or {{}})}}, ensure_ascii=False))
"""
    proc = subprocess.run([str(venv_python), "-c", code], capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise SystemExit(f"[FAIL] runtime_env_for_engine 失败：{(proc.stderr or '').strip()[:500]}")
    payload = json.loads(proc.stdout.strip().splitlines()[-1])
    env = payload["env"]
    models = work / "pi-agent" / "models.json"
    if not models.is_file():
        raise SystemExit(f"[FAIL] resolver 没有生成 {models}（账号 {payload['account']!r} 未被识别）")
    data = json.loads(models.read_text())
    providers = list((data.get("providers") or {}).keys())
    key_len = 0
    for name in providers:
        key_len = max(key_len, len(str((data["providers"][name] or {}).get("apiKey") or "")))
    if key_len < 8:
        raise SystemExit("[FAIL] models.json 里没有有效 apiKey")
    return {"env": env, "providers": providers, "api_key_len": key_len}


def load_fixture(work: Path) -> str:
    """取录制好的 planner 输入；缺了就报错（不做假图，假图测不出问题）。"""
    fx = roothome() / "tools" / "planner_smoke_fixture"
    graph_p, summary_p = fx / "graph.json", fx / "summary.yaml"
    if not graph_p.is_file() or not summary_p.is_file():
        raise SystemExit(f"[FAIL] 缺 fixture：{fx}/graph.json + summary.yaml")
    graph = json.loads(graph_p.read_text(encoding="utf-8"))
    (work / "graph.json").write_text(json.dumps(graph, ensure_ascii=False), encoding="utf-8")
    return summary_p.read_text(encoding="utf-8")


def system_prompt() -> str:
    engine_root = roothome() / "engine" / "muteki"
    code = ("import sys; sys.path.insert(0, %r);"
            "from muteki.solver.pi_decide import _pi_system_prompt;"
            "print(_pi_system_prompt(mode='ctf', challenger=False))") % str(engine_root)
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    if proc.returncode != 0 or not proc.stdout.strip():
        raise SystemExit(f"[FAIL] 抽不到 planner system prompt：{(proc.stderr or '').strip()[:300]}")
    return proc.stdout.strip()


def run_planner(work: Path, env: dict, timeout: int) -> tuple[int, str]:
    root = roothome()
    ext = root / "engine" / "muteki" / "muteki" / "solver" / "pi_decide_extension.ts"
    if not ext.is_file():
        raise SystemExit(f"[FAIL] 找不到 planner 扩展：{ext}")
    summary = load_fixture(work)
    draft = work / "draft.json"
    draft.write_text('{"committed": false, "operations": []}', encoding="utf-8")

    run_env = dict(os.environ)
    run_env.update(env)
    run_env.update({
        "MUTEKI_DECIDE_DRAFT_PATH": str(draft),
        "MUTEKI_DECIDE_GRAPH_PATH": str(work / "graph.json"),
        "MUTEKI_DECIDE_MAX_STEPS": "4",
    })
    pi = root / ".s1-tools" / "bin" / "pi"
    if not pi.is_file():
        raise SystemExit(f"[FAIL] 找不到 pi：{pi}")
    argv = [str(pi), "-p", "--mode", "json", "--no-session", "--no-context-files",
            "--no-builtin-tools", "--extension", str(ext),
            "--tools", "read,open_step,peek_step,preview,commit,satisfy_goal",
            "--system-prompt", system_prompt()]
    argv += ["--provider", run_env.get("MUTEKI_PI_PROVIDER") or "muteki"]
    model = run_env.get("MUTEKI_PI_MODEL") or ""
    if model:
        argv += ["--model", model]
    started = time.time()
    proc = subprocess.run(argv, input=summary, capture_output=True, text=True,
                          timeout=timeout, env=run_env)
    elapsed = time.time() - started
    tail = "\n".join((proc.stdout or "").strip().splitlines()[-3:])[:600]
    if proc.returncode != 0:
        return EXIT_FAIL, (f"pi rc={proc.returncode}（{elapsed:.1f}s）\n"
                           f"stderr: {(proc.stderr or '')[:400]}\n{tail}")
    data = json.loads(draft.read_text())
    ops = [str(op.get("op")) for op in (data.get("operations") or []) if isinstance(op, dict)]
    if not data.get("committed") or not ops:
        return EXIT_FAIL, (f"planner 未提交（{elapsed:.1f}s）：committed={data.get('committed')} "
                           f"ops={len(ops)}\n{tail}")
    return EXIT_OK, f"planner 提交成功（{elapsed:.1f}s）：operations={ops}"


def main() -> int:
    ap = argparse.ArgumentParser(description="planner 冒烟（不依赖 muteki 后端）")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--workdir", default="", help="临时目录（默认系统临时目录；沙箱里请指到可写目录）")
    ap.add_argument("--keep", action="store_true", help="保留临时目录")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    cfg = read_config()
    account, model = planner_account(cfg)
    if not model:
        print("[WARN] planner.model 为空，将用账号默认模型", file=sys.stderr)
    venv = roothome() / ".s1-venv" / "bin" / "python"
    python = venv if venv.is_file() else Path(sys.executable)
    created = not args.workdir
    work = Path(args.workdir).expanduser() if args.workdir else Path(
        tempfile.mkdtemp(prefix="planner-smoke-"))
    work.mkdir(parents=True, exist_ok=True)
    try:
        info = stage_agent_dir(python, account, model, work)
        rc, detail = run_planner(work, info["env"], args.timeout)
        payload = {"ok": rc == 0, "account": account, "model": model or "(default)",
                   "provider": info["providers"], "api_key_len": info["api_key_len"],
                   "detail": detail, "workdir": str(work)}
        if args.json:
            print(json.dumps(payload, ensure_ascii=False))
        else:
            print(f"[{'GO  ' if rc == 0 else 'FAIL'}] planner · account={account} · "
                  f"model={model or '(default)'} · provider={info['providers']} · "
                  f"key={info['api_key_len']}B")
            print(f"        {detail}")
        return rc
    finally:
        if created and not args.keep:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
