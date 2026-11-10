#!/usr/bin/env bash
# 方案 A：修 planner 凭据 + 启用候选门 + 把 planner 冒烟接进 preflight。
# 幂等：重复执行不会重复插入；每次改动前备份到 <file>.bak-<stamp>。
# 用法： bash apply-A.sh            # 应用
#        bash apply-A.sh --check    # 只报告当前状态，不改
set -euo pipefail

ROOT=${ROOT:-$HOME/.ctfagent}
STAMP=$(date +%Y%m%d-%H%M%S)
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

say() { printf '%s\n' "$*"; }

# ---------- 0. 现状 ----------
say "== 现状 =="
python3 - "$ROOT" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
cfg = json.loads((root/"state/muteki/_worker_config.json").read_text())
for role in ("planner", "titler"):
    p = (cfg.get("llm_profiles") or {}).get(role) or {}
    print(f"  llm_profiles.{role}: model={p.get('model')!r} endpoint_id={p.get('endpoint_id')!r}")
start = (root/"start.sh").read_text()
print("  start.sh 含 MUTEKI_CTFAGENT_REPO:", "MUTEKI_CTFAGENT_REPO" in start)
pf = (root/"ctfagent/preflight.py").read_text()
print("  preflight 含 _check_planner:", "_check_planner" in pf)
print("  tools/planner_smoke.py 存在:", (root/"tools/planner_smoke.py").is_file())
PY
if [ "$CHECK" = 1 ]; then exit 0; fi

# ---------- 1. 配置：planner/titler 绑账号 ----------
cp -a "$ROOT/state/muteki/_worker_config.json" "$ROOT/state/muteki/_worker_config.json.bak-$STAMP"
python3 - "$ROOT" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])/"state/muteki/_worker_config.json"
d = json.loads(p.read_text(encoding="utf-8"))
llm = d.setdefault("llm_profiles", {})
for role in ("planner", "titler"):
    prof = llm.setdefault(role, {})
    prof["endpoint_id"] = "account:pi-main"
p.write_text(json.dumps(d, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
print("  写入 planner/titler endpoint_id=account:pi-main")
PY

# ---------- 2. start.sh：启用候选门 ----------
cp -a "$ROOT/start.sh" "$ROOT/start.sh.bak-$STAMP"
python3 - "$ROOT" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])/"start.sh"
s = p.read_text(encoding="utf-8")
if "MUTEKI_CTFAGENT_REPO" in s:
    print("  start.sh 已含门禁环境，跳过")
else:
    anchor = '  CTFAGENT_DB="$ROOT/state/ctfagent.sqlite3" \\\n'
    assert anchor in s, "start.sh 结构变了，请人工看"
    add = (anchor
           + '  MUTEKI_CTFAGENT_REPO="$ROOT" \\\n'
           + '  MUTEKI_CTFAGENT_DB="$ROOT/state/ctfagent.sqlite3" \\\n'
           + '  MUTEKI_CTFAGENT_ENFORCE="${MUTEKI_CTFAGENT_ENFORCE:-auto}" \\\n')
    p.write_text(s.replace(anchor, add, 1), encoding="utf-8")
    print("  start.sh 已加 MUTEKI_CTFAGENT_REPO/DB/ENFORCE")
PY

# ---------- 3. 放入 planner 冒烟脚本 ----------
mkdir -p "$ROOT/tools"
install -m 755 "$HERE/planner_smoke.py" "$ROOT/tools/planner_smoke.py"
say "  已安装 tools/planner_smoke.py"

# ---------- 4. preflight.py：新增 planner 检查 ----------
cp -a "$ROOT/ctfagent/preflight.py" "$ROOT/ctfagent/preflight.py.bak-$STAMP"
python3 - "$ROOT" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])/"ctfagent/preflight.py"
s = p.read_text(encoding="utf-8")
if "_check_planner" in s:
    print("  preflight.py 已有 _check_planner，跳过")
else:
    fn = '''def _check_planner(result: PreflightResult, repo_root: Path, *, smoke: bool = False) -> None:
    """planner 可用性（2026-11-08 复盘：641/641 次 planner 返回 0 字符，整场没有一次规划）。

    两层：配置层（endpoint_id / 账号 / key）+ 可选真冒烟（--planner-smoke 跑一次真 planner）。
    失败是 blocking：这项红着就不该开赛。
    """
    state = Path(os.environ.get("MUTEKI_STATE_ROOT") or (repo_root / "state" / "muteki"))
    cfg_path = state / "_worker_config.json"
    if not cfg_path.is_file():
        result.add("planner", WARN, f"找不到 {cfg_path}，跳过")
        return
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        result.add("planner", FAIL, f"{cfg_path} 解析失败：{exc}", blocking=True)
        return
    problems: list[str] = []
    for role in ("planner", "titler"):
        profile = dict((cfg.get("llm_profiles") or {}).get(role) or {})
        endpoint = str(profile.get("endpoint_id") or profile.get("credential_id") or "").strip()
        if not endpoint:
            problems.append(f"llm_profiles.{role}.endpoint_id 为空")
            continue
        account = (endpoint.split(":", 1)[1]
                   if endpoint.startswith(("account:", "endpoint:")) else endpoint)
        key = state / "_secrets" / "accounts" / account / "API_KEY"
        if not key.is_file() or key.stat().st_size < 8:
            problems.append(f"{role} 的账号 {account!r} 缺 API_KEY")
    if problems:
        result.add("planner", FAIL,
                   "；".join(problems) + "（planner 无账号 ⇒ Pi 无 provider ⇒ 静默退出）",
                   blocking=True)
        return
    if not smoke:
        result.add("planner", OK, "planner/titler 已绑账号（未跑真冒烟，加 --planner-smoke）")
        return
    script = repo_root / "tools" / "planner_smoke.py"
    if not script.is_file():
        result.add("planner.smoke", FAIL, f"缺少 {script}", blocking=True)
        return
    venv = repo_root / ".s1-venv" / "bin" / "python"
    python = str(venv if venv.is_file() else sys.executable)
    try:
        proc = subprocess.run([python, str(script), "--json"], capture_output=True,
                              text=True, timeout=300)
    except subprocess.SubprocessError as exc:
        result.add("planner.smoke", FAIL, f"冒烟执行失败：{exc}", blocking=True)
        return
    tail = (proc.stdout or proc.stderr or "").strip().splitlines()
    detail = (tail[-1] if tail else "")[:400]
    if proc.returncode == 0:
        result.add("planner.smoke", OK, detail or "planner 冒烟通过")
    else:
        result.add("planner.smoke", FAIL, f"冒烟失败 rc={proc.returncode}：{detail}", blocking=True)


'''
    anchor = "def run_preflight("
    assert anchor in s
    s = s.replace(anchor, fn + anchor, 1)
    s = s.replace("    require_qwb: bool = False,\n) -> PreflightResult:",
                  "    require_qwb: bool = False,\n    planner_smoke: bool = False,\n) -> PreflightResult:", 1)
    s = s.replace("    _check_secrets(result, root)\n",
                  "    _check_secrets(result, root)\n    _check_planner(result, root, smoke=planner_smoke)\n", 1)
    p.write_text(s, encoding="utf-8")
    print("  preflight.py 已加 _check_planner 并接入 run_preflight")
PY

# ---------- 5. cli.py：--planner-smoke ----------
cp -a "$ROOT/ctfagent/cli.py" "$ROOT/ctfagent/cli.py.bak-$STAMP"
python3 - "$ROOT" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])/"ctfagent/cli.py"
s = p.read_text(encoding="utf-8")
if "--planner-smoke" in s:
    print("  cli.py 已有 --planner-smoke，跳过")
else:
    s = s.replace(
        '    sp.add_argument("--require-qwb", action="store_true", help="i春秋 赛事：qwb/creds 缺失即失败")\n',
        '    sp.add_argument("--require-qwb", action="store_true", help="i春秋 赛事：qwb/creds 缺失即失败")\n'
        '    sp.add_argument("--planner-smoke", action="store_true",\n'
        '                    help="真跑一次 planner（用账号凭据+pi，不依赖后端）")\n', 1)
    s = s.replace("        require_qwb=args.require_qwb,\n    )",
                  "        require_qwb=args.require_qwb,\n"
                  "        planner_smoke=bool(getattr(args, \"planner_smoke\", False)),\n    )", 1)
    p.write_text(s, encoding="utf-8")
    print("  cli.py 已加 --planner-smoke")
PY

# ---------- 6. 回读校验 ----------
say "== 应用后 =="
python3 - "$ROOT" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
cfg = json.loads((root/"state/muteki/_worker_config.json").read_text())
for role in ("planner", "titler"):
    p = (cfg.get("llm_profiles") or {}).get(role) or {}
    print(f"  llm_profiles.{role}: endpoint_id={p.get('endpoint_id')!r} model={p.get('model')!r}")
s = (root/"start.sh").read_text()
print("  start.sh 含 REPO/DB/ENFORCE:",
      all(k in s for k in ("MUTEKI_CTFAGENT_REPO", "MUTEKI_CTFAGENT_DB", "MUTEKI_CTFAGENT_ENFORCE")))
print("  preflight 含 _check_planner:", "_check_planner" in (root/"ctfagent/preflight.py").read_text())
print("  cli 含 --planner-smoke:", "--planner-smoke" in (root/"ctfagent/cli.py").read_text())
PY
say "备份后缀：.bak-$STAMP"
