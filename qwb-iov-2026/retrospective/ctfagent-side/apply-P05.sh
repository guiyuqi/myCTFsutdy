#!/usr/bin/env bash
# P0-5：打开 pi worker 的技能目录（muteki 自带的 ctf triage playbook 等）。
# 根因：PiDriver._CONTEXT_FLAGS 写死 --no-skills，把 worker_skills 投影到 .pi/skills 的技能全关了；
# 而 _permission_flags 本来已给 --approve，所以只差这一个 flag。
# 默认开启技能；MUTEKI_PI_SKILLS=0 可恢复旧行为（单次 Run 生效，重启后端后再次读取）。
set -euo pipefail
ROOT=${ROOT:-$HOME/.ctfagent}
ENGINE=${ENGINE:-$ROOT/engine/muteki}
STAMP=$(date +%Y%m%d-%H%M%S)
say() { printf '%s\n' "$*"; }
FILE="$ENGINE/muteki/solver/cli_engines/engines/pi.py"

say "== 现状 =="
grep -n 'no-skills' "$FILE" | sed 's/^/  /' || true
if [ "${1:-}" = "--check" ]; then exit 0; fi

if ! grep -q "_pi_skills_enabled" "$FILE"; then cp -a "$FILE" "$FILE.bak-$STAMP"; fi

# ---------- 1. 打补丁：--no-skills 变成可关（默认关闭=技能开启） ----------
~/.ctfagent/.s1-venv/bin/python - "$FILE" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
s = p.read_text(encoding="utf-8")
if "_pi_skills_enabled" in s:
    print("  已打过补丁，跳过")
    raise SystemExit(0)

# 1a. 增加 import os（若没有）
if "\nimport os\n" not in s:
    s = s.replace("import json\nimport subprocess\nimport sys\n",
                  "import json\nimport os\nimport subprocess\nimport sys\n", 1)

# 1b. 模块级开关（放在 _SOLVER_DIR 之后、class 之前）
anchor = '_SOLVER_DIR = Path(__file__).resolve().parents[2]\n'
assert anchor in s, "找不到 _SOLVER_DIR 锚点"
switch = anchor + '''
# 2026-11-08 车联网专项赛复盘：worker_skills.project_skill_roots() 会把
# muteki-ctf-local-playbook / muteki-waf-bypass / muteki-blackboard 投影进每个 Run 的
# .pi/skills 与 .agents/skills，_permission_flags() 也已经传了 --approve（信任项目文件）。
# 但 PiDriver 曾在这里写死 --no-skills，于是这份内置 triage 手册从未进入模型上下文
# （15 个 run 的事件流里 muteki-ctf-local-playbook 命中 0 次）。
# 技能是懒加载的：系统提示只注入一行描述，模型要用时再 read 全文，成本约 100 token。
# MUTEKI_PI_SKILLS=0 时恢复旧的 --no-skills 行为（每个进程启动时读取）。
_pi_skills_enabled = str(os.environ.get("MUTEKI_PI_SKILLS", "1")).strip().lower() not in {
    "0", "false", "no", "off", "disabled"}
'''
s = s.replace(anchor, switch, 1)

# 1c. _CONTEXT_FLAGS：按开关决定是否带 --no-skills
old = '''    _CONTEXT_FLAGS = (
        "--no-skills",
        "--no-context-files",'''
new = '''    _CONTEXT_FLAGS = (
        *(() if _pi_skills_enabled else ("--no-skills",)),
        "--no-context-files",'''
assert old in s, "找不到 _CONTEXT_FLAGS 锚点"
s = s.replace(old, new, 1)
p.write_text(s, encoding="utf-8")
print("  pi.py: --no-skills 改为 MUTEKI_PI_SKILLS 控制（默认 = 加载技能）")
PY

# ---------- 2. 语法与 argv 检查 ----------
PYBIN="$ROOT/.s1-venv/bin/python"
[ -x "$PYBIN" ] || PYBIN=python3
"$PYBIN" -m py_compile "$FILE" && say "  py_compile OK"

cd "$ENGINE"
MUTEKI_PI_BIN=/bin/true MUTEKI_PI_SKILLS=1 "$PYBIN" - <<'PY'
from muteki.solver.cli_engines.engines.pi import PiDriver
flags = list(PiDriver()._CONTEXT_FLAGS)
print("  default:", "OK 无 --no-skills" if "--no-skills" not in flags else "FAIL 仍有 --no-skills")
PY
MUTEKI_PI_BIN=/bin/true MUTEKI_PI_SKILLS=0 "$PYBIN" - <<'PY'
from muteki.solver.cli_engines.engines.pi import PiDriver
print("  MUTEKI_PI_SKILLS=0:", "OK 带 --no-skills" if "--no-skills" in PiDriver()._CONTEXT_FLAGS else "FAIL")
PY

# ---------- 3. 生成 patch 0005（相对打过 0001/0003 的当前树） ----------
PATCH="$ROOT/patches/0005-pi-worker-skills.patch"
{
  echo "diff --git a/muteki/solver/cli_engines/engines/pi.py b/muteki/solver/cli_engines/engines/pi.py"
  diff -u "$(ls -t "$FILE".bak-* | while read f; do grep -q _pi_skills_enabled "$f" || { echo "$f"; break; }; done)" "$FILE" \
    | sed -e "1s#^--- .*#--- a/muteki/solver/cli_engines/engines/pi.py#" \
          -e "2s#^+++ .*#+++ b/muteki/solver/cli_engines/engines/pi.py#"
} > "$PATCH" || true
say "  生成 patches/0005-pi-worker-skills.patch（$(wc -l < "$PATCH") 行）"
# 当前树已打补丁 ⇒ reverse check 应通过
if git apply --check --reverse "$PATCH" 2>/dev/null; then
  say "  幂等检查：reverse-check OK"
else
  say "  ⚠ reverse-check 失败（补丁可能与当前树不严格一致，人工看一眼）"
fi

# ---------- 4. 补丁台账 ----------
~/.ctfagent/.s1-venv/bin/python - "$ROOT/patches/README.md" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text(encoding="utf-8")
if "0005" in s:
    print("  README 已有 0005")
else:
    row = ("| 0005 | `muteki/solver/cli_engines/engines/pi.py` | worker 技能开关：去掉写死的 `--no-skills`，"
           "改由 `MUTEKI_PI_SKILLS` 控制（默认 1=启用） | ① 配置/上游 bug | 2026-11-08 复盘："
           "`worker_skills` 把 `muteki-ctf-local-playbook` 投影进 `.pi/skills`，但 `--no-skills` 让它从未被加载"
           "（15 个 run 命中 0 次） | 上游把技能开关做成配置项后删掉本补丁 |\n")
    idx = s.find("| 0004 |")
    if idx >= 0:
        line_end = s.index("\n", idx)
        s = s[:line_end+1] + row + s[line_end+1:]
    else:
        s += "\n" + row
    p.write_text(s, encoding="utf-8")
    print("  README: 已加 0005")
PY

say "备份：$FILE.bak-$STAMP"
