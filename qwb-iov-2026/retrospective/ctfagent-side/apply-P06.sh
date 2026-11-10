#!/usr/bin/env bash
# P0-6：把"triage"从靠自觉变成 worker prompt 的常驻指针 + 缺失时的门禁提示。
#   1) cli_prompts：在 EXEC / EXPLORE / CAMPAIGN 三套 worker prompt 里加一行指针（读 playbook）；
#   2) cli_board_context：附件类题且事实里没有任何 triage 工具证据时，在 worker prompt 顶部
#      插入一条 TRIAGE 门禁提示（有 triage 事实后自动消失）。
# 幂等；每次改动前备份。MUTEKI_TRIAGE_GATE=0 可关闭门禁提示（指针保留）。
set -euo pipefail
ROOT=${ROOT:-$HOME/.ctfagent}
ENGINE=${ENGINE:-$ROOT/engine/muteki}
STAMP=$(date +%Y%m%d-%H%M%S)
say() { printf '%s\n' "$*"; }
P="$ENGINE/muteki/solver/cli_prompts.py"
B="$ENGINE/muteki/solver/cli_board_context.py"
PYBIN="$ROOT/.s1-venv/bin/python"
[ -x "$PYBIN" ] || PYBIN=python3

say "== 现状 =="
grep -c 'muteki-ctf-local-playbook' "$P" || true
grep -c '_triage_gate_block' "$B" || true
if [ "${1:-}" = "--check" ]; then exit 0; fi

cp -a "$P" "$P.bak-$STAMP"
cp -a "$B" "$B.bak-$STAMP"

# ---------- 1. worker prompt 指针 ----------
"$PYBIN" - "$P" <<'PYPROMPT'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text(encoding="utf-8")
if "muteki-ctf-local-playbook" in s:
    print("  已有指针，跳过"); raise SystemExit(0)
CN = ("动手前先读工作区里的 CTF triage 技能 `muteki-ctf-local-playbook/SKILL.md`"
      "（Pi 在 `.pi/skills/`，其它引擎看各自 skills 目录），按它的顺序做第一轮 triage。\n\n")
EXEC_OLD = '_EXEC_PROMPT = (\n    "完成当前 CTF 任务。你可以使用完整 shell 和常用工具。\\n\\n"\n'
EXEC_NEW = EXEC_OLD + '    "' + CN.replace('"', '\\"').replace("\n", "\\n") + '"\n'
assert EXEC_OLD in s, "_EXEC_PROMPT 锚点变了"
s = s.replace(EXEC_OLD, EXEC_NEW, 1)

EXP_OLD = '_EXPLORE_PROMPT = (\n    "完成当前 CTF Step。\\n\\n"\n'
EXP_NEW = EXP_OLD + '    "' + CN.replace('"', '\\"').replace("\n", "\\n") + '"\n'
assert EXP_OLD in s, "_EXPLORE_PROMPT 锚点变了"
s = s.replace(EXP_OLD, EXP_NEW, 1)

CAMP_OLD = ('_CAMPAIGN_PROMPT = (\n'
            '    "Complete the entire authorized CTF challenge in this one Worker session.\\n\\n"\n')
CAMP_NEW = CAMP_OLD + ('    "Before the first probe, read the workspace skill '
                       '`muteki-ctf-local-playbook/SKILL.md` (`.pi/skills/` for Pi, the '
                       'engine\'s skills dir otherwise) and follow its triage order.\\n\\n"\n')
assert CAMP_OLD in s, "_CAMPAIGN_PROMPT 锚点变了"
s = s.replace(CAMP_OLD, CAMP_NEW, 1)
p.write_text(s, encoding="utf-8")
print("  cli_prompts: 三套 worker prompt 已加 playbook 指针")
PYPROMPT

# ---------- 2. 门禁提示 ----------
"$PYBIN" - "$B" <<'PYGATE'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text(encoding="utf-8")
if "_triage_gate_block" in s:
    print("  已有门禁，跳过"); raise SystemExit(0)

helper = '''
# ---------------------------------------------------------------------------
# P0-6 triage 门禁（2026-11-08 复盘）：附件类题在没有任何 triage 工具证据之前，
# 在 worker prompt 顶部插一条提示。它不拒绝任何调用，只把"先跑标准工具"变成
# 每代都能看到的一行；一旦图里出现 triage 证据（file/binwalk/tshark/strings/xxd…）自动消失。
# MUTEKI_TRIAGE_GATE=0 可关闭（指针仍在 cli_prompts 里）。
_TRIAGE_TOOL_RE = re.compile(
    r"(?i)(?:\\bbinwalk\\b|\\bunblob\\b|\\bunsquashfs\\b|\\bsasquatch\\b|\\bjefferson\\b|"
    r"\\bubireader_\\w+|\\btshark\\b|\\bcapinfos\\b|\\btcpdump\\b|\\b7z\\s+[lx]\\b|"
    r"\\breadelf\\b|\\bobjdump\\b|\\bstrings\\s|\\bxxd\\s|\\bhexdump\\b)")
_TRIAGE_GATE_TEXT = (
    "【TRIAGE 门禁】本 Run 还没有 triage 事实（附件已给）。先跑 `file` / `strings` / `xxd`"
    "（固件加 `binwalk -eM`，失败换 `unblob -e`；流量加 `tshark -q -z io,phs`），把原始输出摘要"
    "（含路径）submit-fact 之后再推进原方向；没有 triage 事实前不要开新方向。")


def _triage_gate_block(self) -> str:
    """附件类 CTF 题、且图里还没有 triage 证据时，返回一条门禁提示；否则空串。"""
    import os as _os
    if str(_os.environ.get("MUTEKI_TRIAGE_GATE", "1")).strip().lower() in {"0", "false", "no", "off"}:
        return ""
    challenge = getattr(self, "challenge", None)
    if challenge is None or getattr(challenge, "mode", "ctf") != "ctf":
        return ""
    if not list(getattr(challenge, "attachments", []) or []):
        return ""
    graph = getattr(self, "shared_graph", None)
    if graph is None:
        return ""
    try:
        snapshot = graph.snapshot()
        blob = "\\n".join(
            f"{getattr(ev, 'source', '')} {getattr(ev, 'fact', '')}"
            for ev in (getattr(snapshot, "evidence", []) or []))
    except Exception:  # noqa: BLE001 — 门禁读不到图时绝不能卡住 prompt
        return ""
    if _TRIAGE_TOOL_RE.search(blob):
        return ""
    return _TRIAGE_GATE_TEXT

'''
anchor = "\ndef _compile_worker_prompt(\n"
assert anchor in s, "_compile_worker_prompt 锚点变了"
s = s.replace(anchor, helper + anchor, 1)

inject_old = '''    if not bool(getattr(self.challenge, "allow_operator_input", True)):
        fixed_template = without_operator_input_capability(fixed_template)'''
inject_new = '''    if role in {"worker_bootstrap", "worker_explore"}:
        triage = _triage_gate_block(self)
        if triage:
            sections = [("triage-gate", triage, {}), *sections]
    if not bool(getattr(self.challenge, "allow_operator_input", True)):
        fixed_template = without_operator_input_capability(fixed_template)'''
assert inject_old in s
s = s.replace(inject_old, inject_new, 1)

if "\nimport re\n" not in s:
    s = s.replace("\nimport os\n", "\nimport os\nimport re\n", 1)
p.write_text(s, encoding="utf-8")
print("  cli_board_context: 已加 _triage_gate_block 并在 _compile_worker_prompt 注入")
PYGATE

# ---------- 3. 编译 + 行为测试 ----------
"$PYBIN" -m py_compile "$P" "$B" && say "  py_compile OK"
cd "$ENGINE"
"$PYBIN" - <<'PYTEST'
import sys, types
sys.path.insert(0, ".")
from muteki.solver import cli_prompts
from muteki.solver.cli_board_context import _triage_gate_block

class Ev:
    def __init__(self, fact): self.fact = fact; self.source = ""
class SG:
    def __init__(self, facts): self._f = facts
    def snapshot(self): return types.SimpleNamespace(evidence=[Ev(f) for f in self._f])
def mk(attachments, facts, mode="ctf"):
    ch = types.SimpleNamespace(mode=mode, attachments=attachments)
    return types.SimpleNamespace(challenge=ch, shared_graph=SG(facts))

checks = [
    ("附件 + 0 事实 → 门禁触发", bool(_triage_gate_block(mk(["a.bin"], [])))),
    ("有 binwalk 事实 → 不触发", _triage_gate_block(mk(["a.bin"], ["binwalk -eM a.bin → squashfs"])) == ""),
    ("有 xxd 事实 → 不触发", _triage_gate_block(mk(["a.bin"], ["xxd -l 64 a.bin 得到 magic"])) == ""),
    ("无附件 → 不触发", _triage_gate_block(mk([], [])) == ""),
    ("pentest → 不触发", _triage_gate_block(mk(["a.bin"], [], mode="pentest")) == ""),
    ("EXEC 指针", "muteki-ctf-local-playbook" in cli_prompts._EXEC_PROMPT),
    ("EXPLORE 指针", "muteki-ctf-local-playbook" in cli_prompts._EXPLORE_PROMPT),
    ("CAMPAIGN 指针", "muteki-ctf-local-playbook" in cli_prompts._CAMPAIGN_PROMPT),
]
ok = True
for name, passed in checks:
    print(("  PASS " if passed else "  FAIL ") + name)
    ok = ok and passed
raise SystemExit(0 if ok else 3)
PYTEST

# ---------- 4. 生成 patch 0006 ----------
cd "$ENGINE"
PATCH="$ROOT/patches/0006-worker-triage-pointer.patch"
{
  echo "diff --git a/muteki/solver/cli_prompts.py b/muteki/solver/cli_prompts.py"
  diff -u "$(ls -t "$P".bak-* | while read f; do grep -q 'muteki-ctf-local-playbook' "$f" || { echo "$f"; break; }; done)" "$P" \
    | sed -e "1s#^--- .*#--- a/muteki/solver/cli_prompts.py#" -e "2s#^+++ .*#+++ b/muteki/solver/cli_prompts.py#"
  echo "diff --git a/muteki/solver/cli_board_context.py b/muteki/solver/cli_board_context.py"
  diff -u "$(ls -t "$B".bak-* | while read f; do grep -q '_triage_gate_block' "$f" || { echo "$f"; break; }; done)" "$B" \
    | sed -e "1s#^--- .*#--- a/muteki/solver/cli_board_context.py#" -e "2s#^+++ .*#+++ b/muteki/solver/cli_board_context.py#"
} > "$PATCH" || true
say "  生成 patches/0006-worker-triage-pointer.patch（$(wc -l < "$PATCH") 行）"
if git apply --check --reverse "$PATCH" 2>/dev/null; then say "  幂等检查：reverse-check OK"; else say "  ⚠ reverse-check 失败"; fi

# ---------- 5. 台账 ----------
"$PYBIN" - "$ROOT/patches/README.md" <<'PYREADME'
import pathlib, sys
p = pathlib.Path(sys.argv[1]); s = p.read_text(encoding="utf-8")
if "0006" in s:
    print("  README 已有 0006"); raise SystemExit(0)
row = ("| 0006 | `muteki/solver/cli_prompts.py` + `cli_board_context.py` | worker prompt 常驻一行 playbook 指针；"
       "附件类题在没有 triage 事实时，prompt 顶部加一条 TRIAGE 门禁提示（有证据即消失，`MUTEKI_TRIAGE_GATE=0` 可关） "
       "| ① 配置/行为 | 2026-11-08：11 个初始 run 的 prompt 里根本没有 triage 文本（只有 4 个重派 run 有）；"
       "binwalk 全场 6 次、unblob 0 次 | 上游自带 playbook+gating 后删掉本补丁 |\n")
idx = s.find("| 0005 |")
assert idx >= 0
end = s.index("\n", idx)
s = s[:end+1] + row + s[end+1:]
p.write_text(s, encoding="utf-8")
print("  README: 已加 0006")
PYREADME

say "备份：$P.bak-$STAMP / $B.bak-$STAMP"
