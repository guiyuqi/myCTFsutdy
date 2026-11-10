#!/usr/bin/env bash
# P0-3：给 run 续做加"代/预算"上限（默认 12 代、25M token），超限不再 reopen。
# 幂等（已存在则跳过），每次改动前备份。
set -euo pipefail
ROOT=${ROOT:-$HOME/.ctfagent}
ENGINE=${ENGINE:-$ROOT/engine/muteki}
STAMP=$(date +%Y%m%d-%H%M%S)
say() { printf '%s\n' "$*"; }

say "== 现状 =="
grep -c 'continuation_cap_reason' "$ENGINE/apps/web/run_lifecycle.py" 2>/dev/null | sed 's/^/  run_lifecycle 命中: /' || true
grep -c 'RunBudgetExhausted' "$ENGINE/apps/web/run_gateway.py" 2>/dev/null | sed 's/^/  run_gateway 命中: /' || true
grep -c 'MUTEKI_RUN_MAX_GENERATIONS' "$ROOT/start.sh" 2>/dev/null | sed 's/^/  start.sh 命中: /' || true
if [ "${1:-}" = "--check" ]; then exit 0; fi

cp -a "$ENGINE/apps/web/run_lifecycle.py" "$ENGINE/apps/web/run_lifecycle.py.bak-$STAMP"
cp -a "$ENGINE/apps/web/run_gateway.py" "$ENGINE/apps/web/run_gateway.py.bak-$STAMP"
cp -a "$ROOT/start.sh" "$ROOT/start.sh.bak-$STAMP"

# ---------- 1. run_lifecycle.py：上限函数 + 续做处拦截 ----------
python3 - "$ENGINE" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "apps/web/run_lifecycle.py"
s = p.read_text(encoding="utf-8")
if "continuation_cap_reason" in s:
    print("  run_lifecycle.py 已有上限逻辑，跳过")
else:
    helper = '''
class RunBudgetExhausted(RuntimeError):
    """续做会超过 Run 级上限（代数 / 累计 token）。"""

    code = "run.budget_exhausted"


def continuation_cap_reason(run: Run) -> str:
    """返回"这个 run 不该再开新代"的原因；空串表示允许。

    默认值来自 2026-11-08 车联网专项赛复盘：三题解出分别用了 3/9/11 代、
    2.9M/12.9M/15.0M token；而空转的长跑用了 22–26 代、17–37M。
    因此默认 12 代 / 25M token 能保住全部已解出形态，同时砍掉纯空转的后半程。
    """
    def _int(name: str, default: int) -> int:
        raw = os.environ.get(name, "")
        try:
            value = int(raw) if str(raw).strip() else int(default)
        except (TypeError, ValueError):
            value = int(default)
        return max(0, value)

    max_generations = _int("MUTEKI_RUN_MAX_GENERATIONS", 12)
    max_tokens = _int("MUTEKI_RUN_MAX_TOKENS", 25_000_000)
    generations = int(getattr(run, "execution_generation", 0) or 0)
    if max_generations and generations >= max_generations:
        return f"generations={generations} 已达上限 {max_generations}"
    if max_tokens:
        try:
            tokens = int((run.cost.snapshot() or {}).get("global_tokens") or 0)
        except Exception:  # noqa: BLE001 — 指标读不到时绝不能反过来卡住续做
            tokens = 0
        if tokens >= max_tokens:
            return f"tokens={tokens} 已达上限 {max_tokens}"
    return ""


'''
    anchor = "\ndef _retire_worker_command_epoch(self, run: Run) -> None:"
    assert anchor in s, "run_lifecycle 结构变了"
    s = s.replace(anchor, helper + anchor, 1)

    # 在 _resolve_launching 的最前面（docstring 之后、任何状态改动之前）拦截
    marker = '''    if run.runtime_incomplete and not await self._settle_incomplete_runtime('''
    assert marker in s, "找不到 _resolve_launching 的入口"
    guard = '''    cap_reason = continuation_cap_reason(run)
    if cap_reason:
        LOG.warning("refusing to resolve %s: %s", run_id, cap_reason)
        raise RunBudgetExhausted(
            f"run 续做已达上限（{cap_reason}）；如确需继续，先调大 "
            f"MUTEKI_RUN_MAX_GENERATIONS / MUTEKI_RUN_MAX_TOKENS")
'''
    s = s.replace(marker, guard + marker, 1)
    p.write_text(s, encoding="utf-8")
    print("  run_lifecycle.py: 已加 RunBudgetExhausted / continuation_cap_reason，并在 _resolve_launching 入口拦截")
PY

# ---------- 2. run_gateway.py：把上限拒绝变成可见回执 ----------
python3 - "$ENGINE" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "apps/web/run_gateway.py"
s = p.read_text(encoding="utf-8")
if "RunBudgetExhausted" in s:
    print("  run_gateway.py 已有处理，跳过")
else:
    old = '''        except Exception as exc:
            LOG.exception("gateway resolve failed for %s", run_id)'''
    new = '''        except Exception as exc:
            from apps.web.run_lifecycle import RunBudgetExhausted as _Capped
            if isinstance(exc, _Capped):
                LOG.warning("resolve refused for %s: %s", run_id, exc)
                return self._error_receipt(
                    run_id, command,
                    code=exc.code,
                    message=str(exc),
                    category=ErrorCategory.STATE)
            LOG.exception("gateway resolve failed for %s", run_id)'''
    assert old in s, "run_gateway 结构变了"
    s = s.replace(old, new, 1)
    p.write_text(s, encoding="utf-8")
    print("  run_gateway.py: 续做上限拒绝 -> run.budget_exhausted 回执")
PY

# ---------- 3. start.sh：把上限写成显式环境 ----------
python3 - "$ROOT" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1]) / "start.sh"
s = p.read_text(encoding="utf-8")
if "MUTEKI_RUN_MAX_GENERATIONS" in s:
    print("  start.sh 已有上限环境，跳过")
else:
    anchor = '  CTFAGENT_DB="$ROOT/state/ctfagent.sqlite3" \\\n'
    assert anchor in s
    add = (anchor
           + '  MUTEKI_RUN_MAX_GENERATIONS="${MUTEKI_RUN_MAX_GENERATIONS:-12}" \\\n'
           + '  MUTEKI_RUN_MAX_TOKENS="${MUTEKI_RUN_MAX_TOKENS:-25000000}" \\\n')
    p.write_text(s.replace(anchor, add, 1), encoding="utf-8")
    print("  start.sh: 写死 12 代 / 25M token 上限（可用环境覆盖）")
PY

# ---------- 4. 单测 ----------
cat > "$ENGINE/tests/test_continuation_caps.py" <<'PY'
"""P0-3 回归：run 续做的代数/token 上限（2026-11-08 复盘）。"""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from apps.web.run_lifecycle import RunBudgetExhausted, continuation_cap_reason


def _run(generations: int, tokens: int):
    return SimpleNamespace(
        execution_generation=generations,
        cost=SimpleNamespace(snapshot=lambda: {"global_tokens": tokens}),
    )


def test_allows_known_solved_shapes(monkeypatch):
    monkeypatch.delenv("MUTEKI_RUN_MAX_GENERATIONS", raising=False)
    monkeypatch.delenv("MUTEKI_RUN_MAX_TOKENS", raising=False)
    for gens, tokens in ((3, 2_900_000), (9, 12_900_000), (11, 15_000_000)):
        assert continuation_cap_reason(_run(gens, tokens)) == ""


def test_generation_cap(monkeypatch):
    monkeypatch.setenv("MUTEKI_RUN_MAX_GENERATIONS", "12")
    monkeypatch.delenv("MUTEKI_RUN_MAX_TOKENS", raising=False)
    assert continuation_cap_reason(_run(11, 0)) == ""
    assert "generations=12" in continuation_cap_reason(_run(12, 0))


def test_token_cap(monkeypatch):
    monkeypatch.delenv("MUTEKI_RUN_MAX_GENERATIONS", raising=False)
    monkeypatch.setenv("MUTEKI_RUN_MAX_TOKENS", "25000000")
    assert continuation_cap_reason(_run(5, 24_999_999)) == ""
    assert "tokens=25000000" in continuation_cap_reason(_run(5, 25_000_000))


def test_metrics_failure_never_blocks(monkeypatch):
    monkeypatch.setenv("MUTEKI_RUN_MAX_TOKENS", "1")
    broken = SimpleNamespace(execution_generation=1,
                             cost=SimpleNamespace(snapshot=lambda: (_ for _ in ()).throw(RuntimeError("x"))))
    assert continuation_cap_reason(broken) == ""


def test_zero_disables(monkeypatch):
    monkeypatch.setenv("MUTEKI_RUN_MAX_GENERATIONS", "0")
    monkeypatch.setenv("MUTEKI_RUN_MAX_TOKENS", "0")
    assert continuation_cap_reason(_run(99, 10**12)) == ""
PY

# ---------- 5. 编译 + 单测 ----------
PYBIN="$ROOT/.s1-venv/bin/python"
[ -x "$PYBIN" ] || PYBIN=python3
"$PYBIN" -m py_compile "$ENGINE/apps/web/run_lifecycle.py" "$ENGINE/apps/web/run_gateway.py" \
  && say "  py_compile OK"
cd "$ENGINE"
if "$PYBIN" -c "import pytest" >/dev/null 2>&1; then
  "$PYBIN" -m pytest -q tests/test_continuation_caps.py 2>&1 | tail -8
else
  say "  pytest 不可用，退回内联断言"
  "$PYBIN" - <<'PYTEST'
import os, sys
sys.path.insert(0, ".")
from types import SimpleNamespace
from apps.web.run_lifecycle import continuation_cap_reason
os.environ.pop("MUTEKI_RUN_MAX_GENERATIONS", None); os.environ.pop("MUTEKI_RUN_MAX_TOKENS", None)
print("default:", repr(continuation_cap_reason(SimpleNamespace(execution_generation=11, cost=SimpleNamespace(snapshot=lambda: {"global_tokens": 15_000_000})))))
os.environ["MUTEKI_RUN_MAX_GENERATIONS"] = "12"
print("at cap:", repr(continuation_cap_reason(SimpleNamespace(execution_generation=12, cost=SimpleNamespace(snapshot=lambda: {"global_tokens": 0})))))
os.environ.pop("MUTEKI_RUN_MAX_GENERATIONS"); os.environ["MUTEKI_RUN_MAX_TOKENS"] = "25000000"
print("token cap:", repr(continuation_cap_reason(SimpleNamespace(execution_generation=5, cost=SimpleNamespace(snapshot=lambda: {"global_tokens": 25_000_000})))))
PYTEST
fi

# ---------- 6. 生成 patch 0004 ----------
cd "$ENGINE"
git diff -- apps/web/run_lifecycle.py apps/web/run_gateway.py tests/test_continuation_caps.py \
  > "$ROOT/patches/0004-run-continuation-caps.patch"
say "  已生成 patches/0004-run-continuation-caps.patch（$(wc -l < "$ROOT/patches/0004-run-continuation-caps.patch") 行）"
cd "$ROOT" && bash patches/apply.sh --status | tail -6
say "备份后缀：.bak-$STAMP"
