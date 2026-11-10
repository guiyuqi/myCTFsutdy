# planner 为什么全程判死（本场最大故障 · 根因已复现）

## 症状
- `reason_done` 事件 **641 次，`raw_response_finish_reason` 全为 `error`、`raw_response_chars=0`**（空串 sha256 `e3b0c442…`）。
- 29/29 个 run 的 `.muteki-agent-state/reason/draft.json` 恒为 `{"committed": false, "operations": []}`。
- 执行代结局：planner 判死 **192** / 292（66%）；代级解出率 4.5%。
- 最早失败时间 **2026-11-07 19:26**（赛前搭建当晚）→ 与赛中任何配置调整无关。

## 复现（1 分钟）
```bash
cd ~/.ctfagent
D=state/sessions/run-51063/workspace/.muteki-agent-state/reason   # 任意一个跑过的 run
mkdir -p .tmp/plantest && cp $D/graph.json .tmp/plantest/ && cd .tmp/plantest
printf '{"committed":false,"operations":[]}' > draft.json
env MUTEKI_DECIDE_DRAFT_PATH=$PWD/draft.json MUTEKI_DECIDE_GRAPH_PATH=$PWD/graph.json \
    MUTEKI_DECIDE_MAX_STEPS=4 MUTEKI_DECIDE_CHALLENGER=0 PI_SANDBOX_DISABLE=1 HOME=$PWD \
  ~/.ctfagent/.s1-tools/bin/pi -p --mode json --no-session --no-context-files \
    --no-builtin-tools --extension ~/.ctfagent/engine/muteki/muteki/solver/pi_decide_extension.ts \
    --tools read,open_step,peek_step,preview,commit \
    --system-prompt "You plan CTF steps; commit a draft via the commit tool." 'facts: none'
# 输出：No API key found for the selected model.   ← stdout 只有 session 头、退出码 0
```

## 机制
- 引擎的 planner 调用要求凭据目录 `<run>/.muteki-agent-state/reason/pi-agent/`
  （`muteki/core/usage_routes.py:71` 也按这个路径找 `models.json`）。
- 实测：跑了 32 代的 run 里，该目录**始终不存在**（同目录下只有 graph.json / draft.json / plugins.json）。
- ⇒ worker 的 pi 凭据会 stage（所以 worker 能跑），**planner 的没有 stage**，pi 在鉴权处直接退出、不产生任何 assistant 文本，
  引擎看到"0 字符且未 commit" → 记 `invalid_plan` → run 判 `runtime_failure`。

## 修复清单（按顺序）
1. **planner 冒烟进 preflight**：给 3 条事实，要求产出 `committed=true` 的 draft；不通过即 NO-GO。
   （另一个会话已新增 `tools/planner_smoke.py` + `tools/planner_smoke_fixture/`，见工作区）
2. 修 staging：planner 也要写 `reason/pi-agent/{models.json,auth}`，或复用 worker 的 staging 逻辑。
3. **planner 失败降级为优雅收束**（输出 `no_plan` 也算成功），不要 `runtime_failure`。
4. planner/titler 用 v4-pro 或更强模型（平台默认本就是 v4-pro，被 `bootstrap --model` 一并改掉了）。
5. reopen 不重置执行预算（本场 223 次 `run.resolve` 把续做预算清零，单 run 跑到 32 代）。
