# CTF Agent 框架 · 需求与架构（基于 DSH Web）

> 状态：草案，等待新会话实施。所有"DSH 能力"条目已在本机 checkout 上核对过（见 §3 的"已核实"）。
> 目标不是"更好的提示词"，而是**让约束不可绕过**。

---

## 1. 需求

### 1.1 功能需求

| # | 需求 | 验收（可测） |
|---|---|---|
| R1 | 一个进程/服务独占平台环境权限；任何 agent 不能直接 start/stop 容器 | 外部 agent 调 `env.*` → 403 + 提示 |
| R2 | 环境就绪判定唯一：`detail.endpoints[0].status=="running"` 且 `proxyIps` 非空 | 60s 内返回地址或判幽灵并拉黑 |
| R3 | 每题一个工作项，含状态机/subtask 验收/预算/`next_action`/`revisit_at` | 任何时刻可导出 board 快照（JSON） |
| R4 | 每条结论必须带 artifact（路径 + sha256）；负结论必须带外部反证 N | 无 artifact 的 claim 落盘被拒 |
| R5 | flag 提交需要 verifier 签的 token；同题提交次数受限 | 无 token / 超额 → 拒 |
| R6 | 技能加载返回"执行契约"（工具白名单 + 验收 + 失败模式），并绑定到该工作项 | 调白名单外工具 → 拒 |
| R7 | 工具是结构化动词（`env.ensure`/`challenge.pull`/`gdb.run`/`net.probe`/`decode.astc`/`web.js`/`zip.aes`/`submit.flag`），返回 JSON + evidence_id | 禁止用裸 shell 完成高风险动作 |
| R8 | 时间必须来自 `clock.now`（本机 + 平台 `detail.currentTime`），断言限 60s 内 | 未取时即断言 → 拒 |
| R9 | 全部事件 append-only，可复原：会话崩溃后用 board+ledger 继续 | 新会话 5 分钟内接续同一工作项 |
| R10 | Web 上可见：board 看板、每题验收打勾、预算消耗、live 输出 | 打开 DSH Web 即可看 |

### 1.2 非目标（明确不做）

- 不重写 agent 运行时（循环、工具调度、会话、压缩、审批）——DSH 已有。
- 不做自动"作弊"（读他人 flag / 共享 flag）；本项目只做"本队靶机与公开题面"。
- 不做通用渗透平台；只服务 Jeopardy 式 CTF（可扩展到 A&D，但不在第一版）。

---

## 2. 组件

```
Planner(父) ──board API──► board(工作项状态机)
      ▲                        │ claim/acceptance
      │                        ▼
   DSH session ◄── gate ◄── tools(动词) ──► 外部执行体
      │                        │               ├─ envd（平台 env API）
   Scribe ◄── ledger ◄────────┘               ├─ gdb/objdump（容器内或本地）
   Verifier ──签 token──► submit.flag          ├─ 解码器（astc/oodle/zip）
                                               └─ web（playwright/chromium）
```

- **envd**：单点、串行、带配额账与幽灵黑名单；只做 `ensure/release/state`。
- **board**：每题一条 JSON，`state` + `acceptance[]` + `budget` + `next_action` + `revisit_at` + `missing`。
- **ledger**：`{ts, item, actor, claim, verdict, artifacts[], tool_calls[], external_refs[]}` append-only。
- **gate**：策略引擎（YAML），以 DSH 的 **PreToolUse hook** 形式执行；拒绝时回 `{"reason":..., "next":...}`。
  > ⚠️ **勘误 2026-10-24（B2）**：用 command hook 是三个方案里最弱的一个。更好的落法是**原生 Cordis 插件**：`ctx.tools.guard()` 是**单调**守卫（"no later listener can turn that denial back into permission"），且 `agent.ctx` 作用域能让子代理**根本看不见**白名单外的工具——比"调用了再拒"干净。见 `ERRATA.md`（B2）。
- **verifier**：独立复核后签发 token（含 flag 摘要 + 证据 id + 过期时间 + signer）。
- **tools**：DSH 工具插件注册的动词；每个动词内部做参数校验、预算扣减、evidence 落账。

---

## 3. DSH 映射（已核实）

| 需要 | DSH 已有能力 | 落法 |
|---|---|---|
| 新增工具动词 | `@deepseek-ai/dsh-tools` 的 `ctx.tools` + `defineTool`（README: "Registering a tool is enough to make it visible… schemas into the system-prompt"） | 写 `dsh-plugin-ctf`，注册 `env.ensure` 等 |
| 拦截工具调用 | `dsh-hook-protocol` + `dsh-hooks-claude-code` / `-codex`：**PreToolUse/PostToolUse/UserPromptSubmit/SessionStart/Stop/SubagentStop**；hook **exit 2 会阻断并把 stderr 给模型看** | gate 作为 command hook；或直接写原生 Cordis plugin（"full harness API, no hook protocol in between"） |
| 技能加载 | `dsh-skill` + `dsh-skill-filesystem`：`SKILL.md` + frontmatter + `bundle` | Skills 2.0 = `SKILL.md` + `bundle.yaml`（bind_tools/acceptance/failure_modes） |
| 子代理 | `dsh-subagent` / `dsh-tool-subagent`（README 提到 inherited 行为） | Solver/Verifier 作为 subagent；**需实测 hooks 是否继承到子代理**（见风险 R-1） |
| 编排 | `dsh-tool-workflow`（脚本化 fan-out）+ `dsh-tool-goal` / `ralph` | Planner 用 workflow 做"每小时重排" |
| 人工审批 | `dsh-user-approval` / `dsh-permission-presets` | `board.override` 的 break-glass 走审批，落 ledger |
| Web UI | DSH Web GUI（会话/流式/文件）+ `dsh-client-ui-*` 客户端插件 | 首版用现有会话视图；board 看板做客户端插件（可后置） |
| 持久化 | 会话 + workspace；本项目再把 board/ledger 写成文件 | `state/board.jsonl`、`state/ledger.jsonl` |

> ⚠️ **勘误 2026-10-24（B1 / B2）**：
> - **B2**：本表第 2 行"gate 作为 command hook"是该表里最弱的选项。hook 桥的 `SubagentStart`/`SubagentStop` 上报 `agent_type` **恒为 `general-purpose`**，拿不到 caller 身份（R-2 在 hook 层做不出来）；且每次调用起一个子进程。应改用原生插件：`ctx.tools.guard()`（单调，不可翻案）+ `agent.ctx` 作用域（子代理看不见白名单外工具）。
> - **B1**：本表"技能加载"行写的 `SKILL.md + bundle.yaml` 与实际不符。`dsh-skill-filesystem` 只认 `name/description/whenToUse/metadata`，顶层 `bind_tools`/`acceptance`/`failure_modes` 会被**静默丢弃**、不报错。
> 详见 `ERRATA.md`（B1、B2）。

---

## 4. 数据契约（最小）

```jsonc
// state/board/<id>.json
{"id":"12073","state":"ACTIVE","owner":"pwn-12073","budget":{"wall_s":5400,"tokens":1200000,"new_conns":300},
 "acceptance":["gate-open","hop1-broker","hop2-vault","hop3-keeper","oracle-flag"],
 "done":["gate-open","hop1-broker"],"missing":"hop2 的任意读原语",
 "next_action":"读 broker FUN_231b 的 send_framed 调用点","revisit_at":"2026-10-24T16:20:00+08:00",
 "env":{"url":"http://<target>:28604","expires_at":"..."},"evidence":["work/12073/chain.log#L168"]}
```

```jsonc
// ledger 一条
{"ts":"...","item":"12073","actor":"pwn-12073","claim":"B 回 DOC ⇒ 门禁已开",
 "verdict":"hypothesis","artifacts":[{"path":"work/12073/local_end2end.log","sha256":"..."}],
 "tool_calls":["gdb.run(...)","challenge.send(...)"],"external_refs":[]}
```

```jsonc
// verify token
{"flag_sha256":"...","item":"12078","evidence_ids":["..."],"signer":"verifier","exp":1792...}
```

```yaml
# policy.yaml（gate 规则节选）
- {id: env-only-envd, match: {tool: "env.*", caller: "!envd"}, action: deny}
- {id: submit-needs-token, match: {tool: "submit.flag"}, require: {token: verify}}
- {id: submit-cap, match: {tool: "submit.flag", scope: item}, limit: {attempts: 3}}
- {id: negative-verdict, match: {tool: "board.verdict", value: "unsolvable|not-exists"},
   require: {field: external_solve_count, equals: 0}}
- {id: claim-artifact, match: {tool: "board.claim"}, require: {artifacts_exist: true, sha256_match: true}}
- {id: clock-fresh, match: {tool: "board.time_assert"}, require: {clock_now_age_s: "<60"}}
- {id: skill-bound-tools, match: {tool: "*"}, require: {tool_in: "item.skill.bind_tools"}}
```

---

## 5. 阶段与验收

| 阶段 | 内容 | 验收 |
|---|---|---|
| P0（半天） | `envd` + `gate`（只拦 env/submit） | 10 次并发申请容器只有 1 条成功路径；无 token 无法提交 |
| P1（1 天） | `ledger` + `board` + `scribe` | 任一时刻可导出 board；连续 2 小时无"空窗"（parked 自动回队） |
| P2（2–3 天） | `tools` 动词化 + `tools.search` + Skills 2.0 + `verifier` | 新题 60s 内产出 tool_plan；同一错误不重复出现两次 |
| P3 | 黄金镜像（Android 模拟器 / Windows VM / ASTC+Oodle / 浏览器）+ Swarm | 任一题环境准备 <60s |

**回放验收**：用本场 10 题的材料（`~/ctf-2026/notes/`、`work/`、`evidence/submit-log.jsonl`）做离线回放：
让框架在"无平台"条件下重走 12080 与 12086（这两题可纯离线复算 flag），要求：
① 必须先出 `tool_plan`；② 结论必须带 artifact；③ 全程无越权 env/submit 调用；④ board 上可见 subtask 进度。

> ⚠️ **建议复核 2026-10-24（D2）**：回放题选 12080/12086 验证不了要治的病——这两题是**成功案例**且可离线复算，既没有环境压力，也不会诱使 agent 下负结论。
> 建议改用 **12062 / 12073 + 一个伪造的 `已答出N次 > 0` 的 detail**，这样"判据三重对照"和 verifier 才有东西可拒。
> 验收标准也应改成"**框架拒绝了我多少次**"，而不是"框架又解出了一次"。见 `ERRATA.md`（D2）。

---

## 6. 风险与待验证（诚实清单）

- **R-1 子代理是否继承 hooks**：若 substep 用了不同 hooks 配置，gate 可能被子代理绕过。→ 第一件事就测：subagent 里调 `submit.flag` 是否被拦。
- **R-2 caller 身份**：hook 进程怎么知道"这是 Warden 还是 Solver"？方案：每个 subagent 的 workspace 里写 `state/role`，hook 读环境变量/文件；或按 agent 名白名单。
  > ⚠️ **勘误 2026-10-24（B2）**：在本场实测的 DSH 版本上，**"按 agent 名白名单"在 hook 层做不出来**——hook 桥的 `SubagentStart`/`SubagentStop` 上报的 `agent_type` 恒为 `general-purpose`（"the subagent seam carries no per-kind label"）。`state/role` 文件那条是可行的替代，但更好的是干脆不用 hook：用 `agent.ctx` 作用域让子代理**看不见**不该有的工具。
- **R-3 异步/后台任务**：~~DSH 的后台 job（bash background）绕过 PreToolUse？~~ → ⚠️ **机制更正（B3）**：后台 job 里的每条命令仍是一次工具调用，`tools/pre-execute` 看得到，**不存在绕过**。真正的软肋是 `tools/pre-execute` **刻意不允许改写 `exec.arguments`**，所以"禁止用裸 shell 做高风险动作"只能靠正则黑名单。需在工具层（动词）而不是 shell 层做限制——**"去掉万能 shell"的结论成立，但理由要换成"gate 只能 deny、不能 sanitize"**。
- **R-4 审批链路**：`board.override` 走 `dsh-user-approval` 时，人类不在场会阻塞；需超时降级策略。
- **R-5 平台边界**：envd 只能调"本队靶机 + 题面读取 + 提交"，不得扫描平台；这条要写成 gate 规则并留审计。
- **R-6 装备**：框架不能替代 Windows VM / Android 模拟器 / 解码器；P3 不做，能力上限仍被卡（本场 12070/12084 就是证据）。

---

## 7. 一条原则

**提示词解释原因，gate 决定后果。**
任何"必须/禁止"如果要紧，就必须有一条规则能在越界时立刻失败，并给出下一步；否则它就是建议，比赛压力下一定会被忘掉。
