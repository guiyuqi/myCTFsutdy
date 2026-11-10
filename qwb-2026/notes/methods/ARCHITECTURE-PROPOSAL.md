# 架构提案：把"提示词约束"换成"硬约束"（讨论稿）

> 背景：2026 羊城杯一手数据（`notes/methods/POST-MORTEM-YCB2026.md`）+ 外部调研（`notes/methods/RESEARCH-AGENT-CTF.md`）。
> 争议点：**架构决定上限** 这个判断，我同意一半。下面先说结论，再给可执行设计。

---

## 0. 结论：架构决定"能兑现多少模型能力"，模型决定"能不能想出新解法"

本场证据（全部可复核）：

| 失败类型 | 实例 | 是模型不行，还是架构不行 |
|---|---|---|
| 工具没被调用 | `pyzipper` 装着却手写 20 行 HMAC（12080） | **架构**：工具清单不在决策路径上 |
| 技能加载后忘了用 | 多题 `SKILLS_USED` 只是"部分使用" | **架构**：技能只是文本，没有绑定工具与验收 |
| 同一错误重复犯 | 6 次"不可解/无端点"结论 | **架构**：没有强制"结论必须带证据 + 外部反证" |
| 资源失控 | 容器 90–110 分钟、9 次无效提交 | **架构**：谁都能调 env/submit |
| 时间判断漂移 | 父代理把 12:32 当 13:29 | **架构**：时间靠模型记忆，而不是查询 |
| 多跳链打不动 | 12073 4 跳、12079 十轮单指标 | **模型**（推理/实现上限），但可被"分解 + 中间验收"缓解 |

⇒ 我们的损耗里，**约 60–70% 是架构可消掉的**；剩下 30–40% 才是模型在"没见过的机制 + 长链实现"上的上限。

> ⚠️ **口径复核 2026-10-24（D1）**：这是一个估值，且分母两可，建议换成可测的那句。
> **按题算**：真正能被架构救回的只有 3–4 道（12065 资源误判、12075/12076 无 revisit、12062 换实例重扫）；
> **按墙钟算**：**49.6%（108.2 / 218.3 分钟）的回合时间落在 13 个"回合内轮询"的 turn 里**（复算见 `work/handoff/ERRATA.md` D1 与 `~/ctf/templates/ctf-kit/recompute.py`）。
> 两个数都真，含义不同：前者说"框架能多解几道"，后者说"同一批题能早几小时解出"。

**为什么提示词会失效（四个断点）**：
1. **注意力有限**：RULES/AGENTS 很长，模型每轮只看得到一部分；约束越靠后越容易丢。
2. **没有代价**：忘了调用工具、没做外部反证，不会立刻失败——错误在 1 小时后才暴露。
3. **工具是"可选"的**：`shell` 万能 ⇒ 模型倾向自己写（它更擅长写代码，而不是查清单）。
4. **状态在上下文里**：上下文一压缩/一换代理，状态（容器、判据、预算）就没了。

**架构要做的事**：把这些"软约束"变成**不可绕过的接口、门禁和状态**。

---

## 1. 目标链路（替换现在的 prompt→tool 链）

```
            ┌───────────────── Planner（父代理，只做决策）─────────────────┐
            │ 读 board 快照 → 重排 / 解阻塞 / 批 verify token / 停手      │
            └───────▲───────────────────────────────────────┬─────────────┘
                    │ board API（只读快照 + 决策动词）        │ spawn/steer
   ┌────────────────┴──────────┐              ┌──────────────▼──────────────┐
   │ board：工作项状态机 + 预算 │◄────────────►│ Solver（子代理，只做执行）   │
   │ NEW→TRIAGED→ACTIVE→…       │   claim/收尾 │ 只能用 tools 白名单里的动词  │
   └───────┬──────────▲─────────┘              └──────────────┬──────────────┘
           │          │ acceptance/evidence                    │ 每次调用过 gate
           │          │                                         ▼
   ┌───────▼──────┐ ┌─┴──────────┐                     ┌──────────────────┐
   │ ledger 台账  │ │ verifier   │                     │ gate 策略引擎    │
   │ append-only  │ │ 双签 token │                     │ pre-tool 拦截    │
   └───────▲──────┘ └────────────┘                     └────────┬─────────┘
           │ 事件流                                            │ 允许/拒绝
   ┌───────┴───────────┐  ┌──────────────┐  ┌──────────────────▼─────────┐
   │ scribe（自动写笔记/│  │ envd 环境守护 │  │ tools（结构化工具动词，MCP/CLI）│
   │ WP/台账）          │  │ 唯一 env 权限 │  │ challenge.pull / gdb.run / … │
   └───────────────────┘  └──────────────┘  └────────────────────────────┘
```

**与现状的差别**：现在"提示词→模型自己找工具"；目标是"**模型只能通过 gate 允许的动词做事，状态在 board/ledger 里，不在上下文里**"。

---

## 2. 五个硬组件（都能落地，不依赖模型自觉）

### 2.1 `envd`：环境守护（唯一有权调平台 env API）

- 接口：`env.ensure(challenge) -> {url, ports, expires_at, evidence_id}`、`env.release(challenge)`、`env.state()`。
- 内部：单线程队列；`detail.endpoints[0].status=="running" && proxyIps` 才返回；90 秒未 ready ⇒ 判幽灵、拉黑、换题；**只允许单 keep-alive 探活**（本场实测：新连接才是惩罚来源）。
- 硬约束：**其它角色拿到 `env.*` 调用直接被 gate 拒绝**（caller token 校验）。
- 收益：本场 90–110 分钟的直接浪费归零；"幽灵容器/`40409` 双语义"变成代码里的状态机，而不是每个代理各自重新踩。

### 2.2 `board`：工作项状态机（替代"父代理脑子里的优先级"）

每题一条记录：

```yaml
id: 12073
state: ACTIVE           # NEW → TRIAGED → ACTIVE → (STALLED) → PARKED → SOLVED/DEAD
budget: {wall: 90m, tokens: 1.2M, conns: 300}
next_action: "读 broker FUN_231b 的 send_framed 调用点"
revisit_at: 2026-10-24T16:20
acceptance: [gate-open, hop1, hop2, hop3, oracle-flag]   # subtask 级
evidence: [work/12073/chain.log#L168, ...]
owner: pwn-12073
```

- **subtask 级验收**（借 Cybench 的 subtask 思路）：进度不再是"解出/未解出"，而是 `acceptance` 里打勾；`STALLED` 必须写 `missing:`（缺哪条原语）。
- **parked 必须有 `revisit_at`**：调度器到点自动重新入队（治~~本场"14:00–15:00 空窗却没回 12075/12076"~~ → ⚠️ **勘误（A1）**：该"空窗"不成立，14:00–15:00 有 43 次工具调用；真正的问题是 12075/12076 停手后没被重新排队。见 `work/handoff/ERRATA.md`）。
- 预算超限 ⇒ 自动 `PARKED`，由 Planner 决定是否续。

### 2.3 `ledger` + `verifier`：证据台账与双签（治 6 次假结论）

- 每条"结论"必须是一条 ledger 记录：`{claim, artifacts:[{path,sha256}], tool_calls:[...], contradicts_external:bool}`，**artifact 必须存在于磁盘**（gate 校验路径与 sha256）。
- **外部反证是必填字段**：`verdict: "not-exists|unsolvable"` 必须附 `detail.score` 的 `已答出N次` 读数（N>0 直接拒绝该 verdict）。
- `verifier` 生成 **submit token**：`{flag, evidence_ids, signer, expires}`；`submit.flag` 无 token 即拒。
- 收益：本场 12083 的 8 次无效提交、12073 的假 SOLVED、以及 5 次"不可解"都会被机制挡住。

### 2.4 `gate`：pre-tool 策略引擎（把 RULES 变成 403）

规则用 YAML 描述，`deny` 时返回 `reason + 下一步`（不是沉默失败）：

```yaml
- id: env-only-by-envd
  match: {tool: "env.*", caller: "!envd"}
  action: deny
- id: submit-needs-token
  match: {tool: "submit.flag"}
  require: {token: verify}
- id: submit-once
  match: {tool: "submit.flag", challenge: "$same"}
  require: {attempts: "<3"}
- id: net-budget
  match: {tool: "net.probe"}
  limit: {per_item_conns: 300, new_conns_per_min: 30, stop_on_slowdown: true}
- id: no-negative-verdict-without-external
  match: {tool: "board.verdict", value: "unsolvable|not-exists"}
  require: {field: external_solve_count, min: 0}   # 必须已查询且为 0
- id: claim-needs-artifact
  match: {tool: "board.claim.record"}
  require: {artifacts_exist: true, sha256_match: true}
- id: clock-is-a-tool
  match: {tool: "board.time.assert"}
  require: {called: "clock.now", max_age_s: 60}
```

**关键点**：RULES 里"禁止并发/禁止猜 flag/必须回源核对"这些句子，全部变成上述规则的 `deny`。

### 2.5 `tools`：结构化工具动词（治"工具清单不在决策路径"）

- 只暴露动词，不暴露 shell：`challenge.pull(id)`、`env.ensure`、`net.probe(target,budget)`、`gdb.run(script)`、`bin.checksec(path)`、`heap.model`、`decode.astc(path)`、`zip.aes(path,pass)`、`web.js(url)`、`pdf.md(path)`、`submit.flag(flag,token)`。
- **`tools.search(query)` 是强制步骤**：Triage 阶段必须调用一次并把结果写进 `board.tool_plan`；否则 item 不能进 `ACTIVE`。
  （本场 `pyzipper` 装着没人用，就是因为没有这一步。）
- 每个动词返回 JSON + `evidence_id`，直接进 ledger——**"我看到 X"必须指向一条工具回包**（治 soliloquizing）。

---

## 3. Skills 2.0：从"文档"变成"可执行清单"

现在的 `skill` 是加载一段 Markdown。改成 **`skill.load` 返回一个执行契约**：

```yaml
id: pwn-heap-tcache
when: "binary calls malloc/free && glibc >= 2.32"
bind_tools: [bin.checksec, gdb.run, heap.model, net.probe]
steps:
  - 用 heap.model 复现 UAF 读（acceptance: 读到相邻对象）
  - 用 safe-linking 公式构造 fd（acceptance: 本地 tcache 命中）
  - 栈迁移前验证 16 字节对齐（failure_mode: saved RIP ≡ 8 mod 16）
acceptance:
  - artifacts: [本地 UAF 日志]
  - artifacts: [本地任意写日志]
failure_modes:
  - {symptom: "chunk 走了 fastbin", fix: "关闭 tcache 或改 size"}
```

- **加载即绑定**：加载后 gate 把该 skill 的 `bind_tools` 设为白名单；`steps` 的 `acceptance` 进 board。
- **踩坑→改 skill 是流程的一部分**（本场我只写了复盘、没改 skill，等于没沉淀）：赛后必须把每次 `failure_mode` 写回 skill 文件，否则下场比赛 skill 库不增长。

---

## 4. 角色分工（代码层面的边界，不是称呼）

| 角色 | 权限 | 禁止 | 本场对应 |
|---|---|---|---|
| Planner（父代理） | board 只读 + `board.reorder/unblock/stop` + 批 verify token | 禁止直接调 `env.*`/`submit`/`net.*` | 现在是"什么都干"，带宽被操作吞掉 |
| Warden | 只有它持有 `env.*` | 不做题 | 本场由父代理兼任 → 瓶颈 |
| Solver | tools 白名单 + `board.claim.record` | 不得 `submit`（除非自己解出且拿 token） | 基本符合 |
| Verifier | `board.verdict` + 签 submit token | 不做题 | 本场缺失 → 6 次假结论 |
| Scribe | 从 ledger 事件生成 notes/WP | 不改结论 | 本场缺失 → 最后 2 小时补文档 |

---

## 5. 上下文与恢复（治"停不下来/回不去/压缩即失忆"）

- **状态外置**：容器地址、预算、判据、parked 原因全在 `board`/`ledger`；会话压缩不影响。
- **可恢复会话**：每个 item 记录 `session_id` + `workspace snapshot`；`resume(item)` 从 board 读状态，不依赖聊天历史（CAI 的"暂停后仍保持排名"就是这套）。
- **交接模板由 Scribe 生成**：`state / acceptance 打勾情况 / missing / next_action / artifacts`，不允许自由发挥。

---

## 6. 迁移路线（不要一次吃完）

**Phase 0（半天，止血）**：`envd` + `gate`（只拦 `env.*` 与 `submit`）。验收：任意代理无法直接 start/stop 容器；无 token 无法提交。

**Phase 1（1 天，可观测）**：`ledger`（append-only + artifact 校验）+ `board`（状态机 + revisit）+ `scribe`（自动写 notes）。验收：每题有 subtask 进度；连续 2 小时无"空窗"（parked 自动回队）。

**Phase 2（2–3 天，能力面）**：`tools` 动词化 + `tools.search` 强制 + Skills 2.0（bind_tools + acceptance）+ `verifier` 双签。验收：新题 60 秒内产出 `tool_plan`；同一错误不重复出现两次。

**Phase 3（装备）**：黄金镜像（Android 模拟器 + Windows VM + ASTC/Oodle + 浏览器）+ Swarm（重任务一次性 worker）。验收：任一题环境准备 <60 秒。

---

## 7. 需要拍板的三件事

1. **父代理是否彻底退出执行**（只留 board 决策 + 批 token）？
   - 我的建议：是。否则"决策延迟"永远是瓶颈。
   - 反方意见：应急时父代理手工干预更快——可以用"break-glass"：`board.override` 需要人类口令，且自动记 ledger。
2. **门禁粒度**：只拦高风险（env/submit/net），还是连"写结论/加载技能"也拦？
   - 我的建议：**全部拦**，但拒绝时给"下一步提示"，否则会变慢（本场已看到 403 式失败会浪费轮次）。
3. **建造顺序**：先 `envd+gate`（止血）还是先 `board+ledger`（可观测）？
   - 我的建议：`envd+gate` 半天出效果，`ledger` 紧随（否则后面全是"我记得"）。

---

## 8. 一句话

**提示词是"建议"，架构是"物理定律"。** 本场我们输在物理定律缺失：谁都能开容器、谁都能提交、结论不需要证据、进度不存在状态里。
把这些做成代码后，同一批 agent 的产出会明显不同；剩下的差距才轮到"模型能不能想到新解法"。
