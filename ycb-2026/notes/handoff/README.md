# CTF Agent 框架 · 交接包（给新会话）

> 来源：2026 羊城杯（DASCTF · match 1750）实战。本包**不含代码**，只有需求、架构、方法与可直接加载的提示词。
>
> ⚠️ **勘误 2026-10-24（A2）**：本句不成立——包内**含有代码与二进制**（`12068/main.exe`、`win_server.exe`、`12068-solve.py`，`12070/BabyMenuKit.ps1` 等）。另有两处需注意：A1「14:00–15:00 空窗」已被复算推翻；B1 `prompts/skills/*` 的 frontmatter 若按原样装进 DSH 会被静默丢弃。全部见 `ERRATA.md`。
> 新会话的任务：**基于 DSH Web 搭一个专门打 CTF 的 agent 框架**（不是改现有 AGENTS.md/RULES.md）。

## 先读顺序

1. `CTF-FRAMEWORK-SPEC.md` —— 需求 / 架构 / DSH 映射 / 数据契约 / 阶段 / 验收 / 风险
2. `METHODS.md` —— 本场 agent 真正用过并生效的 8 个方法（每条含判据与反例）
3. `prompts/*.md` —— 5 个角色的系统提示（Planner/Warden/Triage/Solver/Verifier/Scribe）
4. `prompts/skills/*.md` —— 8 个可加载技能（Skills 2.0 契约格式）
   > ⚠️ **勘误 2026-10-24（B1）**：这些文件的 frontmatter 若**按原样**装进 DSH，`when`/`bind_tools`/`acceptance`/`failure_modes` 会被 `dsh-skill-filesystem` **静默丢弃**（它只认 `name`/`description`/`whenToUse`/`metadata`），技能只剩名字和一句描述，且**不报错**。正确写法见 `prompts/skills/_template.dsh.md`，说明见 `ERRATA.md`（B1）。
5. `checklists/*.md` —— 负结论检查表 / 开赛 Runbook / 交接模板

## 一句话架构

**DSH 提供运行时（tools/hooks/skills/subagent/session/web）；本框架补领域层：`envd`（环境守护）+ `board`（工作项状态机）+ `ledger`（证据台账）+ `gate`（策略门禁）+ `tools`（结构化动词）。**
提示词只做"解释为什么"，**约束一律由 gate 强制**（不可绕过）。

## 本场实测到的、必须被框架解决的失效（每条都有证据）

| 失效 | 本场证据 | 框架对策 |
|---|---|---|
| 容器抢/踩/幽灵态 | 4 台幽灵容器；销毁不回落名额；90–110 分钟墙钟 | `envd` 单点 + 幽灵黑名单 |
| 无效提交 | 12083 连续 8 次格式错误 | `verifier` 签 token 才能 submit |
| 假结论/假突破 | 6 次"不可解"，1 次假 SOLVED | `ledger` 强制 artifact + 外部反证 |
| 工具没被想到 | `pyzipper` 已装却手写 20 行 HMAC | `tools.search` 强制，`tool_plan` 才能进 ACTIVE |
| 技能加载不等于执行 | 多题 `SKILLS_USED` 部分使用 | Skills 2.0：`bind_tools` + `acceptance` |
| 停下不回 | 12075/12076 停后再没回去 | `board.revisit_at` + `missing` |
| 时间漂移 | 12:32 被当作 13:29 | `clock.now` 工具 + 断言门禁 |
