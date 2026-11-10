# 外部调研：别人怎么用 Agent 打 CTF（2026-10-24 赛后代查）

> 目的：用**公开的一手资料**校准我们这场暴露的问题（环境、编排、工具接口、判据）。
> 结论先行：**公开资料里"快"的队伍/框架，赢在 ①环境与实例自动化 ②工具接口（尤其交互式调试器） ③技能/判据沉淀 ④同题赛马 + 突破共享，而不是"题数×代理数"。**

---

## 1. 关键来源与要点

### 1.1 EnIGMA（ICML 2025）——**工具接口 > 模型能力**

- 论文：[EnIGMA: Interactive Tools Substantially Assist LM Agents in Finding Security Vulnerabilities](https://arxiv.org/abs/2409.16165)
- 核心：为 agent 新增 **交互式工具**（可运行的调试器、服务连接工具等），在 390 道 CTF、4 个基准上取得 SOTA
  （NYU CTF / Intercode-CTF / CyBench）。
- 两个必须记住的副产品：
  1. **"soliloquizing"**：模型会在**没有与环境交互**的情况下自造观察（幻觉出"我看到了 X"）。
     → 这正是我们本场 6 次"假结论/假突破"的同构问题（见 `notes/methods/POST-MORTEM-YCB2026.md` 附录 B）。
  2. **数据泄漏量化**：基准题可能被模型见过，评估要扣掉"记忆分"。
- 对我们的映射：我们的环境里**缺的恰恰是"agent 友好的交互式工具"**——GDB 包装、无头浏览器、ASTC/Oodle 解码器、容器取址器。
  我们让 agent 用 shell 手搓这些，等于让它自己造工具（慢且易错）。

### 1.2 D-CIPHER（2025）——**Planner + 异构 Executor**

- 论文：[D-CIPHER: Dynamic Collaborative Intelligent Multi-Agent System with Planner and Heterogeneous Executors](https://arxiv.org/abs/2502.10931)
- 结构：**Planner**（全局规划）+ 多个**异构 Executor**（各管一类任务）+ **Auto-prompter**（自动生成高质量初始提示）。
- 结果：NYU CTF Bench **22.0%**、Cybench **22.5%**、HackTheBox **44.0%**，比前作高 **2.5–8.5%**；
  ATT&CK 技术覆盖 +65%。
- 对我们的映射：**"Planner 独立于 Executor"** 是关键——我们的父代理同时当 Planner 和"操作员"（轮询容器、写文档），
  Planner 的带宽被操作吞掉了。

### 1.3 CAI / Cybersecurity AI（2025-12）——**顶级赛事已被工程化 agent 拿下**

- 论文：[Cybersecurity AI: The World's Top AI Agent for Security CTF](https://arxiv.org/abs/2512.02654)
- 数据：2025 年多个赛事 Rank #1；**Neurogrid 45 题拿下 41 面旗（$50,000 冠军）**；Dragos OT 比人类强队快 37% 到 10K 分；
  **被故意中途暂停后仍保持顶级排名**。
- 成本：专用模型架构把 **1B token 的推理成本从 $5,940 降到 $119**。
- 对我们的映射：①"暂停不影响排名"说明其**状态可恢复、任务可中断续跑**（我们缺 session 恢复）；
  ②成本效率意味着**可以长时间跑**，不必靠"猜一次就中"。

### 1.4 Cybench（ICLR 2025 Oral）——**同一模型，脚手架差 4 倍**

- 论文：[Cybench: A Framework for Evaluating Cybersecurity Capabilities and Risks of Language Models](https://arxiv.org/abs/2408.08926)
- 40 道专业 CTF、4 个赛事；为难题设 **subtask（中间步骤）** 评分；对 GPT-4o 与 Claude 3.5 Sonnet
  比较 **4 种脚手架**（structured bash / action-only / pseudoterminal / web search）。
- 关键事实：**强模型能解出"人类队 11 分钟"的题**，但最难的一题人类要 24h54m——说明**题目难度跨度大，排序比算力重要**。
- 对我们的映射：我们的"脚手架"是自制的（ycb.py + 手写脚本），**没有 subtask 级别的进度度量**，
  所以无法判断"这题推进了 30% 还是 0%"，只能靠感觉停/不停。

### 1.5 ctf-agent-workstation / ctf-agent-orchestrator（NUS Greyhats，开源工程）——**最接近我们需要的形态**

- 仓库：[NUSGreyhats/ctf-agent-workstation](https://github.com/NUSGreyhats/ctf-agent-workstation)
- 它的自述第一句就是我们的结论：**"the bottleneck is usually *environment*, not intelligence"**。
- 直接可抄的设计（我们这场缺的）：
  1. **实例自动化**：HTB/Cywaria/SAS 等平台的 **on-demand instance 在开解时启动，连接信息自动注入 prompt**；
     → 容器"谁去 start / 地址怎么给"不是 agent 的任务，是**平台集成层**的任务。**这印证了我们"Warden 必须是脚本/单点"的判断。**
  2. **`ctfgrep` 预检**：**在 agent 开始之前**静默扫题目文件，找出候选 flag；
     → 我们本场多次"flag 就在附件里但没人先扫一遍"（12080/12082 的诱饵判断也靠这个更快）。
  3. **同题赛马 + 突破共享**：多个 agent 各自独立 workspace，通过 **working notes + `notify_teammates`** 共享**已验证**的突破；
     **一个 agent 解出/提交正确 → 自动停掉同题其它 run**。
     → 我们本场是"同题多代理各写各的 notes，父代理人工转述"，慢且易丢。
  4. **Steering / Resume / Retry / Unsolve**：中途给提示、从 session 恢复、重试、撤销"已解"状态。
     → 我们缺"Resume"，导致 12079/12075 停下就再也回不去。
  5. **Advisor（每题一个顾问 agent）**：读 solver 的实时 transcript、查资料/CVE、把**简短提示**转给 solver。
     → 这正是我们缺的 Verifier/Advisor 角色。
  6. **Skills 作为版本化工作流**，"踩坑后把它写进 skill，解出率随库增长"。
     → 我们的 `notes/briefs/RULES.md` + 30 个 skills 已有雏形，但**本场没有"踩坑→改 skill"的闭环**（我写进了复盘，但没改 skill）。
  7. **Swarm**：把重 CPU/内存/磁盘的题**派到一次性 worker VM**（golden image 克隆，空闲 30 分钟自动停）。
     → 我们的 VM/模拟器缺口，本质是"没有可克隆的黄金镜像"。
  8. **持久 GDB MCP server**、headless IDA 技能 → 交互式调试器**作为工具暴露**，而不是让 agent 写 gdb 脚本。
  9. 统计：per-challenge token/cost/duration/turns 明细 → 用数据判断"这题值不值得继续"。

---

## 2. 与我们本场缺陷的逐条对应

| 我们的问题（一手证据） | 外部资料里的对应物 | 结论 |
|---|---|---|
| 容器起停/取址/幽灵态吃掉 90–110 分钟 | 「on-demand instance 自动启动 + 连接信息注入 prompt」；「实例是平台集成层的事」 | **不是"该派一个子代理管容器"，而是"该有一层自动 provisioning"** |
| 父代理串行轮询容器、写文档 → 决策带宽被吞 | 「Planner 独立于 Executor」 | 父代理必须**脱离操作** |
| 5 次"不可解/不存在"负结论被推翻 | 「soliloquizing：无交互自造观察」 | 需要**Verifier + 强制环境交互**（每条结论必须有回包/文件/日志） |
| 12073 假"SOLVED"、12086 假"无端点" | 同上 + 「Auto-submit only on validated flag」 | 需要**双签 + 自动停兄弟 run** |
| 12079 十轮单指标打转 | 「subtask 评分」+「Advisor 读 transcript 给提示」 | 需要**中间指标/进度度量**，而不是"解出/未解出"二元 |
| 同题多代理各写各的 notes | 「working notes + notify_teammates + 突破共享」 | 需要**共享突破总线**（一条结论全员可见） |
| 离线题停下就回不去 | 「Resume / Retry」「暂停后仍保持排名」 | 需要**session 恢复 + parked 队列** |
| 装备缺口（ASTC/Oodle/模拟器/VM） | 「preloaded toolchain」「Swarm golden image」 | 需要**黄金镜像 + 解码器全家桶** |
| 技能加载了但没用上（本场 SKILLS_USED 多为"部分使用"） | 「踩坑→写进 skill→解出率上升」 | 技能必须**带可执行判据**，否则只是文档 |

---

## 3. 可直接采纳的 10 条设计（按性价比排序）

| # | 设计 | 对应缺口 | 工作量 | 验收方式 |
|---|---|---|---|---|
| 1 | **实例 provisioning 层**：`container-pool.py` 提供 `ensure(challenge)->url`，自动 start/取址/预热/健康/回收；地址写进 `work/env/<id>.json`，agent 只读 | 容器 90–110 分钟浪费 | 半天 | 连续 5 次 `ensure` 成功率 ≥95%，无人工介入 |
| 2 | **`ctfgrep` 预检**：解题前扫附件（含解包后）匹配 flag 形态 + 已知诱饵词 | 本场多次"先猜后看" | 2 小时 | 对 12080/12082/12083 的附件能直接给出候选 |
| 3 | **Verifier 双签 + 自动停兄弟**：任何 flag 提交前由独立 agent 复核；正确后停同题其它 run | 假突破 2 次、重复提交 9 次 | 半天 | 本场若回放，12083 的 8 次错误应为 1–2 次 |
| 4 | **突破总线**：`work/bus/<challenge>.md` 只允许写"已验证结论 + 证据路径"，agent 每轮必须读 | 同题代理重复劳动 | 2 小时 | 同题两个代理的结论重复率 <20% |
| 5 | **Resume/parked 队列**：任务状态机 + `next_action` + `revisit_at`；15:00 前自动把 parked 题重新入队 | 离线题停止后不回 | 半天 | 空窗期自动分配 ≥1 轮 |
| 6 | **交互式工具层**：GDB wrapper（`gdb -batch -x` 模板）、无头浏览器封装（含 `HOME=` 可写）、ASTC/Oodle 解码器、PDF/Office 生成 | EnIGMA 的核心结论 | 1 天 | 工具能"一条命令出结构化结果"，不需要 agent 写解析 |
| 7 | **subtask 评分**：每题定义 3–5 个可判定中间态（如"拿到泄漏""过了门禁""打通下一跳"），进度可见 | 12079 打转、12073 半成品 | 半天 | 家长能按"进度百分比"排序，而不是感觉 |
| 8 | **黄金镜像 + Swarm**：一台预装全部工具的镜像；重任务派一次性 worker | VM/模拟器缺口 | 1–2 天 | 新题环境准备 <60 秒 |
| 9 | **Advisor agent**（每题一个）：读 solver transcript、查 CVE/资料、给≤3 行提示 | 卡住时无人解阻塞 | 半天 | 卡住题平均恢复时间减半 |
| 10 | **成本/轮次面板**：per-challenge token/时间/轮次，用数据决定"停/继续" | 投入产出负相关 | 2 小时 | 每小时重排有数据支撑 |

---

## 4. 对你三条假设的校准

1. **"每道题都要派子代理"** → 外部资料的做法不是"题数×代理"，而是**"同题赛马（2–3 个）+ 突破共享 + 正确即停兄弟"**；
   以及**把资源类工作（实例）自动化**。把 25 题铺满 25 个代理，会让"等我决策"的队列更长（本场已出现）。
2. **"需要别的子代理来管容器"** → 更准确的版本是**"需要一层 provisioning 代码 + 一个单点守护者"**；
   开源工程里容器是**平台集成层的职责**，不是 agent 的职责。
3. **"离线题应该一直跑"** → 对，但外部资料强调的是**可恢复性**（Resume/Retry/状态持久化），
   而不是"不停机"。我们要补的是 **parked 队列 + 中间进度**，否则"继续跑"只是重跑同一条死路。

---

## 5. 与"别人快"的直接对照

| 快队/框架的机制 | 我们的现状 | 影响 |
|---|---|---|
| 实例自动 provisioning（on-demand + 注入） | 父代理手工 `ycb.py env` 轮询 | 90–110 分钟 |
| 交互式调试器/浏览器作为工具 | 让 agent 写 gdb/py 脚本 | 每题多 20–40 分钟 |
| 同题赛马 + 突破共享 + 自动停 | 同题多代理各写各的 | 重复劳动 + 假结论 |
| skills 版本化沉淀 | 有 80 个 skill，但本场"踩坑→改 skill"闭环缺失 | 同类错误重复犯 |
| subtask 进度 | 只有"解出/未解出" | 停/继续全凭感觉 |
| 成本面板 | 无 | 高投入低产出无法被及早发现 |

---

## 6. 一句话结论

**我们的 agent 不是"能力到顶"，而是"接口（工具/环境/进度）到顶"。**
EnIGMA 的结论是"交互式工具显著提升表现"，workstation 作者的第一句话是"瓶颈是环境不是智能"，
这两条与本场一手数据（投入与解出率负相关、90 分钟耗在容器、5 次判据翻案）**完全一致**。
所以下一步投入的顺序应该是：**provisioning 层 → 交互式工具层 → 双签/突破总线 → subtask 进度 → 黄金镜像**，
而不是"再加 20 个代理"。

---

## 参考

- [EnIGMA: Interactive Tools Substantially Assist LM Agents in Finding Security Vulnerabilities (ICML 2025)](https://arxiv.org/abs/2409.16165)
- [D-CIPHER: Dynamic Collaborative Intelligent Multi-Agent System with Planner and Heterogeneous Executors (2025)](https://arxiv.org/abs/2502.10931)
- [Cybersecurity AI: The World's Top AI Agent for Security Capture-the-Flag (CTF) (2025-12)](https://arxiv.org/abs/2512.02654)
- [Cybench: A Framework for Evaluating Cybersecurity Capabilities and Risks of Language Models (ICLR 2025 Oral)](https://arxiv.org/abs/2408.08926)
- [NUSGreyhats/ctf-agent-workstation —— AI-powered CTF solving workstation](https://github.com/NUSGreyhats/ctf-agent-workstation)
- [LD-CIPHER: an LLM Multi-agent Framework for Lightweight Autonomous Solutions to CTF Challenges (IEEE)](https://ieeexplore.ieee.org/document/11220455)
