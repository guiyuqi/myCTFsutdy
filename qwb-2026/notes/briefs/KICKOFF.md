# 开赛启动词（粘贴用）

> **用法**：开赛时新建会话（workspace 选 `~/ctf-2026`），把下面 `====` 之间整段粘进去。
> 只需替换 `<平台域名>`、`<N> 题`、`<T>` 三处；凭据已配好（`~/.config/ctf/creds.env`）。
> 整段设计原则：**只写目标 + 硬门槛 + 次序**，平台怪癖在 `work/platform-<域名>.md` 里，不重复。

```
====================== 复制从这里开始 ======================

【CTF 开赛启动】你是本队父代理。目标：<N> 题 / 时长 <T>。平台：<平台域名>。
凭据：`~/.config/ctf/creds.env`（CTFD_BASE/CTFD_COOKIE 已配）。
失效时先 `python3 scripts/ctfd.py creds` 定位问题，不要猜；不要向我索要明文凭据。

━━ 硬门槛（不满足不许进下一步；每条都要在汇报里给出证据行）━━
G1 环境：`bash scripts/selfcheck.sh --full | tee evidence/selfcheck.log`。
         有缺失 → 记进 needs-approval.md，**禁止自行安装**。（落盘是为了事后可审计）
G2 规则：读 `notes/briefs/RULES.md` §0（技能路由）与 §0.2（技法包）。
         **首个汇报必须贴**"题目类型 → 将加载的 skill 名"。
G3 平台事实：`work/platform-*.md` 存在就**先读完再动手**（这是唯一允许赛中读的额外 md）。
G4 纪律：凭据只在 `~/.config/ctf/creds.env`，**不得写入工作区**；提交只走 `scripts/ctfd.py`。

━━ 阶段 1 · 5 分钟侦察（抢血的前提）━━
1. `python3 scripts/ctfd.py bulk --download` → `work/triage.md`
   （题多时按 `--category` 分批，或加 `--limit`）
2. 排序：**解出人数少 + 分值低 + type=standard 优先** → 先打不占容器的静态题
3. 后台跑 `python3 scripts/ctfd.py watch --interval 5`：**新题出现立刻派单**（一血常在新题上）
4. VIP / 403 / 429 → 标记跳过，**不要研究锁**

━━ 阶段 2 · 每题动手之前（顺序不可颠倒）━━
1. `python3 scripts/ctfd.py hint <id>` ← **自动解锁 cost=0 的免费 hint**
   （历史上一道 crypto 的唯一突破口就是一条免费 hint；`--unlock`/`--all` 会花分，未经我同意不要用）
2. 从题目描述确认 **flag 格式**（前缀不统一，禁止硬套 ctfshow{} / flag{}）
3. 只有 `type=dynamic_docker` 才起容器：一次 1 个、60s 限频；只取必须联网的东西，**立刻 stop**

━━ 阶段 3 · 派单（一题一子代理）━━
- brief 必须自包含：题目原文摘要 + 附件路径 + **技能名** + flag 格式 + 报告格式
- 子代理必须：**先 `skill` 加载再动手**；报告含 `SKILLS` / `SKILLS_USED` / `BLOCKED`
- 高分或低解出、且**连续 5 次工具调用无新证据** → 赛马 2 个；
  先出可复现 flag 者胜，**立刻提交并 `interrupt_agent` 停掉另一个**
- 卡住时读它的 `work/<id>_*/` 产物，把"缺什么"补进消息，**不要原样重发 brief**
- **派完立即结束本回合**：不要 `sleep`、不要轮询 `list_agents`、不要反复读 `job_output`
  干等；完成摘要会自动回注。**同一目标＋同一范围＋同一方法只派一个跑者**，
  要换跑者必须换方法（否则只是把同一份 token 烧两遍）。

──── 派单骨架（照抄省事；**不要求统一格式**，报告/wp 格式随平台变）────
【任务 <id> · <题名>】附件 `firmware/<文件>`｜目标地址 <http://<address>/ 或 无容器>
【先读】`notes/briefs/RULES.md`（§0 技能路由 / §0.1 硬性边界 / §4 报告 / §4.1 短回报）
【技能】<技能名 1>、<技能名 2>　←　动手前 `skill` 加载，并用 1–2 行说明关键判据
【意图·去重键】目标 <拿到什么>｜范围 <只碰哪个 host / 读哪个附件>｜方法 <怎样算解出>
【flag 格式】`<前缀>{...}`　←　按题目明示，禁硬套
【纪律】① 每确认一组事实立即回报 `FACT:` / `EVIDENCE:` / `NEXT:`（卡住换 `STUCK:`）
　　　　② 连续 5 次工具调用无新证据 → 换**本质不同**路线，或 `BLOCKED`
　　　　③ 不自行装包；不碰平台与其他题目标；容器用完立刻 stop
　　　　④ flag 到手**自己提交**（`CTF_AGENT=<名> ctfd.py submit`），
　　　　　 脚本拒提（退出码 2）时立刻停手上报；`--force` 不许自己加
──── 骨架结束 ────

━━ 阶段 4 · 提交（抢血的关键动作）━━
- flag 到手**立刻**：`python3 scripts/ctfd.py submit <id> '<flag>'`（限速/排队/记账已内置）
- 同题 **≤3 次**；提交前本地可复现；**403 不是 flag 错**（先疑 CSRF/权限）
- 父代理独立对账：平台 `is_solved` ↔ `evidence/submit-log.jsonl`

━━ 阶段 5 · 交付 ━━
`notes/<id>-<名>.md`、`scripts/<id>-solve.py`、`evidence/<id>-*`、
`notes/FLAGS.md`、`work/AGENT-STATE.md`、`wp.md`
`wp.md` 里的 flag 与 submit-log 中 `result:true` **逐字节比对**。

━━ 抢血次序（有时间压力就照这个打）━━
① 静态小分值签到 → ② watch 抓到的新题 → ③ 已 READY（离线算完、只差提交）→ ④ 其余动态题
单题 **15–20 分钟无新证据** → 换人或赛马；**不做无限枚举**；**不做"猜 flag 写法"的重复提交**。

━━ 现在开始 ━━
先跑 G1/G2/G3 并用一行汇报结论，然后**不要等我确认**，直接进阶段 1。
有 flag 就立刻提交并贴出来；卡住就报 BLOCKED + 已排除方向。

======================= 复制到这里结束 =======================
```
