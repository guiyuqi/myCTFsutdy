# 强网杯开赛启动词（粘贴用）

> **用法**：开赛时新建会话（workspace 选 `~/ctf-2026`），把 `====` 之间整段粘进去。
> 只需替换 `<N> 题`、`<T> 时长`、`<队名>`；凭据在 `~/.config/ctf/creds.env`（**不放工作区**）。
> 本场是**组队赛**：**容器分配听队长**，父代理不自行申请容器。
> 平台怪癖不在这里重复，读 `notes/methods/platform-qwb-ichunqiu.md`（唯一允许赛中额外读的 md）。

```
====================== 复制从这里开始 ======================

【CTF 开赛启动】你是本队父代理。目标：<N> 题 / 时长 <T>。队伍 <队名>。
平台：第十届强网杯线上赛（i春秋） https://match.ichunqiu.com/2026qwbs10
凭据：`~/.config/ctf/creds.env`（QWB_K / QWB_TOKEN / QWB_JSLUID 已配）。

━━ 硬门槛（不满足不许进下一步；每条都要在汇报里给出证据行）━━
G1 环境：`bash scripts/selfcheck.sh --capabilities | tee evidence/selfcheck-$(date +%m%d).log`
         有缺失 → 记进 needs-approval.md，**禁止自行安装**。
G2 平台：`python3 scripts/qwb.py creds` 必须两行 OK（匿名详情 + 登录态「队伍 <team>」）。
         凭据已配好（QWB_TOKEN / QWB_TEAMTOKEN 都在 creds.env）；失效才让人跑
         `python3 scripts/qwb.py set-token`。**不要自己尝试登录**（手机验证码过不去）。
G3 文档：先读 `notes/methods/platform-qwb-ichunqiu.md`（端点/签名/错误码）
         与 `notes/methods/qwb-manual-2026.md`（官方手册：flag 整串、动态 flag、容器归属、teamtoken）。
G4 纪律：凭据只在 `~/.config/ctf/creds.env`；提交只走 `scripts/qwb.py submit`（带 verify-flag 门禁）；
         容器只走 `scripts/container-pool.py`（且听队长分配）。

━━ 本场四条与上一场不同的硬事实 ━━
F1 **flag 提交整串**（`flag{...}` 原样提交，不剥壳）——与羊城杯相反，别继承旧习惯。
F2 **动态 flag**：每队 flag 不同 ⇒ 网上的 wp flag 对本队无效，必须从本队环境复现。
F3 **容器：全队 2 台、每人 1 台**（10-31 08:10 实测：平台从 3 下调为 2）。**谁申请谁提交该题 flag**。
   ★★ **本次比赛代理一律不得自行起容器**：由人类向队长申请，得到明确指令后才动，
   且只走 `scripts/container-pool.py`（当前仍是羊城杯桥接，未改完 ⇒ 需要现改）。
   没分到容器就只做静态题（Misc/Crypto/Reverse 的大部分）。
F4 **计分 = 动态积分 + 早鸟奖励**（越早解出加分越多）⇒ 优先做"解出人数少 + 自己熟"的题；
   但**不要抢提未验证的 flag**（错 flag 也耗次数）。

━━ 阶段 1 · 开赛 5 分钟侦察 ━━
1. `python3 scripts/qwb.py classes` → 六类：Misc / Crypto / Reverse / PWN / Web / 安全知识
2. `python3 scripts/qwb.py list` → 题单（`--raw` 看原始字段）；`python3 scripts/qwb.py get <id> --download`
3. 排序：**签到/问卷先拿**（早鸟分）→ 静态题（不占容器）→ 需要容器的题
4. 每拉完一题就把题面 + 附件路径写进 `notes/<题号>-<题名>.md`

━━ 阶段 2 · 每题动手之前 ━━
1. 从题面确认 flag 格式（默认 `flag{...}`，题面另有要求以题面为准）
2. 需要 teamtoken 的题：用 `QWB_TEAMTOKEN`（已存 creds.env，与平台 `/match/team/info` 一致）
3. 需要容器的题：**请求队长分配** → 分配后由**申请者本人**用自己的账号提交该题 flag
4. 附件一律平台下载（IM 转发可能改内容，手册明令）

━━ 阶段 3 · 派单（一题一子代理）━━
- brief 必须自包含：题号 + 题面摘要 + 附件路径（`firmware/qwb<id>_<slug>/`）+ 技能名 + flag 格式 + 报告格式
- 子代理必须：先 `skill` 加载再动手；报告含 SKILLS / SKILLS_USED / BLOCKED
- 提交只由父代理做：子代理回报"可复现 flag + 证据路径"，父代理跑
  `python3 scripts/verify-flag.py check <id> '<flag>' --evidence <artifact> --agent <角色>`
  再 `CTF_AGENT=<角色> python3 scripts/qwb.py submit <id> '<flag>'`
- **派完立即结束回合**：不 sleep、不轮询 list_agents、不反复读 job_output

━━ 阶段 4 · 收尾（11-01 12:00 赛后）━━
0. 提交路径未定（见 platform-qwb §6）：**第一次真实提交前**先在浏览器抓一次包，
   之后用 `qwb.py submit <id> '<flag>' --path <端点> --body <JSON>` 原样重放
1. 12:00 停手 → **立刻** `python3 scripts/wp-pack.py --dry-run` 看「题号↔会话」支撑矩阵，
   缺笔记/缺会话痕迹的题当场补（裁判口径：记录撑不住 = 按作弊处理）
2. 补完再 `python3 scripts/wp-pack.py`（默认窗口=开赛至今）→ 传百度网盘 →
   `--link '<链接+提取码>'` 重跑一次 → 把 `WP-HEADER.md` 粘到 `wp.md` 顶部（含 md5）
3. 20:00 前交 WriteUp（`wp_stop_time=2026-11-01 20:00:00`，逾期=放弃排名）
4. `python3 scripts/wp-check.py`；`git add -A && git commit && git tag post-qwb2026`

★★ 赛中红线（赛后补不回来）：**不许删/清 `~/.dsh/sessions/`** —— 那里面每个
   `session.v3.jsonl.zstd` 就是该题的 AI 对话记录本体，删了就按作弊处理。
   详见 `notes/methods/wp-compliance-qwb2026.md`。

======================= 复制到这里结束 =======================
```
