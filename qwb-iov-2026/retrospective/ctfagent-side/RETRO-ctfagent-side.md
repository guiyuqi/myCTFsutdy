# 2026 强网杯·车联网安全专项赛 深度复盘

> 赛事：2026 第十届强网杯 · 车联网安全专项赛（CTF 遴选赛）
> 时间：2026-11-08 09:00–12:00（3 小时）｜平台：太初封神台
> 队伍：<team>｜赛况快照（11:45）：**630 PT · 第 48 名 · 解出 3 题 · 一血 1 个**
> 复盘口径：数据全部来自本机 `~/.ctfagent/state/`（15 个 run 的事件流、usage 库、台账、
> 每 run 的 planner 快照）；结论分 **【已核】**（有命令/文件位置）/ **【判词】**（我的推理）。
> 复算脚本：`research/retro-qwb-iov/analyze_runs.py`（产出 `digests/`）；复现实验：`plan-test/`。

---

## 0. 先给六条结论

1. **当天最大的损失不是模型，是 planner 槽位没有凭证。** `llm_profiles.planner.endpoint_id=""`，
   而 DeepSeek key 只按账号注入给 worker ⇒ planner 进程拿不到 key ⇒ Pi 静默退出（rc=0、0 token、不产 draft）
   ⇒ muteki 记 `planner_invalid_plan` ⇒ 3 次重试后整个 run 以 `runtime_failure` 结束。
   usage 库里 **1 081 条 coordinator 记录全是 `status=error` / token 全 null，成功 0 条**。【已核，见 §4】
2. **整个比赛没有一次成功的"规划"。** 15 个 run 合计 **225 次"代"**，只有 3 次以 `solved` 收尾；
   271 次 worker 启动 **全部是 `bootstrap` 角色**，`explore / race / review / verify` 一次都没跑。
   系统实际退化成：**单 worker 短跑（4–15 分钟）→ planner 死 → run 关 → 自动重开 → 再来一轮**。【已核】
3. **即使这样还是解出 3 题**，而且这 3 题的关键突破都发生在单个 bootstrap worker 的窗口内
   （18.4 分钟 / 82 分钟 / 86 分钟，跨 3 / 9 / 11 代累积）。投入：3 题共 **31M token**；
   未解的 12 个 run 花掉 **184M token**。【已核】
4. **"flash 到智商上限"这个判断，证据不足**。失败分两类：
   ① **执行/编排类**（planner、并发、上下文短跑）——这是当天的主因，换模型治不了；
   ② **结构洞察类**（6–8 道题已做到最后一步，差一个"题眼"）——这类换 GLM 可能有用，但也可能只是时间不够。
   直接证据：同一模型 + 同一扩展 + 真实 37 KB 图 YAML，我手工跑 planner **15 秒就 commit 了一份合法计划**。【已核，§4.3】
5. **这一场的"架构更换"只落实了一半**：真正跑的是 `muteki + Pi + tools/dispatch.py + 3 个补丁`；
   `ctfagent` 的假设族台账/判死门禁**没有上桌**（台账里只有赛前一天留下的 1 题 4 回合、0 族、0 判死），
   候选门禁补丁（0002）也**没启用**（启动脚本从未 export `MUTEKI_CTFAGENT_*`，全机无进程带该变量）。【已核，§5】
6. **并发不是 2，是 12**。配置 `max_workers=1`、seat `max_running=2`，但实测同一分钟有 **12 个 run 在打工具**，
   ≥6 个并发的分钟数 **145 分钟**。214M token ≈ **$70**（按 Pi 目录价 flash 0.30/1.20 USD/M 拆分算）。
   "并发就是钱的倍数"这句话是对的，只是实际倍数没人看住。【已核】

7. **方案 A 已落地并实测通过**：planner/titler 绑定账号、候选门环境写进 `start.sh`、
   preflight 新增 blocking 的 `planner.smoke`——实测冒烟 28.6 s 提交成功（§7.7）。

---

## 1. 账本总表（15 个 run，全部按事件流现算）

| 题 | run | 分钟 | 代 | 调用 | python 类占比 | token | ≈$ | 解出 |
|---|---|---|---|---|---|---|---|---|
| BCM-A3 诊断密钥灌注 | run-37596 | 85.7 | 11 | 428 | 61% | 15.0M | 4.86 | ✅ `flag{BCM_MLKEM_s33d_r3us3…}` |
| 97 号公路·阿九 | run-63775 | 82.2 | 9 | 345 | 36% | 12.9M | 4.15 | ✅ `flag{R0ute97_Ch0rus_Encore_2026}` |
| NL-BCM 固件包 | run-363803 | 18.4 | 3 | 120 | 74% | 2.9M | 0.96 | ✅ `flag{767a9ca2-…}` |
| LastIgnition 主轮 | run-51063 | 170.1 | 26 | 764 | 42% | 28.3M | 9.10 | — |
| LastIgnition 续 | run-1314496 | 89.6 | 12 | 301 | 39% | 9.5M | 3.13 | — |
| LastIgnition 再续 | run-1995778 | 64.2 | 7 | 231 | 30% | 7.7M | 2.48 | — |
| SOME/IP 网关 1 | run-914360 | 59.1 | 8 | 270 | 58% | 6.3M | 2.09 | — |
| SOME/IP 网关 2 | run-1314315 | 75.1 | 10 | 325 | 43% | 9.3M | 3.02 | — |
| SOME/IP 网关 3 | run-1611990 | 62.4 | 10 | 316 | 31% | 7.3M | 2.37 | — |
| V2X 静默译码 | run-40288 | 170.9 | 24 | 555 | 48% | 17.0M | 5.74 | — |
| 功耗侧信道·猎隼 | run-35254 | 169.2 | 23 | 459 | 55% | 14.6M | 4.97 | — |
| CAN 言乱语 | run-144625 | 165.4 | 23 | 850 | 72% | 37.1M | 11.84 | — |
| 916 流量包 | run-98091 | 167.0 | 22 | 491 | 68% | 18.0M | 6.07 | — |
| 日志的秘密 | run-107924 | 166.2 | 23 | 513 | 50% | 17.5M | 5.85 | — |
| Autopilot | run-2703728 | 74.6 | 14 | 368 | 41% | 10.9M | 3.54 | — |
| **合计** | 15 run | 1 620 run-分钟 | **225** | **6 336** | — | **214.4M** | **70.1** | **3** |

合计：**225 代 / 6 336 次调用 / 214.4M token（入 207.9M、出 6.47M）**。
- 结局分布：`runtime_failure` 186（全部是 `planner_invalid_plan`）、`no_progress` 31、`operator_stop` 5、`solved` 3。
- 模型：**全部 `deepseek-flash`**（271 次 worker 启动，全部 bootstrap，无一次 pro）。
- 人工介入：8 个 run 收到 `hint` 命令事件共 92 次（最多 run-51063 24 次、run-1314496 16 次）；6 个 run 被 `stop`。
- 整个比赛 agent 只调用过 **1 次 `submit_flag`**（就是解出的那面旗）；平台提交按手册要求由人做。

---

## 2. 逐 run 复盘

### 2.1 解出的三题（为什么这三题能成）

**run-363803 · NL-BCM 固件包（18.4 分钟，3 代，最快的解）** 【已核】
- 打法：附件 FWPK 头逆向 → 线上 DoIP（ISO 13400）路由激活 → UDS `0x23 ReadMemoryByAddress`
  （ALFID=0x44）读出引导区 → 用 FWPK 头里的 `0x13572468` 走闪存里的解密函数还原 0x1258 字节镜像
  → 在 payload 偏移 0x1270 直接拿到明文《NL-BCM 车间刷新说明》→ flag。
- 关键：**这是一道"协议 + 固件"题，活靶在场**，每一步都有可验证的往返，模型不需要"猜"。
  工具构成：heredoc 脚本 50、python -c 28、文件/解包 18、xxd 3。

**run-63775 · 97 号公路·阿九（82 分钟，9 代）** 【已核】
- 打法：7z 解包 → 两个带 DWARF 符号的 PE（`car_music_player.exe` / `route97_rhythm.exe`）→
  wine 在沙箱里跑通（需 unshare 挂 /run/user）→ WAV chunk 结构（**大端 size** 这条被自己纠了两次：
  fact_003 认为 chunk 缺失、fact_006 改为存在、fact_007 再确认）→ flgx 置换/AES-CBC 变体 →
  最后用 **unicorn 模拟器**跑 main 拿寄存器初值，把"32 字节明文的 FNV-1a64"转成逐 note 求解 → flag。
- 这一题是**工具用得最像人**的一轮：objdump/readelf 55 次、gdb 28 次、r2 4 次、strings 19 次，
  python 只占 36%。
- 值得注意的自我纠错：两次推翻自己的 fact（这一点和 2026-10-31 那场"诱饵"错误的教训是一致的）。

**run-37596 · BCM-A3 诊断密钥灌注（85.7 分钟，11 代）** 【已核】
- 打法：OTA 包（BCMOTA01）→ diag.bin（BCMDIAG1）→ ML-KEM-768、16 槽、故障槽 3/9/14 →
  先证伪"封装侧 e=0"路线并记 dead_end → 发现**三槽共享同一 s/e（keygen 随机源卡死）** →
  恢复 ŝ、重加密校验 c'==ct → tag = HMAC-SHA256(K_fin, ack) 3/3 成立 →
  最后一步 `payload = AES-256-GCM(key=SHA256("BCM-DIAG-KDF-v1"‖K_fin9), nonce=payload[0:12], AAD=payload_aad)` → flag。
- 这题的价值：**它证明模型能做 10 层以上的假设管理**（9 条死路、16 条事实、每轮都在前一轮基础上推进）。

> 三题共同点：**都有"可执行的判别器"**——重加密校验、oracle、活靶往返、模拟器。
> 模型在这类"每步能自证"的任务上表现最好。

### 2.2 未解但做到很深的（4 道，判词：差一个"题眼"）

**run-144625 · CAN 言乱语（165 分钟，850 次调用，37.1M token，最高）** 【已核】
- 做了：BLF 613 个 zlib LOBJ → 1 671 948 帧；256 张 34×34 瓦片**精确像素互咬**拼回 16×16 文档图；
  零宽字符三处分块拼 zlib 得 3416 B 正文；GIF 运动场（全画面 dx=+3，中带反向）切出 8 个字形
  `4DWWXFPU`；UDS 8 组 seed/key；`0x18FF2100` 二层结构（2 的幂 burst）；chain.txt 16 层 BFS；
  QR v8 49×49 的 S 串；50 Hz 填充 ID 的 ±1/±3 ms 时间抖动。
- 卡点：所有信道都"解出了中间量"，但没有一个走到 flag；**它把大量时间用在"穷举排除"**（40357 种置换、
  20183 个口令、1.01M 组 AEAD）。最后一次还推翻自己"未补偿平均=均匀噪点"的结论。
- 判词：**执行满分，收敛失败**。它一直在扩大枚举面，而不是回到"题目想要的那条链"。

**run-98091 · 916 流量包（167 分钟，18M）** 【已核】
- 做了：整文件字节反转的 pcapng → 自定义 `DGPT/1` 协议 → P-256 私钥 = **137**（BSGS 在 2^32 内唯一命中）
  → ECDH 共享 x → `HKDF-SHA256(ikm=x, salt=nonce, info="DGPT/1")` → AES-256-GCM 解出**内层 pcapng**
  （含资产清单与 81 组密钥提示）。这一步在 **+25 分钟**就完成了。
- 卡点：之后 140 分钟全花在内层，没有跨过去。三处"数字碎片"（S 串、时序、内层）没有拼成一条。
- 判词：**入口全对，终点没找到**；典型的"链长了以后丢失主线"。
- **深挖已单独成文**：`WP-98091.md`（三层结构、可复现解密、两个卡点的 oracle 与死路清单）。
  写 WP 时复核出的两条硬结论：① 0e81 那条 gzip 流的**末尾 8 字节是真 footer**
  （CRC32 `0xd702f2d4` / ISIZE **1,149,987**）⇒ 拼接长度正确，误差只能是流内字节级移位；
  ② 之前用"输出全是 base64"当判据是**弱判据**（copy token 会复制合法字符），
  真 oracle 必须是 gzip footer 或 `crc32(明文)==manifest crc32`。

**run-35254 · 功耗侧信道·猎隼（169 分钟，14.6M）** 【已核】
- 做了：Falcon-512 公钥解析、trace 四区切分、A/B 模板码、候选集（324/317 唯一）、
  `g=f·h` 线性系统判别器；并**自我纠正**了一条错误的负结论（"viol=129/129 ⇒ 模型排除"因为稠密卷积会污染全部方程而无效）。
- 卡点：bank→f/g 的映射与 KDF 形式始终没对上（40 种 KDF × 18 种序列化 × 5 nonce × 4 aad 全 0）。
- 判词：数学味最重的一题，**模型能审自己的负结论**，但缺少"换个建模角度"的跳跃。

**run-40288 · V2X 静默译码（170.9 分钟，17M）** 【已核】
- 做了：HQC 轻量参数（n=1153）、三个泄漏 weight-16 稀疏向量、720 组 KDF×AEAD、
  10.6 万组 AEAD/流密码扫描、小消息穷举 2 万×6×6。
- 卡点：`payload` 75 B 与 `n12|ct48|t16=76` 不自洽（WP 里也记了这条）；`llr` 被证明是纯诱饵。
- 判词：和 35254 同类——**穷举做完，题眼没找到**。

### 2.3 卡在"协议门"上的三题（判词：不是能力问题，是缺一条正确路径）

**LastIgnition 系列（run-51063 → 1314496 → 1995778，三轮共 84M token，93 条死路）** 【已核】
- 静态逆向其实已经**完整**：唯一 OK 分支 `0x1400df6e1`、凭据内联比较 `0x1400df56d–0x1400df583`、
  `view_key=SHA256("LI7/view\0"+cred32)`、HMAC 校验、两级校验链、`sub_140009140` 的
  `32B cred + 32B mask + 10×u32 页表`。
- 卡点：`cred` 必须是 H1 的 SHA256 前像；128 万窗口 + 260 万候选全 0。
- 值得注意的是第二轮**自己找到了绕开沙箱 wine 的办法**（docker + winebox），把 oracle 做到 1.4–2.3 s/次。
- 判词：**逆向能力足够，缺的是"凭据从哪来"这条设计意图**。

**SOME/IP 网关系列（run-914360 → 1314315 → 1611990，三轮 22.9M）** 【已核】
- 已经钉死：service `0xbeef`、方法 `0x0001/0x0101/0x0201`、`isotp` 是 JSON 键、`can_id` 必须字面 `"0x7e0"`、
  `10 03` 与 `27 01` 可过、`27 02` 恒 `7f2735`（40+ 组键族全试）。
- 判词：**SecurityAccess 的 key 算法在附件（校准器 ELF）里**，但三轮都没把它逆成"能算 seed 的函数"。
  第三轮已经收窄到"只做 27"，仍然没破——这是**"知道要做什么，做不到"**，和 §2.2 的"不知道做什么"不同。
- **后来补到的两条（都改变结论）**：
  1. agent **确实挖到了隐藏分支**：`run-1314315/1611990/914360` 的工具输出里都有
     `argc==31337` 与两个明文密钥 `can-uds-security-key-qwb-2026!!!` / `flexray-static-auth-key-qwb-2026`
     （我校验过原文）。也就是说"key 在哪"这条已经解决，差的是把它接回 UDS 27 服务。
  2. **靶场从 10:22–10:33 起持续 `Connection refused` 直到 11:02**（我校验：1314315 24 次、1611990 24 次、
     914360 2 次，目标 `<target>:32945`；另有 SIP 30490 超时）。这条是**外部因素**，
     意味着这三轮里有一半时间根本没法验证 27 02。

**run-2703728 · Autopilot（74.6 分钟）** 【已核】
- 做了：SOME/IP + OTA 服务、V2X 订阅、**用 LCG nonce 链恢复 OTA CA 私钥**、
  自签 `flags=1` 工程包 **PUT 成功**。
- 卡点：拿不到 flag——漏洞打通了，但"flag 在哪"没找到。
- 判词：**这题可能只差"用工程包读出受保护数据"这一步**；属于最容易补的一类。

---

## 3. 时间轴：一天里到底发生了什么

| 时间 | 事件 |
|---|---|
| 08:00–08:25 | 补丁 0001/0002/0003 APPLIED、后端 :8011 / 面板 :3011 起来、冒烟 `run-3335` 解出 |
| 09:00–09:07 | 8 个 run 被派（几乎同时）；此时 12 并发的大头已经形成 |
| 09:14 | run-363803 起（第 9 个）→ **18 分钟后解出**（当天最快） |
| 09:47 / 10:00 / 10:11 / 10:33 | 人工二次派单：SOME/IP 2/3、LastIgnition 续/再续、Autopilot；题面里带【队长给的额外方向】 |
| 10:25–10:33 | run-63775 解出（82 分钟）；run-37596 解出（85.7 分钟） |
| 11:02–11:17 | SOME/IP 三轮、LastIgnition 续全部被 `stop`（人放弃） |
| 11:48–11:52 | 剩余长跑被停/自然结束；5 个 run 打了 165–171 分钟 |

判词：**人这一天的动作是合理的**（发现一题做不动就换角度、收窄范围、给脚本），
但**机器侧没有一次成功规划**，所以"换角度"只能是"再起一个 run 从头读附件"，
前面几十 M token 的上下文只能靠 blackboard 事实传递。

---

## 4. 事故分析：planner 没有凭证（当天第一杀手）

### 4.1 证据链（全部可复算）

1. **配置**：`state/muteki/_worker_config.json` 里
   ```json
   "llm_profiles": {"planner": {"provider": "deepseek", "model": "deepseek-flash",
                                "endpoint_id": "", "connection": "default"}}
   ```
   `endpoint_id` 为空。【已核】
2. **代码**：`swarm/coordinator_dispatch.py:786` 从 `planner.endpoint_id`（或 `credential_id`）取账号 id；
   为空 ⇒ `account_id=""` ⇒ `pi_decide.py:2005` 的 `runtime_env_for_engine(..., account_id="")`
   不注入任何账号密钥（key 在 `_secrets/accounts/pi-main/API_KEY`，只按账号注入）。
3. **usage 库**：`state/muteki/usage.sqlite3` 共 1 672 条记录，其中 **1 081 条 `actor_kind=coordinator`、
   `status=error`、`input/output tokens = null`、`quality="missing"`、`credential_id="system:pi"`**；
   coordinator 的成功记录 **0 条**。worker 记录 591 条全部 `observed`（有 token）。【已核】
4. **产物**：每个 run 的 `workspace/.muteki-agent-state/reason/draft.json` 都是
   `{"committed": false, "operations": []}` —— 扩展启动时写的初始态，从未被 commit 覆盖。【已核】
5. **机制验证（凭证如何到 Pi）**：Pi 的凭据不是走环境变量，而是
   `credential_accounts.py:2470-2515` 把账号 `API_KEY` 写进 `PI_CODING_AGENT_DIR/models.json` 的
   `providers.muteki.apiKey`，再给进程 `MUTEKI_PI_PROVIDER=muteki / MUTEKI_PI_MODEL=<model>`。
   我直接调 `runtime_env_for_engine`：
   - `account_id="pi-main"` → 生成 `models.json`（apiKey 35 字符、baseUrl=api.deepseek.com）、
     env 带 `MUTEKI_PI_PROVIDER/MODEL`、`PI_CODING_AGENT_DIR` 被创建；
   - `account_id=""` → **不创建 agent dir、无 provider/model** ⇒ Pi 没有可用 provider，静默退出。
   这解释了为什么 worker 能跑而 planner 不能：**worker 有账号，planner 的账号是空串**。【已核】
6. **复现**（我在 `plan-test/` 做的，真 API、真扩展、真 37 KB 图 YAML）：
   - 带 key：**15.4 秒、8 次工具调用、产出 `committed: true` 的合法计划**（读事实 → satisfy_goal → preview → commit）。
   - `env -u DEEPSEEK_API_KEY`：**rc=0，只输出 1 行 `session` 事件，无 usage、不产 draft** ——
     与比赛里的表现逐字一致（静默退出）。【已核】

### 4.2 后果

- 186 次 `run.finished: runtime_failure / planner_invalid_plan`；
- 225 次"代"里只有 3 次 `solved`、31 次 `no_progress`；
- **271 次 worker 启动全是 `bootstrap`**：即每个 run 的每一代都只做"侦察一轮"，
  `explore / race / review / verify` 从未发生 ⇒ 没有并行探索、没有交叉验证、没有专门的收束轮；
- 由于 planner 每次都是秒级失败，run 的"寿命"完全由那个 bootstrap worker 的时长决定（4–15 分钟），
  所以 15 个 run 在 3 小时里被反复"重启"了 225 次。

> **一句话**：我们花钱买了一个 swarm，实际跑的是一个"每次 7 分钟、每轮从头读附件、靠黑板攒记忆"的单 agent。

### 4.3 修复（配置层，5 分钟）

- 把 planner 槽位绑到账号：`llm_profiles.planner.endpoint_id = "account:pi-main"`
  （改完用 `runtime_env_for_engine` 复核：应生成 models.json + `MUTEKI_PI_PROVIDER`，见 §4.1 第 5 条；
  titler 同理）。或者让 muteki 在 `endpoint_id` 为空时回退到 seat 的 credential。
- **加一条开赛前自检**（本次没有，导致 3 小时全瞎）：
  跑一次 planner smoke：`committed=true` 且 usage 里 coordinator 记录 `status=observed` 且 tokens>0；
  否则**不开赛**（这比"补丁全 APPLIED"重要得多）。
- 顺手补可观测性：把 planner 的 stderr / 每次 attempt 的 draft 落盘到 `state/logs/planner/`。
  现在这三小时里，唯一能看出问题的是 usage 库里 1 081 条 0 token 记录——**这不是给人看的**。

---

## 5. 架构复盘：这一场到底跑的是什么

| 层 | 计划中 | 实际 |
|---|---|---|
| 引擎 | muteki 0.4.7 + Pi 0.86.1 | ✅ 跑了 |
| 补丁 | 0001（`-P`）、0002（候选门禁）、0003（`--no-mcp`） | ✅ 全 APPLIED；**但 0002 是哑弹**（见下） |
| 派单 | `tools/dispatch.py` | ✅ 人手动派了 15 个 run |
| 假设族台账 / 判死门禁 / 换族重派（ctfagent §6.5） | 本应是"策略层" | ❌ **没上桌**：`ctfagent.sqlite3` 里只有赛前一天留下的 1 题、4 回合、**0 族、0 尝试、0 判死** |
| 候选门禁（patch 0002） | 每个候选要有出处 | ❌ **未启用**：`MUTEKI_CTFAGENT_REPO/DB` 只有文档提过，`start.sh` 从未 export，全机无进程带该变量 |
| 规划（planner） | 多步 campaign + 并行 | ❌ **全程失败**（§4） |
| 并发 | 文档说 2 | ❌ 实测最多 12 个 run 同时有工具调用 |

> 所以"这次换了架构"的真实含义是：**从 DSH 的"一个会话苦干"换成 muteki 的"多 run 并行 + 黑板事实"**。
> 这一步是有效的（3 解 vs 1 解），但**策略层（族台账/门禁/规划）基本没有生效**，
> 这就是"3 解"和"11 道不同的题被派过"之间那道坎（15 个 run 里 4 个是重派）。

---

## 6. 模型能力评估：flash 到底卡在哪

### 6.1 证据（支持"能力够"）

| 事实 | 出处 |
|---|---|
| 完整逆出 Falcon-512 功耗侧信道的 trace 分区/模板码/候选集，并**自我推翻**错误的负结论 | run-35254 fact_005/fact_009 |
| 用 BSGS 在 2^32 内找到 P-256 私钥=137，推出 ECDH→HKDF→AES-GCM 并解出内层 pcapng | run-98091 fact_002/006 |
| 256 瓦片精确像素拼图 + 零宽字符三处拼接 + GIF 运动场字形 + QR v8 + 时间抖动信道 | run-144625 事实 2–29 |
| 用 unicorn 建 harness，改到能逐 note 求解（并纠正 WAV 大端/小端两次） | run-63775 fact_003→006→007→011 |
| 恢复 ML-KEM 共享秘密、验 HMAC、推出最后的 AES-GCM KDF | run-37596 fact_008→015 |
| 手工重放 planner：**15 秒产出合法计划**（同模型、同扩展、真图 YAML） | `plan-test/`（本文 §4.3） |

### 6.2 证据（支持"能力不够"或"时间不够"）

| 现象 | 数据 |
|---|---|
| 长跑全是"枚举收窄"，很少换建模角度 | run-144625：40357 置换、20183 口令、1.01M AEAD；run-40288：10.6 万组合 |
| 关键"题眼"没对上 | LastIgnition 的 cred 来源、SOME/IP 的 27 key、Autopilot 的 flag 位置、346/75B payload 的密钥来源 |
| 单代时长被压缩 | 平均 7.2 分钟/代（1 620 run-分钟 / 225 代），模型刚进入"深水区"就被 planner 杀掉 |
| 上下文极重 | 每 run 输入 6–36M token（平均每次工具调用约 30–45k 输入）——**代际重读**的代价 |

### 6.3 判词

> **"flash 到智商上限"目前是【判词】，不是【已核】。**
> 已核的是：它在**"有判别器、有明确下一步"**的任务上很强（3 解 + 4 道深水题）；
> 在**"需要一次结构跳跃"**的任务上，本次没有观察到成功案例——但本次它每次只被给了 4–15 分钟，
> 且没有并行/交叉验证。**在 planner 修好之前，这个对照实验不成立。**

---

## 7. 与两场历史对照

| 场次 | 时间 | 引擎/形态 | 题目 | 成绩 | 关键差异 |
|---|---|---|---|---|---|
| 极氪 2026 | 2026-09-19（3 h） | DSH 单会话 | 11 题 | **11/11 全解** | 那批题"有可执行判别器"的比例高（协议/CAN/图像/微码），模型能一路推；工具链使用率极低（1 787 次调用里 bash 85.9%、python 脚本 140 次、RE 工具几乎 0），**但不影响全解** |
| 强网杯主赛 | 2026-10-31（27 h） | DSH 单会话 | 41 题 | 12 解（agent 独立 1） | 人给 5 条片段才解出 1 道；agent 在长赛程里被"等/轮询"吃掉 49.6% 墙钟 |
| **车联网专项** | **2026-11-08（3 h）** | **muteki + Pi** | **11 道不同的题（15 run，4 个重派）** | **3 解 · 630 PT · 48 名 · 1 血** | 多 run 并行 + 黑板事实 + 人可介入，**架构方向对**；但规划全灭、策略层未上线 |

三个数放在一起看：
- **11 → 1 → 3** 的变化，更可能由"题型 × 时间 × 是否有活靶"解释，而不是"模型退化"；
- 极氪那场 11/11 恰恰说明：**只要题在模型的能力半径内，"只写 python 不调工具"根本不是问题**。
  所以"DS 只会写 python 脚本"这个观察是**真的**（本次 python 类调用占比 30–74%），
  但它**不是本次失败的因果**——本次三题里有两题正是靠 python 脚本（协议/数值）解决的。
- 真正新增的变量是：**muteki 的编排**。它带来了并行与记忆（好），也带来了 planner 单点故障（坏）。

---

## 7.5 四个问题的直接回答

### Q1 这次为什么能解 3 题，上次只能 1–2 题？

先把口径钉死（两处有出入，都列出）：
- 上次（强网杯主赛 10-31→11-01，27 h）：**12 题 / 1201.57 分 / 532 名**。
  报告旧口径写"agent 直接解 **2** 题"（`research/report/CTF-AGENT-REPORT.md:38`），但其中一题是
  **比赛方问卷**（填完白送 flag）——按你的口径**不计**。所以 agent 真正解的只有 **1 题**，
  且那题是"队友给 5 条片段"后解出的。**本文统一按 1 题对比**。
- 这次（3 h）：**3 题 / 630 PT / 48 名 / 1 血**，全部由 agent 在 run 内产出。
- 单位时间产出：上次 1 题 / 27 h = **0.037 题/小时**；这次 3 题 / 3 h = **1 题/小时**，
  **提升约 27 倍**；题数 3 倍。【已核，算术】

差异归因（按证据强度排序）：

| 归因 | 证据 | 强度 |
|---|---|---|
| **① 不停机**：多 run + 自动重开，把"零活动"从制度上消灭 | 这次 09:00–11:52 共 173 分钟，**零活动分钟 = 0**；上次 **10-31 16:00→11-01 08:00 共 16 小时零文件活动、零提交**（报告 §1.1 第 42 行） | 【已核】 |
| **② 上下文分段**：每代重开一个 worker，只读黑板事实 + 新 prompt，不背 200 万 token 的历史 | 225 代 / 271 次 worker 启动；每代 4–15 分钟；单 run 输入 3–36M token 但**每次调用只带当前窗口** | 【已核】 |
| **③ 并行**：最多 12 个 run 同时推进（虽然配置写的是 2） | 同分钟有 tool.start 的 run 数峰值 12；≥6 并发的分钟 145 个 | 【已核】 |
| **④ 人工介入更细**：hint 命令 8 个 run 共 92 次（51063 24 次、1314496 16 次、2703728/1314315/40288 各 12 次），还有 4 次二次派单带【队长给的额外方向】 | control.command 统计 | 【已核】 |
| **⑤ 题目差异/运气** | 这次 3 题里 2 题是"活靶/可执行判别器"（DoIP 活靶、ML-KEM 重加密校验），1 题有 DWARF 符号 | 【判词】 |

反向证据（不能全归功于架构）：
- **上次 agent 的失败不是"没时间"，是"假设错"**：上次复盘自己的分类是 A–E，
  A 类（假设/定性强错）5 题 + B 类（判据停在试过的档位）4 题 = **9000 分**的题"再给 30–60 分钟能过"
  （`~/self/ctf/qwb-2026/retrospective/01-conclusion.md:8-31`）。这类错误这次**照样发生**：
  LastIgnition 的 cred 来源、SOME/IP 的 27 key、98091 的内层，都是同一个病。
- 所以"3 vs 1–2"里，**架构贡献的是"更多次尝试 + 不空转"**，不是"更聪明"。

### Q2 dsv4-flash 到智商上限了吗？

**不能这么判。三条证据都不支持"上限"，支持"没跑够"。**

1. **它每一代都在产出新知识，直到最后一分钟。**
   按代统计"新事实/代"：run-144625 的 23 代里，**第 23 代（+164 分钟）还在推翻自己 100 分钟前的结论**
   （"drive.gif 存在可复原的静止底图……前人的未补偿平均=均匀噪点结论因此被推翻"）；
   run-51063 的 26 代、run-40288 的 24 代、run-98091 的 22 代同样**没有一代是 0 产出**
   （口径：按事实标题前 70 字符去重；这个口径会把"改了几个字的重复事实"算成新，属保守偏松）。
   ⇒ 它没有被"想不出来"卡住，是被"每代只有 7 分钟"卡住。【已核（口径见上）】
2. **能力上限可验证的那一项，它通过了**：同一模型 + 同一扩展 + 真实 37 KB 图 YAML，
   手工重放 planner **15.4 秒产出合法计划**（§4.3）。所以"不会按协议规划"不成立。【已核】
3. **本次失败集中在"最后一步"**：10 道未解里 4 道（144625/98091/35254/40288）已把中间量基本拿全，
   3 道（51063 系、SOME/IP 系、Autopilot）已经打通漏洞或逆完校验链——**差的是一次结构跳跃**，
   而这类跳跃在"每 7 分钟被打断"的条件下几乎不可能完成。【判词，依据见 §2.2–2.3】

反过来，支持"模型确实不够"的唯一硬数字是：**3 解 / 11 道被派题 = 27%**，
以及 98091 在拿到内层 pcapng 后又花了 140 分钟没跨过去。但这 140 分钟同样是 20 代碎片。
**结论：在 planner 修好、给一次不被打断的 30 分钟之前，"上限"不可判。**（这也正是下次 A/B 的设计。）

### Q3 和极氪 2026（11/11）比，退在哪一步？

| 维度 | 极氪 2026-09-19 | 本次 2026-11-08 |
|---|---|---|
| 形态 | DSH **单会话**连续跑，工具链在手 | muteki 多 run，每个 run 被切成 4–15 分钟的"代" |
| 用时 | 约 3 小时（08:19–11:23） | 3 小时（09:00–12:00） |
| 结果 | **11/11 全解** | 3/11（15 个 run） |
| 工具使用 | 1 787 次调用，bash 85.9%，RE 工具≈0 | 6 336 次调用，真工具 1 000+ 次（objdump/gdb/r2/strings/capstone/angr/unicorn 都用上了） |
| 编排 | 无 planner，无族台账，人就看着一个会话 | planner 设计存在但**全程失效**（186 次 run 死因） |

⇒ **退的不是模型，不是工具，是"连续性"。**
极氪那场证明：**同一个模型、连续 3 小时、没有编排，能解 11 题**；
本次有编排，但编排把 3 小时切成了 225 段，每段开头都要重新读附件、读事实、重建上下文。
**退的那一步是 §4 的 planner 单点故障，它把"连续 agent"变成了"碎片 agent"。**

补充一条：极氪那场的题"没有一道是标准固件解包题"（其 README 原话），本次则大量固件/协议题；
题型难度确有差异，但它解释不了 11→3 这么大的落差。【判词】

### Q4 换 GLM 对症吗？ctfagent/派单/工具面改什么？

**换 GLM 是"半个对症"。**
- 对症的部分：本次剩下的失败里，"结构洞察"类（98091 内层、144625 收束、35254 映射）确实可能靠更强模型跨过去；
- 不对症的部分：**当天 186 次 run 死亡、184M token 打在"无规划单人短跑"上，与模型无关**。
  不修 planner，换 GLM 只会把"碎片短跑"换成"更贵的碎片短跑"。【判词，依据 §4】

落地前先确认三件工程事实（都已核）：
1. Pi **原生支持 GLM**：`ZAI_API_KEY → provider=zai`、`ZAI_CODING_CN_API_KEY → zai-coding-cn`
   （`~/.ctfagent/.s1-tools/lib/node_modules/@earendil-works/pi-coding-agent/docs/providers.md:94-95`）；
2. muteki 的价表只有 deepseek/codex/gpt-5，**GLM 会记成 unpriced** ⇒ 用
   `PUT /api/usage/pricing/override`（`apps/web/usage_api.py:94-100`）补价，否则成本账又是黑的；
3. 换模型必须同时改 **planner 槽位的 endpoint_id**（否则就是本次的事故重演）+ worker seat 的 model。

**A/B 设计（下次赛前 2 小时就能做完）**：挑 2 道本次"做到最后一步"的题
（98091 内层、Autopilot），同一 prompt/工具/时间上限（30 分钟、1 run），
flash vs glm 各跑一遍，看"是否跨过那道坎"和"每解一题 token"。**没有这个对照，换模型只是换感觉。**

**`ctfagent` / 派单 / 工具面要改的（按优先级，全部是配置或 prompt 层）**：
1. **planner smoke 进 preflight**（`ctfagent preflight` 加一项）：跑一次 planner，断言 commit + usage>0；
2. ✅ **候选门禁真启用**：`start.sh` export `MUTEKI_CTFAGENT_REPO/DB/ENFORCE=auto`，并留一条"假候选被拒"的自测；
3. **派单带上一轮事实**：现在 1314315/1611990 是靠人把脚本路径写进题面；应该由 `dispatch.py`
   自动把上一 run 的 fact 摘要（≤2 KB）附在题面后——这是"跨 run 假设备份"的最小实现；
4. **族/死路跨 run 共享**：run-51063 的 93 条 dead_end 在 1314496/1995778 里没有被继承，导致静态逆向重做一遍；
   把 `fact` 里 `mark_deadend` 的内容在派单时一并注入，就能省掉重复；
5. **收敛轮**：每 30 分钟强制一次"回到题面，题目要的产物是什么"——本次 4 道深水题的共同点就是
   "中间量都有、没人收束"。

### 7.6 与另一个会话（辅助比赛侧）复盘的交叉核对

对门文档：`~/.ctfagent/docs/RETRO-2026-11-08.md`（455 行，同一场、另一条数据线）。逐条对过：

**一致的（互相独立地得到了同一个结论）**
- planner 从头到尾没工作过，**是本场第一杀手**；
- token **214.4M**、3 解、5 个长跑空转、事实大量重复、成本量级（$60 上下）；
- 三道解出题的共同形态：**离线 + 判据自证 + 单包/单文件**。

**口径不同、不是矛盾**（两份文档都写了数字，读的时候别混）

| 量 | 本文 | 对门 | 差异来源 |
|---|---|---|---|
| "代" | **225** | **292** | 本文 = 15 个正式 run 的 `execution_generation` 去重；对门 = `run.started` 事件数（含重开与 29 个 run） |
| planner 失败次数 | **1 081**（usage 表行数） | **641**（`reason_done` 事件） | 统计口径不同（逐次计费行 vs 完成事件）；我在事件流里找不到 `reason_done` 类型，无法逐一对应 |
| 解出 | **3**（run 级） | **13**（"代级 solved"） | 统计粒度不同 |
| 成本 | **$70.15**（入 0.30 + 出 1.20 拆分） | **≈$64**（仅按入 0.30） | 对门没计输出价 |

**对门发现、我复算后确认的**
- `run.resolve` 命令 **223 次**（`_platform/platform.db` 的 `command_ledger_index`，
  我直接查表得到 `('run.resolve', 223)`）⇒ **reopen 重置续做预算**，这是 170 分钟长跑的直接原因；
- 靶场 `<target>:32945` **从 10:22/10:33 起 `Connection refused` 到 11:02**；
- agent 挖到 `argc==31337` 隐藏分支与两个明文密钥（原文已核）。

**对门发现、我未能复算的**
- "641 次 `reason_done`、`raw_response_chars=0`"：我扫了 `*.jsonl` 与 `.full`，**没有 `reason_done` 事件类型**，
  无法复核它这组数字；但结论方向（planner 全灭）与我的 usage 证据一致，不影响判断。

**两边都没解释的**
- `run.create` 75 次 vs 正式 run 15 个：多出来的 60 次是彩排/冒烟/重试，说明**"建 run"这个动作本身没被约束**，
  这也解释了为什么 12 路并发没有被 `max_workers=1` 拦住。

---

### 7.7 方案 A 已落地（2026-11-08 下午，已实测）

改动（全部有备份 `.bak-20261108-131349`）：

| # | 文件 | 改动 | 验证 |
|---|---|---|---|
| 1 | `state/muteki/_worker_config.json` | `llm_profiles.planner/titler.endpoint_id = "account:pi-main"` | 回读正确 |
| 2 | `start.sh` | 加 `MUTEKI_CTFAGENT_REPO/DB/ENFORCE`（候选门真正启用） | 回读三个键都在 |
| 3 | `ctfagent/preflight.py` + `cli.py` | 新增 `_check_planner` 与 `--planner-smoke`（blocking） | `preflight` 输出 `[GO] planner.smoke` |
| 4 | `tools/planner_smoke.py` + `tools/planner_smoke_fixture/` | 录制真 planner 输入（run-37596 的 graph + YAML）做回归冒烟 | 见下 |

实测（两条，都是真付费调用）：

```
# 直接跑冒烟
$ ~/.ctfagent/.s1-venv/bin/python ~/.ctfagent/tools/planner_smoke.py --json
{"ok": true, "account": "pi-main", "provider": ["muteki"], "api_key_len": 35,
 "detail": "planner 提交成功（28.6s）：operations=['satisfy_goal', 'commit']"}

# 走 preflight（现在 planner 是 blocking 项）
$ python3 -m ctfagent.cli preflight --planner-smoke --db …
  [GO  ] planner.smoke        {"ok": true, … "planner 提交成功（13.2s）：operations=['satisfy_goal','commit']"}
  == GO · ok=12 warn=2 fail=0 ==
```

⇒ 比赛里失败的正是这条链；现在它有**回归测试**，而且**开赛前不通过就不许开赛**。

### 7.8 P0-3 已落地：run 级续做上限（patch 0004）

对门复盘的 P0-3 是"reopen 重置预算 ⇒ 单 run 32 代"。我按同一目标做了**更保守的版本**：

- **不取消**每代 900s 的墙钟（那是 3 道解出题能跨 9–11 代完成的原因）；
- 改成 **run 级上限**：`MUTEKI_RUN_MAX_GENERATIONS`（默认 **12**）、
  `MUTEKI_RUN_MAX_TOKENS`（默认 **25M**），超限时 `resolve` 直接拒绝并回执 `run.budget_exhausted`，
  不再"点一下继续就续命"。

为什么是这两个数：三题解出分别用 **3 / 9 / 11 代**、**2.9M / 12.9M / 15.0M token**；
空转长跑用 **22–26 代 / 17–37M**。12 代 / 25M 恰好"保住全部已解出形态、砍掉空转后半程"。

改动：

| 文件 | 内容 |
|---|---|
| `apps/web/run_lifecycle.py` | 新增 `RunBudgetExhausted` + `continuation_cap_reason(run)`，在 `_resolve_launching` 入口拦截 |
| `apps/web/run_gateway.py` | 把拒绝变成可见回执：`code=run.budget_exhausted` + 原因 |
| `start.sh` | 显式写 `MUTEKI_RUN_MAX_GENERATIONS=12` / `MUTEKI_RUN_MAX_TOKENS=25000000`（可环境覆盖） |
| `tests/test_continuation_caps.py` | 5 条回归（已解形态放行 / 代数上限 / token 上限 / 指标读失败不误拦 / 0=关闭） |

验证：`py_compile` OK；内联断言 `default=''`、`generations=12 已达上限 12`、`tokens=25000000 已达上限 25000000`；
`patches/apply.sh --status` 显示 **4 个补丁全 APPLIED**（0004 已入台账）。
注：引擎 venv 里没有 pytest，测试文件已随补丁提交，下次在 dev 环境跑。

### 7.9 P0-5 已落地：把 muteki 内置的 triage playbook 打开（patch 0005）

跟前面几条不同：这一条不是"缺能力"，是**自带的技能被一行 flag 关掉了**。

- muteki 自带 `skills/muteki-ctf-local-playbook/SKILL.md`（1.8 KB），内容就是我们想要的 triage 手册：
  > Prefer host tools already on PATH (tshark, tcpdump, binwalk, strings, xxd, file, python3)
  > pcap：`file` + `capinfos`/`tshark -q -z io,phs` → 会话 → `follow,tcp,raw,N` → 重组落盘 → carve
  > 最后一行：**Actually run tools; do not only plan.**
- `worker_skills.py:30-33` 会把它（加上 `muteki-waf-bypass`、`muteki-blackboard`）投影到每个 Run 的
  `.pi/skills` / `.agents/skills`——我在 run-98091 的工作区里核到三个符号链接，**确实 stage 了**。
- 但 `PiDriver._CONTEXT_FLAGS` 写死 **`--no-skills`** ⇒ 技能目录从未被加载；
  15 个 run 的事件流里 `muteki-ctf-local-playbook` **命中 0 次**（模型既没看到也没打开）。
  对照实验：`--no-skills` 时 system sections 只有 `[preamble, cwd]`；换成 `--approve` 后多出 **`skills`** 段。

修复（patch 0005，37 行）：

| 改动 | 说明 |
|---|---|
| `pi.py` 去掉写死的 `--no-skills` | 改由 `MUTEKI_PI_SKILLS` 控制，默认 **1=启用**；设 0 恢复旧行为 |
| 保留 `--approve` | 该 flag 本来就在 `_permission_flags()` 里（非交互 launch），只差去掉 `--no-skills` |

端到端验证（真 worker argv + 真模型调用）：

```
[argv] pi -p --mode json --approve --no-context-files --system-prompt … --provider muteki --model deepseek-flash …
[has --no-skills] False | [has --approve] True
[system sections] ['preamble', 'skills', 'cwd']
[skills 里含 playbook] True
[PASS] worker 现在能看到 muteki 自带的 CTF playbook
```

⇒ 下一场 worker 的上下文里会多一行 playbook 描述（懒加载，约 100 token，模型要用再 `read` 全文）。
**这比我们自己写一份派单模板更便宜、也不会制造第二份真相**；剩下要补的只是两件小事：
① 派单题面加一句指针（`先 read .pi/skills/muteki-ctf-local-playbook/SKILL.md，按其 triage 顺序执行`）；
② 把 triage 做成"事实层"门禁（第一条 fact 必须带 `file`/`binwalk`/`tshark` 的原始输出摘要），
   而不是去检查命令（可造假、啰嗦）。

### 7.10 P0-6 已落地：triage 指针 + 事实级门禁（patch 0006）

补 §7.9 的最后一环。先说一个查出来的事实：**15 个 run 里只有 4 个的 worker prompt 带 triage 文本**。

```
含 '标准 triage' 的 run: run-1314315, run-1314496, run-1611990, run-1995778   ← 全是人工重派的那 4 个
不含:      其余 11 个（含 98091 / 144625 / 40288 / 35254 / 51063 …）
```

原因：那段文字来自 `tools/dispatch.py` 的 `DISCIPLINE` 常量，**只有走 dispatch.py 的 run 才带上**；
首批 11 个 run 是另一条路径建的。这也解释了"binwalk 全场 6 次、unblob 0 次"——**不是模型不看，
是大多数 run 的 prompt 里根本没有这条要求**。

修复（patch 0006，85 行，2 个文件）：

| 位置 | 改动 |
|---|---|
| `cli_prompts.py` | `_EXEC_PROMPT` / `_EXPLORE_PROMPT` / `_CAMPAIGN_PROMPT` 各加一行指针：动手前先读工作区的 `muteki-ctf-local-playbook/SKILL.md`，按其 triage 顺序做第一轮 |
| `cli_board_context.py` | 新增 `_triage_gate_block()`，在 `_compile_worker_prompt`（所有 worker prompt 的唯一出口）顶部注入 **【TRIAGE 门禁】** |

门禁触发条件（不满足就不出现）：
- `mode == ctf` 且题目**有附件**；
- 图里**没有任何** triage 工具证据（`binwalk|unblob|unsquashfs|tshark|capinfos|tcpdump|7z l|x|readelf|objdump|strings|xxd|hexdump`）；
- 证据出现后**自动消失**（不会一直唠叨）；`MUTEKI_TRIAGE_GATE=0` 可关闭。

验证（8 条单测 + 组装后的真 prompt）：

```
PASS 附件 + 0 事实 → 门禁触发
PASS 有 binwalk / xxd 事实 → 不触发
PASS 无附件 / pentest → 不触发
PASS EXEC / EXPLORE / CAMPAIGN 三处指针都在
== 组装后的 worker prompt ==
无 triage 事实：以「【TRIAGE 门禁】…」开头，含 playbook 指针，1 083 字符
有 triage 事实：无门禁，仍含指针，901 字符
```

成本：指针约 60 token 常驻；门禁只在"还没有 triage 事实"时多 182 字符（约 90 token），占一次 35k 输入的 0.3%。
**这是提示级门禁，不是硬拦**——硬拦需要拦 `open_step`，会误伤无附件/纯协议题，暂时不做。

## 8. 下次怎么办（P0 修完再谈换模型）

### P0 —— 开赛前必须绿的三件事（每件 ≤30 分钟）

> **1、2 已完成并实测（§7.7）；3 落成补丁 0004（§7.8）；技能开关补丁 0005（§7.9）；triage 指针+门禁补丁 0006（§7.10）。**

1. ✅ **planner 凭证绑定 + smoke**：`llm_profiles.planner.endpoint_id="account:pi-main"`；
   自检脚本断言"planner 一次成功 + usage 里 coordinator 有 token"。【§4.3】
2. ✅ **候选门禁真启用**：`start.sh` export `MUTEKI_CTFAGENT_REPO/DB/ENFORCE=auto`，
   并验证一次"假候选被拒"的用例（否则 0002 永远是哑弹）。【§5】
3. **并发与预算硬闸**：`max_workers` 与实际并发对不上（1 vs 12）。赛前按"并发 × 3 h × 单价"
   算一次预算，写进 preflight（214M token ≈ $70 这个量级要在开赛前就知道）。

### P1 —— 让"3 解"变成"5–6 解"（按性价比）

4. **给每题一个"收敛轮"**：每 30 分钟强制一次"回到题面：题目要的产物是什么"，
   当前 run 的最后一公里多数是"中间量都有了，没人把它们拼起来"（98091 内层、144625 全部信道）。
5. **把死路变成族**：本次 93 条 dead_end（run-51063）在 run 内是有效的（它确实没重复试），
   但**跨 run 不共享**（1314496/1995778 又从头走一遍静态逆向）。ctfagent 的族台账正是干这个的——
   要么把它接进 dispatch，要么在派单时把上一轮事实做成 prompt 头部（1314315 已经这么做了，效果有限）。
6. **Autopilot 这类"已打通但没 flag"的题**：单独一轮"找 flag 位置"（读工程包/分区/受保护数据），
   不要重新解漏洞。

### P2 —— 换模型（GLM）怎么换才有信息量

7. **先 A/B 再换**：挑 2 道本次"做到最后一步"的题（98091 内层、63775 的姊妹题风格），
   同一 prompt、同一工具、每模型 1 个 run、30 分钟上限，比较"是否跨过那道坎"。
   没有这个对照，换 GLM 只是换一个"感觉更好"。
8. **GLM 的期望**：如果差距在"结构洞察"（§6.2），换一个更强的模型可能真的有用；
   如果差距在"编排/上下文"（§4/§5），换模型 0 收益。**本次证据偏后者，所以先修 P0。**
9. 成本：按本次 214M token/$70 的规模，flash 完全够用；换 pro/GLM 前先算"每解一题要多少 token"，
   本次是 **71M token/解**（214/3），这个数字本身说明"不是钱的问题，是路径的问题"。

### P3 —— 可观测性（这次最痛的教训）

10. **planner / worker 的 stderr 与每次 attempt 的 draft 必须落盘**（现在：0 字节日志 + usage 里 1081 条 0 token）。
11. **每 10 分钟一张状态卡**：run 数 / 代 / 最近一次 planner 成败 / token / 是否有新事实。
    这次唯一能回答"为什么都没解"的信号，是事后我从 usage 库里挖出来的。

---

## 9. 待核 / 未验证

- 【待核】`run.finished` 的 `planner_invalid_plan` 具体是"扩展拒绝 commit"还是"进程没起来"：
  usage 的 0 token 强烈指向后者；但我没有 planner 的 stderr（没落盘），
  所以**根因"无凭证"是强推断（配置 + 复现 + 0 token 三重一致），不是直接观测**。
- 【待核】本次赛事总题量：我方只派过 **11 道不同的题**（15 个 run，其中 4 个是同一题重派）；平台题单未存档。
- 【未验证】"12 并发"是"同一分钟有 tool.start 的 run 数"，不是精确的 worker 进程数；
  但 worker.lifecycle 的 271 次 spawned 与 225 代是两个独立口径，量级一致（启动比代多：部分代起了 2 个 bootstrap worker）。
- 【未验证】极氪那场 11/11 的题面与本次难度不可比；我只用了"有无判别器"这一个维度做对照。

---

## 10. 复算命令

```bash
# 1) 总账（15 个 run 的 token/工具/代/结局）
cd ~/dsh-workspace/dsh-plugin-ctf/research/retro-qwb-iov && python3 analyze_runs.py
cat digests/ALL.md

# 2) 失败码分布
python3 - <<'EOF'
import json,collections
rows=json.load(open('digests/runs_meta.json'))
print(collections.Counter(k for r in rows for k,v in r['codes'].items() for _ in range(v)))
EOF

# 3) planner 的 0 token 记录（关键证据）
cp ~/.ctfagent/state/muteki/usage.sqlite3 /tmp/u.db
python3 - <<'EOF'
import sqlite3,json,collections
c=sqlite3.connect('/tmp/u.db')
rows=[json.loads(r[0]) for r in c.execute("select data from usage")]
print(collections.Counter((d['actor_kind'],d['status']) for d in rows))
print([d for d in rows if d['actor_kind']=='coordinator' and (d.get('input_tokens') or 0)>0][:1] or "coordinator 成功记录：0")
EOF

# 4) planner 配置
python3 -c "import json;d=json.load(open('~/.ctfagent/state/muteki/_worker_config.json'));print(d['llm_profiles'])"

# 5) 复现：无 key 的 planner 静默退出 / 有 key 的 15 秒 commit
cd plan-test && cat README.md    # 两条命令都写在这（含真实 37KB 图 YAML）
```

---

## 附：这一场最值钱的一条经验

> **"引擎跑起来"和"引擎的每一层都有凭证/配置"是两件事。**
> 我们花了三天把 muteki 装好、打补丁、跑通端到端、修好沙箱工具链，
> 却漏了一个空字符串（`planner.endpoint_id`），让 186 次 run 死亡、184M token 打在"没有规划的单人短跑"上。
> 下一次，开赛前的四条自检必须是：**补丁 APPLIED / 后端 readiness / planner smoke 成功 / 并发与预算对账**。
