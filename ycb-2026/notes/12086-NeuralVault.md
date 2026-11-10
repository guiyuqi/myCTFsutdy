# 12086 · NeuralVault（AI / HARD / 500 分）

- 平台：2026 羊城杯 · DASCTF `ycb-bk.dasctf.com`（matchId=1750, stageId=3241）
- 状态：进行中
- SKILLS: ctf-ai-ml（+ 视形态补 competition-agent-cloud / llm-security）
- SKILLS_USED: 待填

## 题目原文

> 某联邦学习平台发现训练过程存在异常。作为安全审计员，你需要分析各参与方提交的梯度更新，
> 定位异常参与方，还原攻击证据，并提交完整的审计报告以获取系统中隐藏的敏感信息。

flag 格式：**题目描述未给**（不像有 `flag{}` 示例），待容器/服务返回后确认。

## 已确立事实（时间序）

| # | 事实 | 证据 |
|---|---|---|
| 1 | `ycb.py download 12086` 失败：返回 `{"code":"40403","message":"无此项：/slab-match/api/v1/exercise/ctf-download"}`（平台没有该下载端点） | `firmware/12086_NeuralVault/attachment.bin`（94 B 错误 JSON） |
| 2 | 改用 detail.json 的 `attachment.url` 直连成功：759 B zip | `firmware/12086_NeuralVault/NeuralVault.zip` |
| 3 | zip 只有 1 个成员 `tempdir/AI附件/problem.json`（1016 B），无 comment / 无 extra field / 无尾部附加数据 | `zipinfo -v`、`xxd` tail |
| 4 | problem.json = 出题人**构建期元数据**（`id:null`、`stage:"pending-review"`、`verdicts.local_review:null`），无任何梯度/权重/数据 | `firmware/12086_NeuralVault/tempdir/AI附件/problem.json` |
| 5 | 隐写排除：无非 ASCII 异常字符（只有正常中文全角标点）、无 tab/CRLF/行尾空格 | 本笔记 §分析脚本输出 |
| 6 | **该题是动态题**：`endpointType=monopoly` + `isNeedInit=true`。对照组：MISC 静态题 12079/12080/12081/12083 均为 `endpointType=none, isNeedInit=false`；PWN/WEB 12062/12067/12070/12078 也为 monopoly+True | `work/details/*.json` |
| 7 | 当前无靶机：`ycb.py env status 12086` → `data: false` | `evidence/12086-env-status.json` |

problem.json 关键字段：`vulns = ["模型逆向工程","梯度反演攻击","数据投毒审计","对抗样本构造"]`，`scene = "联邦学习安全审计平台"`。

## 结论/推断

- 附件只是"题面皮"，**真正的数据应在靶机里**（描述明确要求"提交审计报告以获取系统中隐藏的敏感信息"）。
- 需要 `ycb.py env start 12086` 拿地址 → 侦察服务（GET / + 前端 JS/接口）→ 按 `vulns` 四条线取证据 → 产出审计报告拿到 flag。

## 环境

- 本机 **无 torch / sklearn / safetensors**（Python 3.14.4），有 numpy 2.5.3 / scipy 1.16.3 / cv2 5.0.0 / PIL 12.3。
  → 若需梯度反演：先用 numpy 手写 MLP + 反向传播（或申请装 torch）。

## 离线已备好的工具（拿到靶机即可开跑）

| 文件 | 作用 | 状态 |
|---|---|---|
| `work/12086_neuralvault/probe.py` | 纯 urllib 侦察：抓 `/` + 外链 JS + 列出可疑 API 路径（api/submit/report/grad/audit/flag…），响应全落 `evidence/12086-probe-*` | 自检过 |
| `work/12086_neuralvault/fltools.py` | numpy 版 FL 取证：① 异常参与方定位（L2/余弦/中位距离）② batch=1 线性首层代数反演 `x = Wᵀδ/‖δ‖²`（转置约定自适应）③ 手写 MLP 前向/反传 + DLG 迭代反演 | **自检 4/4 PASS**（反演误差 5e-13；反传 vs 数值梯度 PASS；投毒方 top1 命中） |

## 待办

1. [ ] 起靶机（**已向父代理要槽位，等授权**）
2. [ ] `web-probe` 抓 DOM/网络请求/JS
3. [ ] 按接口取证
4. [ ] 提交 flag + 写 `scripts/12086-solve.py` + `wp.md` 条目

---

## 靶机实测（10:12–10:26，`<target>:24281`，父代理起/停，10:26 为腾槽被销毁）

| # | 事实 | 证据 |
|---|---|---|
| 8 | 协议 = **HTTP**（不是裸 TCP framing）：空连接静默，`GET / HTTP/1.0` → 375 B `HTTP/1.0 404`，`Server: gunicorn`，body 是 Werkzeug 默认 404 页 ⇒ **Flask + gunicorn** | `evidence/12086-proto-log.txt` |
| 9 | ⚠️ **不能并发**：我用 12 并发扫 54 条路由，gunicorn 被压到全部超时（`/` 10 s 无响应），冷却 ~40 s 才恢复 | 同上（时间线） |
| 10 | `GET /health` → 200 `{"status":"ok"}` | — |
| 11 | **`GET /api/info` → 200，1140 B 契约**（免费 hint，见下） | `evidence/12086-api-info.json` |
| 12 | **`GET /api/debug` → 200，泄漏**：`suspected_clients=[2,6]`、`compromised_rounds=[0,1]`、`model_params{activation:sigmoid, hidden_dim:64, output_classes:32}` | `evidence/12086-debug-leak.json` |
| 13 | `POST /api/submit`（GET 返回 405，`Allow: OPTIONS, POST`） | `evidence/12086-discover.json` |
| 14 | 裸路径与 `/api/v1/*`、以及 `/api/{gradients,rounds,clients,data,dataset,weights,updates,query,detector,…}` **全部 404** ⇒ 梯度数据端点仍在未命名的路由上（下一轮要扩候选表） | 同上（178 条枚举） |

契约（`/api/info`）要点：10 clients × 5 rounds、input_dim=32、output_classes=16（debug 说 32，**二者矛盾，需以实际梯度形状为准**）、MLP、noise_std=0.02；
`query_limit=800`、`adv_query_limit=400`、`adv_constraint{eps=0.15, max_changed_dims=12}`；
提交三件套 = `poisoned_clients` / `audit_key`（16 位 hex，拆在两个恶意方的梯度矩阵里）/ `bypass_vector`（骗过 MLP 检测器）；`token=c4b8ee60-…`（会话令牌，落地 header/参数待定）。

## 离线工具链（全部自检通过，等数据即可跑）

| 文件 | 作用 | 自检 |
|---|---|---|
| `work/12086_neuralvault/fltools.py` | 梯度反演：batch=1 时 **首层偏置梯度 = 上游 δ**，故 `x = grad_Wᵀδ/‖δ‖²` **代数精确**还原任意网络的输入；iDLG 定标签；手写 MLP 反传 + DLG | 4 组全 PASS（反演误差 1e-11；反传≈数值梯度 1e-5；两种投毒 top1 命中） |
| `work/12086_neuralvault/audit.py` | ① 恶意方定位（cos 对齐 + 末层 top-8 行范数占比 + 首奇异值占比，因为 **cos 对符号翻转/缩放不变**，单靠它必漏）+ ② 末层矩阵 8 种解码假设 → 16 位 hex 候选（H1/H6 argmax→nibble 等） | PASS：可疑度 +255 vs +3；植入 key 在 8 个候选中命中 |
| `work/12086_neuralvault/adv.py` | 检测器绕过：一次性梯度估计选 12 维到 ±ε，再坐标爬山（{+ε,−ε,0}），**34 次查询**达标 | PASS（L∞=0.15、12 维、两检测器） |
| `work/12086_neuralvault/api.py` | 靶机客户端：info/debug/enum/submit，405 判别法枚举（178+ 条），token 四种携带方式 | 待靶机复跑 |
| `work/12086_neuralvault/fingerprint.py` | 协议指纹（14 种 framing 各一次） | 已证 HTTP |
| `work/12086_neuralvault/routes.py`, `seq_routes.py`, `discover.py` | 路由枚举（**并发版已废弃，重跑一律用 discover.py / api.py enum**） | — |

### 关键判据（自己踩出来的，别再踩）
1. **cos 相似度对缩放/符号翻转不变** → 定位恶意方必须叠加"末层行范数峰值 + 谱集中度"。
2. **自检的基线必须"约束下确实可翻转"**：从 p=0.197 的自信点出发，ε=0.15/12 维连随机搜索上限都只有 0.26 —— 那不是攻击器不行，是约束不可达。
3. **不能并发打靶机**（gunicorn 单点，会假死 ~40 s，看起来像"容器挂了"）。

## 当前状态（10:50）

- 靶机于 10:26 为给 12063 腾槽被父代理销毁；已挖到的情报（`/api/info` 契约、`/api/debug` 泄漏、`/api/submit` 存在）**不依赖靶机在线**，已全部落盘。
- 父代理已把本题重新排入队列并上调优先级，**等下一个空槽即发地址**。
- 开槽后的动作已脚本化（见下表），无需再判断，直接按序执行：

| 顺序 | 命令 | 目的 |
|---|---|---|
| 1 | `python3 work/12086_neuralvault/firstcontact.py <base>` | 基线 + token 携带矩阵 + `POST /api/submit {}` 校验报错 + 畸形请求找 traceback + `/api/debug` 带参 + 定点探数据路由 |
| 2 | `python3 work/12086_neuralvault/api.py enum --base <base>` | 1072 条存在性枚举（405 判别法，GET 单发，0.25 s） |
| 3 | `python3 work/12086_neuralvault/audit.py <grads> ` | 恶意方定位 + 8 种 hex 解码 → audit_key 候选 |
| 4 | `python3 work/12086_neuralvault/adv.py` + 靶机检测器 | 造 bypass_vector（34 次查询内） |
| 5 | `api.py submit '<json>'` | 用 `/api/submit` 当本地 oracle 试 key 变体（**不消耗平台 50 次额度**），拿到 flag 再 `ycb.py submit 12086 '<flag>'` |

## 靶机 #2（`<target>:30857`，10:56 开 → 11:06 关闭）

| # | 事实 | 证据 |
|---|---|---|
| 15 | **`POST /api/detector/query` 存在**（GET→405，`Allow:[POST,OPTIONS]`）⇒ 对抗检测器接口（`adv_query_limit=400` 对它计数） | `evidence/12086-session2-findings.txt` |
| 16 | **`/api/` 前缀共 105 条候选，只有 4 个路由**：`GET /api/info`、`GET /api/debug`、`POST /api/submit`、`POST /api/detector/query`。**没有独立的 gradients 路由** ⇒ 梯度数据很可能由 `detector/query`（`query_limit=800`）承载 | 同上 |
| 17 | 两个 POST 端点都要求 audit token：`401 {"error":"Invalid or missing audit token"}` | 同上 |
| 18 | `/api/info` 的 token 在 12 种无状态携带方式下全 401 —— **但见下条自我纠错** | 同上 |
| 19 | ★ **自我纠错**：我的 header 扫描用的是 `evidence/12086-api-info.json` 里**实例 #1 的旧 token**。实例 #2 的 `/api/info` 也是 1140 B（长度相同，看不出 token 变了）⇒ 那批 401 很可能只是"旧 token 打新实例"。修正：token 必须从当前实例现场解析 | `sess.py`（已改成现场解析+对比打印） |
| 20 | `/api/debug?round=/client=/dump=/full=/verbose=/all=` 返回同一份 194 B ⇒ 参数被忽略 | 同上 |

### 下一轮开局三连（已脚本化）
1. `python3 sess.py <base>` —— cookie jar + **现场 token** + 12 种携带方式打 `detector/query` / `submit`
2. `python3 enum_stage.py <base> 0..4` —— 其余前缀分阶段枚举，**每段 ≤200 条、0.3 s、连续 5 次失败即停**
3. 摸到数据后：`audit.py`（key 候选 8 种）→ `adv.py`（34 次查询造 bypass_vector）→ `POST /api/submit` 本地 oracle 验 → 再上平台

## 靶机 #3（`<target>:29783`，11:12 开 → 约 11:25 关闭）—— 鉴权与 schema 全部破解

| # | 事实 | 证据 |
|---|---|---|
| 21 | **token 每实例不同**（现场 `400a9e99-…` vs 旧 `c4b8ee60-…`）⇒ 上一轮 12 个 401 全是旧 token（自己吓自己） | `evidence/12086-api-info-live.json` |
| 22 | **鉴权 = 请求头 `X-Audit-Token: <现场token>`**（或 JSON body `"token"`）。**不需要 cookie**（cookiejar 全程 0） | `evidence/12086-sess-*.txt` |
| 23 | `POST /api/detector/query {"x":[32 floats]}` → `{"probs":[p0,p1],"remaining":N}`；16 维报 `Expected dimension 32`；未知字段一律 `Missing input vector 'x'` | `evidence/12086-instance3-auth-schema.txt` |
| 24 | `POST /api/submit` 请求体 = `{poisoned_clients, audit_key, bypass_vector}`（报错顺序剥完）；三件套齐了回 `{"reason":"Incorrect poisoned client identification","remaining":4,"status":"fail"}` | 同上 |
| 25 | **每实例只有 5 次 submit**（remaining 从 4 递减）；实例重建会重置 | 同上 |
| 26 | `/api/debug` 的 `suspected_clients=[2,6]` **被 submit 判错**；三个实例该端点返回值完全一致 ⇒ 数据静态、`[2,6]` 是诱饵或口径不同 | 同上 |
| 27 | 路由面进一步封闭：`/api/` 105 + 嵌套 50 + `/fl/ /federation/` 200 = **355 条候选全 404**（除 5 个已知端点） | `evidence/12086-enum-all-stages.json` |
| 28 | **`/tmp` 在沙箱里不跨调用持久**（后台 job 写的脚本下一次调用就消失）——跨步骤状态一律放工作区 | 踩坑 |

### 下一台实例的执行顺序（脚本已备）
1. `next2.py` —— **H1**：带 `X-Audit-Token` 再请求 `/api/info` `/api/debug`（鉴权后极可能解锁更丰富内容）；**H2**：补完裸路径与 `/static/ /data/ /files/ /exports/ /download/ /assets/` × 50 个数据类文件名
2. `detect_probe.py` —— 用检测器 oracle 拿"高置信 normal"的 32 维向量（3 基准 + 有限差分上升，≤100 次查询）
3. `trysubmits.py` —— 用每实例 5 次 submit 做**受控口径检验**（字符串 ID / 字段错位 [0,1] / 0-indexed [1,5] / 1-indexed [3,7]），判据是 reason **是否离开"client"语义**

## 靶机 #4（`<target>:27799`，11:30 起）—— 两个字段已解决，audit_key 无源

### 完整路由地图（**7 个端点，穷尽**）
| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | `{"status":"ok"}` |
| GET | `/api/info` | 契约 + **每次调用都下发新 token** |
| GET | `/api/debug` | 诱饵级泄漏：`suspected_clients=[2,6]`（**0-indexed**）、`compromised_rounds=[0,1]`、`model_params` |
| GET | `/api/detector/info` | `classes=["normal_traffic","anomaly"]`、要求 **class0 ≥ 0.6**、ε=0.15/≤12 维 |
| GET | `/api/detector/base_sample` | **32 维 base_sample（672 B）** —— 对抗扰动的合法起点 |
| POST | `/api/detector/query` | `{"x":[32]}` → `{"probs":[p0,p1],"remaining":N}` |
| POST | `/api/submit` | `{poisoned_clients, audit_key, bypass_vector}` |

穷尽证据：`/api/` 105 条 + 嵌套 50 条 + `/fl//federation/` 200 条 + 动态 84 条 + `/api/detector/*` 130 条 + 内部/查询类 32 条 = **≈600 条候选全 404**，只此 7 个。

### 已解决字段
1. **`poisoned_clients = [3, 7]`**（服务端确认，判据是 reason 变化）：
   `[2,6]`/`["2","6"]`/`[0,1]` → `Incorrect poisoned client identification`；**`[3,7]` → `Incorrect audit key`**。
   即 `/api/debug` 的 `[2,6]` 是 **0-indexed**，提交要 1-indexed。
2. **`bypass_vector` 已构造并自证**：在 base_sample 上改 **12 维**、**L∞=0.15**，class0(normal) 概率 **0.7063 ≥ 0.6**（`evidence/12086-bypass-vector.json`）。

### 未解决：`audit_key`（16 hex）
- **无格式校验**：`""` / `"zz"` / 长度 15/17 全返回 `Incorrect audit key` ⇒ 纯相等比较，无法从格式侧逼近。
- **20 个可解释假设全部失败**（`evidence/12086-key-candidates-tried.json`、`12086-key-final-tried.json`）：
  token 前/后 16 hex、uuid 各组拼接、md5(token)、sha256(token)、md5("3,7")、md5("37")、md5("0,1,3,7")、
  md5(debug/info/detector_info/base_sample 原始响应体)、base_sample 的 abs*16 mod16、符号位、IEEE754 尾数低位、
  md5(float64 字节流) …
- **根因判断：数据面缺失**。契约与 hint 都指向"从两个被投毒客户端的**梯度矩阵**里按行 L2 范数/谱特征拆出 key"，
  但服务端**没有任何梯度端点**（≈600 条候选扫尽，7 个端点全列上）。附件又只有 1016 B 的 `problem.json`（出题人构建期元数据）。
  ⇒ **梯度矩阵既不在附件里，也不在服务端**，`audit_key` 的预期来源不存在。

### 额度机制（重要，属设计漏洞）
- submit 与 detector 的额度都**按 token 计**；`/api/info` **每次调用都铸新 token**，且**旧 token 继续有效**。
  ⇒ 实际可用额度 = 10 × token 数（submit）/ 400 × token 数（detector），**等价于无限**（只需多调几次 `/api/info`）。
  我全程自限：0.12–0.4 s 间隔、单连接、未做暴力搜索。

---

## 12:35–12:48 纠偏与交接（**我上轮的结论被证伪**）

### ① 原判据已被证伪（必须写在最前）
我 11:55 的结论是"无梯度端点 ⇒ `audit_key` 不可得 ⇒ 题目残缺"。**这个结论是错的**：
平台 `detail 12086` 在 **12:36** 的一手原文是
`"score": "已答出35次，初始分值500.0，当前分值495.22，解出分值494.94"`
⇒ **35 队已解出**。所以"数据面不存在"的判断不成立，问题在我**没找到**来源，不是来源不存在。

> 教训（比结论本身更重要）：**"我扫了 N 条候选都 404" ≠ "端点不存在"**。
> 我用 35 队解出这条外部事实去反推自查，才发现两处方法论漏洞——这类"外部反证"必须主动去找，
> 不能靠"我的扫描很彻底"自我背书。

### ② 我未试过的两条具体来源（留给下一个 agent，按性价比排序）
1. **`normal_prob` 小数位 = 16-char hex（最便宜的假设，1 次 submit 即可验）**
   `GET /api/detector/info` 公开返回：
   ```
   normal_prob  = 0.23147521650098232  -> 小数前 16 位 "2314752165009823"（恰 16 字符，全在 hex 字符集）
   anomaly_prob = 0.7685247834990178   -> "7685247834990178"
   ```
   契约要求 `audit_key` 是 "16-char hex string"，而这两个值**任何队伍顺手可读**、且我此前把它当"概率噪声"直接跳过（只拿它当对抗扰动的起点）。这是我本轮最大的疏漏。
2. **路径覆盖有确凿空白：两段式前缀 + Host 头变体**
   我扫过 `/api/`（105）、`/api/` 嵌套（50）、`/fl/ /federation/`（200）、动态参数（84）、`/api/detector/*`（130）、内部/查询类（32）、裸路径与 `/static/ /data/ /files/`（约 160）——**但没扫过**：
   - 两段前缀：`/api/fl/`、`/api/fed/`、`/api/federation/`、`/api/audit/`、`/api/round/`、`/api/rounds/`、`/api/client/`、`/api/clients/`、`/api/model/`、`/api/train/`、`/api/training/`、`/api/aggregate/`、`/api/global/`、`/api/state/`、`/api/data/`、`/api/key/`、`/api/keys/`、`/api/vault/`、`/api/neural/`、`/api/exercise/` × 31 个名字 = **620 条**；
   - **Host 头变体**：若 Flask 开了 `url_map(host_matching=True)`，错误 Host 会返回 **404**（不是 403/405），可以完全解释"看起来全 404"。必须试 `Host: localhost / 127.0.0.1 / neuralvault / neuralvault.local / api.neuralvault.local / fl.local`。

### ③ 已确认可用、可直接复用的资产（这些是实打实的）
| 资产 | 值 / 判据 | 位置 |
|---|---|---|
| 鉴权 | 请求头 **`X-Audit-Token: <现场token>`**（或 body `"token"`）；**不需要 cookie** | `notes` §靶机 #3、`evidence/12086-sess-*.txt` |
| token 时效 | `/api/info` **每次调用都铸新 token**，旧 token 仍有效 ⇒ 额度按 token 计 | `evidence/12086-instance3-auth-schema.txt` |
| 额度 | submit 10/token、detector 400/token，**token 免费** ⇒ 事实上无限（限流绕过；仍应自限速） | 同上 |
| `poisoned_clients` | **`[3, 7]`**（`/api/debug` 的 `[2,6]` 是 **0-indexed**）；判据：`[3,7]` 的 reason 由 `Incorrect poisoned client identification` 变为 `Incorrect audit key` | `evidence/12086-submit-attempts.jsonl` |
| `bypass_vector` | 在 `base_sample` 上改 **12 维**、**L∞=0.15**，`class0(normal)` **0.2315 → 0.7063**（要求 ≥0.6）；base_sample 跨实例 md5 相同 ⇒ 向量跨实例不变 | `evidence/12086-bypass-vector.json` |
| 端点地图 | `GET /health` `/api/info` `/api/debug` `/api/detector/info` `/api/detector/base_sample`、`POST /api/detector/query` `/api/submit` | 同 §靶机 #4 |

### ④ 交接执行顺序（地址一 ready 直接跑，无需再做任何探测）
```bash
cd ~/ctf-2026/work/12086_neuralvault
python3 retry_all.py http://<proxyIp>:<proxyPort>     # 约 6 分钟，任一步命中即停
#   step1 resume.py  : 概率小数位 + 附件 md5/CRC 派生，20+ 个 16-hex 候选
#   step2 keyzoo.py  : 系统性派生（概率×10^k、base_sample 每分量数字段/十六进制/位模式、
#                      行 L2 范数、debug 数值、token 片段），最多 150 个候选
#   step3 bigscan.py : 两段式前缀 620 条 + Host 头 7 变体 + 22 个数据文件名 × 7 目录
```
命中判据：`/api/submit` 的 reason **不再是 `Incorrect audit key`**（此时 clients 与 key 均通过，向量已验证满足约束）⇒ 拿 flag 后先本地确证，再 `CTF_AGENT=ai-12086 python3 scripts/ycb.py submit 12086 '<flag>'`（平台只认 `{}` 内内容；同题 ≤3 次）。

### ⑤ 幽灵容器（本轮踩到的平台侧坑，写下来避免下个 agent 重复消耗槽位）
`env start` 回 `{"code":"00000","message":"执行开启环境成功"}`，但 `detail.endpoints` **长期为空**；`env status` 的 `data:false` **对正常在用的容器也是 false，毫无判别力**。判定只能看 `detail.endpoints[0]`：`status=="running"` 且 `proxyIps` 非空才算 ready；`exposeIps` 若为 `192.168.x.x` 是内网，连不上。本轮 12086 两次 build ≥8 分钟无地址（12:39 start → 12:48 被销毁），当天同型幽灵已出现三台。

---

# ✅ 已解出（13:40，平台 `code=00000 解题成功`）

**flag = `DASCTF{86111530176209339321986958990035}`**
提交裸串 `86111530176209339321986958990035`；回包 `{"code":"00000","message":"解题成功!","result":true,"data":{"isCorrect":true,"hasCheated":false,"eventId":88043}}`

## 正门：`GET /api/federation/log`（两段式前缀，带 `X-Audit-Token`，1.7 MB ZIP）
300 个 `.npy` = **10 clients × 5 rounds × 6 张量**：`dW1(32,48) dW2(48,48) dW3(48,16) db1(48) db2(48) db3(16)`。
模型即 32→48→48→16，与 `/api/info` 的 `input_dim=32` / `output_classes=16` 完全对上。

## 三步解法
1. **定位投毒方** —— 末层 `dW3` 的**行 L2 范数** `max/median`：
   `c3 = 6.26`、`c7 = 3.46`，其余 client 全在 1.12–2.85 ⇒ **投毒方 = 文件里的 c3 / c7**
   （`/api/debug` 的 `suspected_clients=[2,6]` 是 **0-indexed 诱饵**；提交用 1-indexed 正好 `[3,7]`，与我此前靠 reason 判据确认的一致）。
2. **读 audit_key** —— 在 **r2 轮**，`c3_r2_dW3` 与 `c7_r2_dW3` 的**前 8 行行范数是精确整数**（其余行仅 ~0.003，是植入块）：
   ```
   c3: [5, 12, 13, 16, 1, 16, 1, 16]
   c7: [ 8,  7,  1,  5, 1,  6,  7,  7]
   ```
   值域 1..16 ⇒ **nibble = norm − 1** ⇒ `4bcf0f0f` + `76040566` = **`4bcf0f0f76040566`**
   —— 正是 hint 原文 "Examine the **row-wise L2 norms** … of **last-layer** gradients" + "The audit key is **split across two compromised clients'** gradient matrices" 的字面实现。
   （`norm` 直接映射/`norm%16` 会得到 `5cd0101087151677`，是错误分支。）
3. **bypass_vector** —— `base_sample` 上改 **12 维**、**L∞=0.15**，`class0(normal)` 0.2315 → **0.7063**（要求 ≥0.6）；
   本实例提交前复验 `{"probs":[0.7063,0.2937]}` 仍达标（base_sample 跨实例同 md5，向量可复用）。
4. `POST /api/submit` → `{"flag":"DASCTF{…}","status":"success"}`。

## 本局最大教训（写给下次的自己）
**"我扫了 ~600 条候选都 404" ≠ "端点不存在"**。我一直把注意力放在 `/api/` 顶层与 `/api/detector/*`，
却**从未扫过 `/api/federation/` 这类两段式前缀** —— 正门 `log` 就在里面。
更糟的是：12:36 拿到"35 队已解出"这条**外部反证**后，我先花 20 分钟猜 hash 派生 key（20+61 个全错），
而不是先补扫描覆盖。
⇒ **当外部事实（解出数）与内部结论冲突时，第一步是审计自己的覆盖矩阵，不是换编码假设。**

## 作品
- `scripts/12086-solve.py`：**真解脚本**（在线全流程 + `--zip` 纯离线复算），已实测 `--zip` 复现出 `4bcf0f0f76040566`
- `evidence/12086-federation-log.zip`（原始日志 300 个 .npy）、`evidence/12086-submit-success.txt`、`evidence/12086-fedlog-key-candidates.json`
- `work/12086_neuralvault/final_submit.py`（终局三件套提交，含两种拼接顺序 × 两种映射的候选对照）
