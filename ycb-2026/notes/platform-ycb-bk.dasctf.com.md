# 平台事实 · ycb-bk.dasctf.com（DASCTF / slab-match，本科院校组）

> **来源**：2026-10-23 赛前对本队唯一入口 `https://ycb-bk.dasctf.com/compete/1750/detail` 的
> ① 页面/JS 静态逆向（`work/platform-recon/app.js`，7.35 MB）② 未授权只读探测（`{"code":"40401"}`）。
> **这些是"参考"，不是永久规则**：平台已改过多版，**开赛用 `python3 scripts/ycb.py creds` 回源复核一次**。
> **本文件是赛中唯一允许额外读的 md**（AGENTS.md 的"不读其他 md"在此让路）。

---

## 1. 入口与鉴权（**最容易卡住的地方**）

| 事实 | 依据 | 影响 |
|---|---|---|
| 本组入口 `https://ycb-bk.dasctf.com`（比赛号 **1750**） | 参赛手册：本科院校组 = ycb-bk；URL `/compete/1750/detail` | 另外三组是 ycb-dz / ycb-qy / ycb-gz，**镜像环境别跑错组** |
| 前端是 Vue SPA，API 全部同源 `/slab-match/api/v1/...` | `app.js` 里 `baseURL:"/"` | 不要去找 `/api/v1/challenges`（那是 CTFd，本站不是） |
| **鉴权 = 请求头 `authorization: Bearer <jwt>`** | 拦截器原文 `e.headers.authorization = localStorage.getItem("jwtToken")`，而 localStorage 里存的值**自带 `Bearer ` 前缀**（2026-10-23 21:00 实测：裸 JWT → 40401；带 `Bearer ` → 00000） | **★ 千万别剥 `Bearer`**，这是本届踩过的第一个坑 |
| **另需请求头 `matchId: <competeCode>`** | 拦截器：`a && (e.headers.matchId = a)`，a 来自 localStorage `competeCode-userDetail` | 缺 matchId 会被当成没进比赛 |
| 成功码 `code == "00000"` | 前端全部按 `"00000"===i.code` 判成功 | 不是 HTTP 200 就算成功 |
| 未登录 = HTTP **200** + `{"code":"40401","message":"未能读取到有效Token"}` | 实测三个端点 | **40401 永远不是 flag 错**；先查 token |
| 错误体是 **`content-type: text/plain`** 的 JSON 字符串 | 实测 40401 响应头 | 客户端**不能**按 content-type 判断是不是 JSON |
| token 寿命：前端拦截器会在**响应头**有 `Authorization` 时写回 localStorage | 拦截器 response 分支 | 实测普通查询响应**不带** `Authorization` 头 → token 不轮换、无 `exp`，可长期用 |
| token 取法 | 比赛页 F12→Console 跑 `scripts/grab-token-snippet.js`（自动 copy 到剪贴板，含 `Bearer `） | 从 cookie 抄可能拿到旧值/裸值 |
| `data` 有时是 **JSON 字符串**（前端 `JSON.parse`） | 多处 `JSON.parse(r()(n.data))` | 解析要兼容 str/dict（`ycb.py` 已做） |

**token 交接方式（不落工作区）**：

```bash
bash ~/ctf-2026/scripts/set-token.sh          # 交互贴 token（无回显），写 ~/.config/ctf/creds.env (0600)
python3 ~/ctf-2026/scripts/ycb.py creds       # 回源自检：脱敏 + 一次只读请求
```

## 1.5 阶段（**真实值，2026-10-23 21:00 实测**）

```jsonc
// GET /player/stage/info-list?matchId=1750
{"code":"00000","data":[{"id":3241,"name":"CTF夺旗赛","mode":"CTF",
  "startTime":1792807200000,"endTime":1792821600000,
  "description":"…题目将在 10 时和 12 时分批放出…"}]}
// GET /player/stage/status-list?matchId=1750&relationId=1750&relationType=slab-match
{"code":"00000","data":[{"id":3241,"status":"PENDING","startCountdown":46754}]}
```

- **stageId = 3241**（不是 9001；`9001` 是假平台测试遗留，已从缓存逻辑里删掉）。
- `startTime 1792807200000` = **2026-10-24 10:00 (UTC+8)**，`endTime` = 14:00。
- **题目分两批放出：10:00 和 12:00** → `watch` 必须在 12:00 继续跑（别第一批派完就停）。
- `PENDING` 时拉 `exercise-list` 会被**记为非法请求**：

```jsonc
{"code":"40001","message":"阶段未开始无法获取赛题列表，用户非法请求赛题列表已记录"}
```

> **★ 未开赛不要轮询题目列表**：`ycb.py list` 已加保护直接拒绝；`ycb.py watch` 先每 60s 轮询
> **stage 状态**（合法只读端点），开赛后自动转成 10s 轮询题目列表。

## 2. 只读端点（本次逆向确认，payload 取自前端调用点原文）

| 用途 | 方法 | 路径 | 参数 / body |
|---|---|---|---|
| 比赛概览 | GET | `/player/answer-panel/overview` | `{matchId, stageId}` |
| 阶段列表 | GET | `/player/stage/status-list` | `{matchId, relationId, relationType:"slab-match"}` |
| 题目列表 | GET | `/player/ctf/exercise-list` | `{matchId, stageId}` |
| 题目详情 | GET | `/player/ctf/exercise` | `{matchId, exerciseId, stageId}` |
| 公告 | GET | `/player/match/notice/now-list` | `{matchId}` |
| 我的/队伍信息 | GET | `/player/match/user/detail`、`/player/match/team/detail` | `{matchId}` |
| 控制台引导 | GET | `/player/match-stage/console/bootstrap` | `{matchId, stageId}`（缺 stageId → 40001） |
| 比赛概览 | GET | `/player/answer-panel/overview` | `{matchId, stageId}` → 见下 |

`overview` 实测（未开赛也可调，用来拿轮询节奏）：

```jsonc
{"matchTitle":" 2026 年“羊城杯”网络安全大赛初赛【本科院校组】","stageName":"CTF夺旗赛",
 "answerModel":"BREAK","teamName":"<team>","countdown":61173,"stagePoint":0.0,"stageRank":1,
 "exerciseListInterval":10000,"checkEndpointInterval":5000,"answerInterval":1000,
 "noticeInterval":5000,"countdownInterval":60000,"enablePlayerSubmitWriteup":true,
 "manualPrepareEndpoint":true}
```

→ **题目列表 10s 一轮、靶机 5s 一轮、提交间隔 1s、公告 5s**；`answerModel=BREAK`（解题制）。

## 3. 提交（**每题上限 50 次**）

```jsonc
POST /slab-match/api/v1/player/answer-panel/answer
{"matchId":"1750","exerciseId":"<id>","flag":"flag{...}"}
// 成功分支（前端原文）：{code:"00000", data:{result:true | eventId:<n>, hasCheated:false}}
// eventId 还要再查一次拿分数：
GET /player/answer-panel/monitor-answer-result?matchId=1750&eventId=<n>&stageId=<sid>
```

- **平台规则：每题最多 50 次提交**（"注意"级）。本队纪律仍更严：
  - 同题同 flag **不重复提交**（脚本直接跳过，不占额度）；
  - 同题已解出 → 拒提不同 flag（`--force` 只有父代理/人类能加）；
  - 每个子代理**不猜写法**；拿到可复现 flag 才提；
  - 台账 `evidence/submit-log.jsonl`（含 code/message/data/是否 result:true）。
- **判定语义（重要）**：`data.result === false` → 明确错；`data.result === true` → 对；
  **只有 `eventId` 没有 `result`** → 平台已受理但分数待出，`ycb.py` 会自动查
  `monitor-answer-result`，仍无结论时**退出码 2**（"已受理未判定"）——此时**不要重复提交**。
- `ycb.py submit` 退出码：`0`=正确 / `1`=错误 / `2`=已受理未判定 / 非 0 一律先别重试。
- **403/401 与 40401 都不是 flag 错**：先疑 token / matchId / 阶段未开。
- flag 前缀以题目描述为准（**禁止硬套** `flag{}`）。

## 4. 容器 / 靶机（并发是稀缺资源）

| 用途 | 方法 | 路径 | body |
|---|---|---|---|
| 起 | POST | `/player/ctf/build-exercise-env` | `{matchId, exerciseId, stageId}` |
| 查 | GET | `/player/ctf/check-exercise-env` | `{exerciseId, stageId}` |
| 停/回收 | POST | `/player/ctf/expire-exercise-env` | `{stageId, exerciseId}` |
| 重置 | POST | `/player/ctf/recover-exercise-env` | `{...}` |

- **并发上限开赛实测**（起第 2 个报错即上限），不要假设；`ycb.py env` 不做排队，**主代理统一排队**。
- 只有 pwn/web 等 `type` 需要靶机；misc/crypto 静态题**不占槽位**。
- 起容器后 `check-exercise-env` 有 `checkEndpointInterval`（前端默认 5s）→ 隔 5s 轮询。
- **用完立刻 stop**（全队共享）。

## 5. 赛程与硬规则（参赛手册 2026-10-23 原文）

| 项 | 内容 |
|---|---|
| 时间 | **2026-10-24 10:00 – 14:00**（4 小时，线上解题赛） |
| 组别入口 | 党政 dz / 本科 bk / 企业 qy / 高职 gz |
| 答题 | 必须平台登录；**团队任一成员提交成功即得分** |
| 提交上限 | **每题 50 次**（队内共享） |
| 录屏 | 全程录屏（EV/OBS），赛后按团队传百度网盘 |
| 违规 | 禁止对平台暴力攻击/破解；禁止求助或分享题解/flag；赛后 2 小时内交 Writeup |
| 沟通 | 问题在 QQ 群私聊工作人员 |

## 6. 预发附件（开赛才给密码）

| 附件 | 形态 | 状态 |
|---|---|---|
| `firmware/附件.rar` | 95 KB，**RAR 头加密**（`7z l` → `Cannot open encrypted archive`） | 等密码 |
| `firmware/Linxiao.zip` | 21.8 GB，**ZipCrypto 加密**（`flag_bits=0x9`）；内含 `YCB_linxiao.E01` 64.4 GB + `YCB_linxiao.E02` + `checksum.txt` + `背景故事.txt` | 等密码 |
| `firmware/ycb-BabyMenu/` | VMware Win11 x64 VM：64 GiB vmdk（monolithicSparse，26.6 GiB 实占），16 vCPU / 16 GB RAM | **不加密，可离线分析** |

> ⚠️ 本机 9.7 GB 内存**跑不动**这个 16 GB 内存的 VM → 只能 `qemu-img convert` 出 raw 后用
> sleuthkit（`mmls`/`fls`/`icat`）离线看，或挂载后只读分析。
> ⚠️ E01 需要 **libewf / pyewf**（本机缺，见 `needs-approval.md`）。
