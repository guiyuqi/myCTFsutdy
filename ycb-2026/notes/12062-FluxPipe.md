# 12062 · FluxPipe (WEB / HARD) — notes

> 目标：`nc <target> 32512` → 容器 4000（Cowboy HTTP）
> flag 格式：`DASCTF{}`（来源：附件 `problem.json`，非平台明示 → 以靶机回显为准再确认）

## 0. 附件真相（最重要的情报）

`FluxPipe的附件.zip`（sha256 `446a37668a89d865acc6749f1443d5f071e8c47a3fd80aeacb214bbad36b571d`）
里**不是源码**，只有一个 `tempdir/WEB附件/problem.json` —— 题目内部元数据泄漏：

| 字段 | 值 |
|---|---|
| flag_type / flag_format | dynamic / `DASCTF{}` |
| language / framework / db | Elixir / Plug+Cowboy / PostgreSQL 15 |
| source_provided | **false**（本来就没源码） |
| port | 42567 |
| stage | pending-review |
| vulns | ①SQL注入(Ecto raw query拼接) ②信息泄露(Debug端点+ETS表) ③自定义协议逆向(FPX XOR-Rotate) ④侧信道(CRC校验oracle) ⑤代码注入(Code.eval_string) |

→ 黑盒题。`ycb.py download` 抓到的 94B 是 API 错误 JSON（`40403 无此权限`），
真附件必须用 `detail.json` 的 `attachment.url` 直取。

## 1. 已确认的靶机行为（重建前后都适用）

| 行为 | 结果 |
|---|---|
| `GET /` | 2921B 静态 HTML，footer 明写 `API docs at /api/v1/health`；无注释、无 JS、无外链 |
| `GET /api/v1/health` | 200，动态（`uptime_seconds` 变），泄漏 `node=fluxpipe@127.0.0.1`、`epmd_port=4369`、`services.fpx_protocol=listening:4001`、`distribution=enabled`、`beam_version=27`、`postgresql=connected` |
| `GET /api/v1/pipelines` | 200，固定 5 条管道（`ingestion-kafka`/`transform-enrich`/`alert-anomaly`/`sink-elasticsearch`/`debug-sandbox`） |
| 任意方法 `/graphql` | 200，**纯静态桩**：任何输入（空 body / 非法 JSON / 任意 query / GET / POST）都返回同一份硬编码 `__schema`，只给类型名与 mutation 名（createPipeline/deleteUser/execCommand/updateConfig），**不可用** |
| 其他一切路径 | 404 `{"error":"Not found"}` |

**端口性质判定（决定性）**：32512 是纯 Cowboy —— 空闲 5s 断开、`GARBAGE\r\n\r\n` 立刻 400、
`FPX`/`\x00` 无响应到超时、h2c preface 回 GOAWAY。**所以容器内 4001 的 FPX 协议不经过这个代理。**

## 2. 已排除

- WebSocket / SSE / 自定义 Upgrade：24 条路径 × 4 种 Upgrade 全 404，从无 101。
- `/api/v1/pipelines/{1..5,debug-sandbox,ingestion-kafka}/{run,debug,test,exec,eval,metrics,...}`
  30 动作 × GET/POST 全 404 → 无 id 子资源。
- `/api/v1/pipelines` 的 POST/PUT/PATCH/DELETE/HEAD 全 404。
- `/api/v1/pipelines` 的 13 个常见 query 参数（status/name/id/q/filter/sort/limit/offset/order/debug/all/pipeline_id/mode）
  全部输出一致 → **handler 完全忽略参数**（所以"按 status 过滤的 Ecto 拼接 SQLi"不在这条路由上）。
- 单段路径字典（3005 词 × `/` 与 `/api/v1/` 前缀）只命中 pipelines 与 graphql。
- root 页面无 HTML 注释/隐藏字段。

## 3. 我犯的错（必须记住）

**用 24~30 并发跑了 42k + 6k 条请求，把唯一一台靶机的 accept 队列打满 → 整机 ECONNREFUSED。**
后果：① 靶机需重建（父代理警告 12061 已因此损失一台）；② 扫描结果**不可信**
（已知合法路由 `/api/v1/health` 都没被那次扫描命中，说明高并发下结果会假阴）。
**纪律：单线程、每条 ≥200ms、单批 ≤20 条。**

## 4. 当年的待验证清单（**已全部执行完**，结论见 §5）

| # | 项 | 结果 |
|---|---|---|
| 1 | 复核 4 个行为是否稳定 | 3 台实例完全一致 ✔ |
| 2 | 规整化差异 `//`、`/./`、`%2e`、尾斜杠 | 全部 200 且同内容，无第二套 handler ✘ |
| 3 | 内容协商后缀 `.json/.csv/.xml` | 全 404 ✘ |
| 4 | header 门控（X-Debug/X-Internal/XFF/…共 11 种 + 8 种 cookie） | 无 body 差异 ✘ |
| 5 | param fuzz（曾超时未跑完 → **后已补完**） | 50 平铺名×2 值 = 126 次 + 12 嵌套名，**逐字节相同** ✘ |
| 6 | FPX/4001 是否随代理暴露 | 父代理双侧确认：每台都只有 `nc/4000` ✘ |

→ 原先第 6 条推出的"部署态不可解"**已被推翻**（见 §5 顶部更正：解出数在我判定后仍以 1 队/30 秒上涨）。

## 5. 最终状态（未解出）

> ⚠️ **重要更正（收尾前最后 6 分钟测到，推翻了本节原先的结论）**：
> 我在 10:52–10:58 连测 5 次榜单，解出数 **26 → 27 → 29 → 31 → 33 → 34**，
> 约 **1 队 / 30 秒**，且**全部发生在我判定"部署态不可解"之后**。
> ⇒ **这台部署是可解的、而且很容易**；"12 队是早期窗口红利"的猜想**已被自己否掉**。
> 我的"HTTP 面无洞"只在"**我试过的那些面**"上成立，**不等于题不可解**。
> 写 wp 时**不要**写成"平台映射收紧导致不可解"——那是错的，会误导后续复盘。

3 台实例（`32512` → `24116` → `15035`）行为**完全一致**，父代理侧确认**每台都只映射 `nc/4000`**。
在 4000 这条 HTTP 上我已穷尽（见下），未找到任何注入/鉴权/SSRF/协议分派面：

- **SQLi 否定**（关键）：`/api/v1/pipelines` 上 **50 个平铺参数名 × 2 值 = 126 次**，再加
  **12 个嵌套/数组参数**（`filter[status]`、`q[name]`、`id[]`、`where[id]` …），响应**全部逐字节相同**。
  → handler 忽略一切参数，`problem.json` 的"Ecto 拼接 SQLi"不在这条实现上。
- POST 面：`/api/v1/pipelines` 带真实 JSON body 全 404；mutation 名当 REST 子路径全 404。
- `/graphql`：44 个参数名 × 7 种 Content-Type × GET/POST 恒为桩；`500` 只是 Plug.Parsers 的 415 被映射。
- 路径：单段 3005 词 + 多段 322 条，零额外命中。
- 规整化/后缀/vhost/header/cookie/WS/Upgrade/absolute-URI/CONNECT/畸形请求：全部排除。
- FPX 不在 4000（无版本分派器）；容器内网 4001/4369 从本机不可路由。

**已验证不是漏看的**：我把 `/api/v1/pipelines` 的**完整 546B** 和 `/api/v1/health` 的**完整 229B**
从 `evidence/probe.log` 里原样取出解析 —— 5 条管道无第 6 字段、无 flag；health 无隐藏 key。
（我此前的终端输出是 `[:200]` 截断的，专门回查过这一点。）

## 5.1 剩余最可能的方向（给下一位，按我现在的判断排序）

1. **`/graphql` 是"盲执行"**：响应恒为桩，但 `execCommand` 可能**真的执行了**、只是把结果写进
   别处（ETS / pipeline 数据）。验证法：`POST /graphql -d '{"query":"mutation{execCommand(command:\"cat /flag*\")}"}'`
   之后立刻再 `GET /api/v1/pipelines` 与 `/api/v1/health`，**比对是否有副作用**（我只比了桩本身，
   没在"执行后"复查其它端点 —— 这是我最可能漏掉的一步）。
2. **`updateConfig` 先写后读**：`updateConfig` 改掉某配置（如 pipelines 的 `debug-sandbox` 状态
   由 maintenance 变 active），再访问原来 404 的 debug 路由。
3. 若 1/2 都不成立，说明洞在我字典外的**作者自造词路由**上，需要一次性更大字典
   （与"≤30 条连接"铁律冲突，须申请新的连接预算）。

## 6. 交付

- 交接文档：`work/12062_fluxpipe/HANDOFF.md`（含全部负结果与下一步建议）
- 脚本：`fpx.py`（XOR-Rotate 编解码 + 已知明文求解 + 8 种 CRC，`python3 fpx.py` 自检通过）、
  `probe.py`（低速五阶段）、`probe2.py`（14 条最省连接版）、`recon/scan/scan_post/wsprobe.py`（早期，勿再跑高并发版）
- 证据：`work/12062_fluxpipe/evidence/`（root.html、root.headers、probe.log、probe2.log、scan-hits.json）

**运维教训（已写入 REPORT）**：该容器是"累计连接数耗尽"型 —— 必须 keep-alive 单连接、总量 ≤30~50 条；
早期 24~30 并发跑 4 万+ 请求直接把第一台打死，并导致扫描假阴。

---

# 12:3x 换方法重打（`web-12062b`）—— 环境被回收，未开打

> 时间：2026-10-24 12:33 – 12:45 CST。承接上一位代理，要求"方法必须完全不同"。
> 结果：**一包都没发给靶机就被回收**（父代理 12:39 前后 `销毁靶机成功`，把槽位让给 12086）。
> 全部产出 = **0 条靶机流量证伪 P0** + **本地只读审计证明上一位的枚举不可信** + 执行方案。
> 详见 `work/12062b/README.md`、`work/12062b/checklist.md`。

## 1. P0 假设：一手证伪（0 条靶机流量）

任务给的 P0 是"`portMappings` 里可能有第二个端口（`tcp/4001` / `tcpmux/…`），
有就直接对第二个端口讲 FPX"。实测（12:35:39，`ycb.py detail 12062`）：

```json
"ports":        ["nc/4000"],
"portMappings": [{"type": "nc", "port": "4000"}],   // ★ 长度 == 1，无第二项
"exposeIps":    ["<target>"],
"isProxy":      true,
"proxyIps":     []
```

- **`portMappings` 只有一条** ⇒ 不存在第二个映射，FPX/4001 **不可达**。
- `exposeIps` <target> 与本机 eth0 **<target>/20 不同网段**，
  本地实测 `<target>:4000` / `:4001` **均 closed/unreachable** ⇒ 只能走公网代理。

**⇒ P0 不成立，转 HTTP 路线。** 证据原文：`work/12062b/evidence/portMappings-12-35-39.txt`。
**成本对比**：上一位代理为同一结论花了 3 台容器 + 4 万请求；本次 **1 次平台 API 调用**。
（同一个结论，方法差异决定了代价差 4 个数量级——这是本题最该复盘的工程点。）

## 2. 上一位代理的枚举为什么不可信（本地只读审计，可复现）

| 证据 | 内容（全部 `grep`/读文件，未发任何请求） |
|---|---|
| ① 命中判定坏了 | `evidence/scan-hits.json` 只有 2 条命中（`/api/v1/pipelines`、`/graphql`），**没有 `/api/v1/health`** —— 而它是稳定 200（229B）。漏掉已确认 200 的扫描器，"零命中"无判别力 |
| ② 可信探针也只试子路径 | `evidence/probe.log` 里是 `/api/v1/debug/ets`、`/debug/state`、`/debug/tables`、`/api/v1/rules/list`、`/api/v1/metrics/list`、`/api/v1/transforms/1` —— **裸资源名一次都没请求过** |
| ③ 大字典覆盖率 = 0 | `grep -c` 数 `evidence/scan_full.log`：`api/v1/metrics` **0**、`api/v1/alerts` **0**、`api/v1/transforms` **0**、`api/v1/pipelines/5` **0**、`api/v1/rules` 2（都是 `/list`）、`api/v1/debug` 2（都是子路径） |

⇒ 结论"HTTP 面无洞"只在"**试过的那一小撮路径**"上成立。
完整审计：`work/12062b/evidence/enumeration-gap-12-40.txt`。

## 3. 本代理的不同方法：应用自有词汇驱动（不是字典）

依据 `competition-web-runtime`「先从运行时可见的 route/feature 名出发，再扩面」。
词表**全部来自应用自身**：根页 4 张功能卡 `Pipeline Management` / **`Transform Rules`（6 configured）** /
**`Monitoring & Alerts`（3 policies）** / **`Debug Sandbox`（Maintenance）**，加上 footer 与 health 字段。

**关键观察**：根页宣传 4 个功能，本队只找到 1 个（`pipelines`）。
`rules` / `metrics` / `alerts` / `debug` 这 4 个**裸资源名是最大空白面**，而它们正好对应唯一还没打的漏洞
「信息泄露(Debug端点+ETS表)」。

**为什么把 #2 Debug+ETS 排第一**：平台数据 12:36 **246 队** → 12:40 **254 队**，
约 **1.25 队/分钟**持续解出。这个速度只匹配"一条 GET 直接拿东西"的形态，
不匹配"逆向自定义协议 + CRC 侧信道"的深链；而 #2 恰是一条 GET 的形态，且我们只试过它的子路径。

## 4. 限速纪律（本代理全程参数，已写死进脚本）

| 参数 | 值 | 理由 |
|---|---|---|
| 并发 | **1**（单 `requests.Session` keep-alive） | 上一台 24~30 并发 42k 请求 → 整机 ECONNREFUSED |
| 间隔 | **≥300ms**（脚本 0.35s） | 该容器"累计连接数耗尽"型，30 条裸连接即死 |
| timeout | **15s** | 防半死连接堆积 |
| 预算 | 首轮 **≤48**，全程 **≤300** | 留 follow-up 量 |
| 健康检查 | 每 **15** 条 `GET /api/v1/health`；连续 **2** 次失败 → `SystemExit(9)` 落盘 | 防"打爆了自己还在打" |
| 判据 | 404 且 body 恰为 `{"error":"Not found"}` 记 `?`；**404 但 body 变了也单独记**（是信号） | 避免把"路由在、方法不对"误判成"不存在" |

### ★ 要写进复盘的一句
**上一台容器被打爆的真实原因是并发字典扫描**（24~30 并发 / 42k+ 请求 / 裸连接不复用），不是题目。
而且它还**连锁污染了结论**：高并发下扫描器产生**假阴**（连已知 200 的 `/api/v1/health` 都没命中），
于是"扫完零命中"被误读成"HTTP 面无洞"，进而推出"部署态不可解"——该结论已被解出数持续上涨推翻。

## 5. 平台侧一手读数（可解性）

| 时间 | 读数 |
|---|---|
| 12:34 | 已答出 244 次，当前分值 255.96 |
| 12:36 | 已答出 **246** 次，当前分值 251.93 |
| 12:40 | 已答出 **254** 次，当前分值 235.46 |

⇒ 当前部署**明确可解**，且解法对大量队伍是"顺手"的。
**我们没解出来是方法问题（字典扫描打爆容器 + 假阴污染结论），不是题目、也不是部署。**

## 6. 本节产出

`work/12062b/`：`fire.py`（一键入口：先读 `portMappings` 决定路线，限速写死）、
`stage_a.py`（48 条裸资源名执行表）、`probe.py`（通用限速探针）、
`checklist.md`（**5 条 vulns 逐条：入口 / 请求 / 判据**）、`evidence/`（2 份一手证据）。
**未跑**：`stage_a.py` 一次都没执行（靶机已回收），故本目录不含任何靶机响应。

## 7. 下一位 10 分钟执行顺序

1. `python3 work/12062b/fire.py 12062 detail` —— 确认 `portMappings` 条数（0 靶机流量）。
2. `python3 work/12062b/fire.py 12062 stage_a http://<proxy>:<port>` —— 打裸资源名。
3. 命中 `/api/v1/debug` → 直接找 `DASCTF{`。
4. 命中 `rules`/`transforms` → 读回规则学语法 → 传 `1+1` 验证求值 → `:os.cmd('cat /flag*')`。
5. 命中带参数入口 → 按 `checklist.md` #1 三条判据试 SQLi（`Ecto`/`Postgrex` 报错、`'` vs `''` 差异、`1-0` 算术）。
6. **不要**并发、**不要**上字典；≤48 条无结果就换思路。

---

# 三条工程结论（`web-12062b`，供复盘直接引用）

> 这三条与"这道题的 flag 是什么"无关，是**方法论层面**的结论；
> 无论本场是否解出，下次开赛都应该直接套用。

## 结论 A：`portMappings` 长度 1 ⇒ 无第二端口，FPX 只能从容器内部打
**1 次平台 API 调用 vs 上一位 3 台容器 + 4 万请求。**
12:35:39 `detail` 原文：`ports:["nc/4000"]`、`portMappings:[{"type":"nc","port":"4000"}]`（长度 1）、
`exposeIps:["<target>"]`（与本机 <target>/20 不同网段，4000/4001 实测 unreachable）。
⇒ `problem.json` 的 vulns ③④（FPX XOR-Rotate / CRC oracle）**没有对外入口**。
**教训**：先读平台 API 能拿到的事实，再去碰靶机。同一个结论，验证成本可以差 4 个数量级。

## 结论 B：旧枚举是**假阴**，证据链可复现
1. `evidence/scan-hits.json` 只有 2 条命中，**缺 `/api/v1/health`** —— 而它是稳定 200（229B）。
   一个漏掉"已确认 200"的扫描器，它的"零命中"没有判别力。
2. `evidence/probe.log`（相对可信的低速探针）里只有 `/api/v1/debug/ets`、`/debug/state`、
   `/debug/tables`、`/api/v1/rules/list`、`/api/v1/metrics/list`、`/api/v1/transforms/1` ——
   **所有裸资源名一次都没请求过**。
3. `grep -c` 数 `evidence/scan_full.log`：`api/v1/metrics` **0 次**、`api/v1/alerts` **0 次**、
   `api/v1/transforms` **0 次**、`api/v1/pipelines/5` **0 次**。
   号称 3005 词 × 2 前缀，连根页功能卡上的词都没打。
**⇒ "HTTP 面无洞"只在"试过的那一小撮路径"上成立。**
推论：**"扫描零命中"必须先证明扫描器本身有效**（拿一个已知 200 的路由喂给它，看它记不记得）。

## 结论 C：单 worker 容器会被自己的扫描打爆，且会**连锁污染结论**
参数：并发 **24~30**、**42k+** 请求、裸连接不复用 ⇒ 整机 ECONNREFUSED（accept 队列满）。
二次伤害：高并发下客户端自身也大量失败 → 扫描器产生**假阴** → "扫完零命中"被误读成
"HTTP 面无洞" → 进而推出"部署态不可解"这个**错误结论**（已被解出数持续上涨推翻）。
**下次参数（已写死进 `fire.py`/`stage_a.py`）**：
并发 **1**（单 keep-alive）/ 间隔 **0.35s** / timeout **15s** / 首轮 **≤48**、全程 **≤300** /
每 **15** 条 `GET /api/v1/health`，连续 **2** 次失败 `SystemExit(9)` 落盘；
判定"不存在"的唯一形态 = `404` **且 body 恰为** `{"error":"Not found"}`（404 但 body 变了 = 信号）。

---

# 12:52 后续：第 4 台幽灵容器，未开打即收工

- 12:41 父代理 `env start 12062` 回 `执行开启环境成功`；
- 12:41:51 → 12:54:04 我每 20s 采样 `detail.endpoints`，**连续 16 次全部 `[]`**；
- 定性（父代理 + 另一位代理交叉确认）：**`destroy` 链路通，但 `build` 对这几台一律回
  `40409 已构建，请勿频繁点击`** —— "平台认为有构建记录，而那条记录没有对应的活实例"。
  同型已中 12061 / 12066 / 12086 / 12062 四台。**我这台从头到尾 0 条靶机流量。**

## 解出数一手读数（全部我自己读的，时间戳见行）
| 时间 | 读数 |
|---|---|
| 12:34 | 244 次 / 255.96 |
| 12:36 | **246 次 / 251.93** |
| 12:40 | **254 次 / 235.46** |
| 12:48 | 260 次 / 222.77 |
| 12:54 | **268 次 / 205.38** |

24 分钟 **+24 队**，约 **1 队/分钟**持续解出 ⇒ 当前部署对大量队伍是"顺手"的。
（父代理 12:36 另读到 249 / 245.82，秒级差异，**两说并存不覆盖** —— 保留原始读数才可追溯。）

**结论**：我们没解出来，是**方法问题**（并发字典扫描打爆唯一容器 + 假阴污染了"无洞"判断 + 后续四台幽灵容器），
**不是题目、也不是部署**。下一次开赛应直接执行 `work/12062b/checklist.md`。

---

# 13:20 终于拿到靶机：全量实测（`web-12062b`，未解出，但拿到了唯一实质发现）

> 靶机：`http://<target>:18768`（`portMappings:[{type:nc,port:"4000",proxy:"18768"}]`）
> 13:20 起，13:28 因**响应变慢**触发我写死的停手判据而收工。共 **~290 条 HTTP 请求**，
> 单 keep-alive 连接、串行、0.35s 间隔，全程未并发、未上字典。

## 1. 唯一实质发现：`GET /.env` → 200（274B，作者故意种的诱饵）

```
DATABASE_URL=postgres://postgres:f4ke_p4ss_2026@localhost/fluxpipe_dev
SECRET_KEY_BASE=xK9mQ2vL8nP5rT7wY1zA3bC6dE0fG4hI8jK2lM5nO9pQ1rS4tU7vW0xY3zA6b
ADMIN_PASSWORD=flux_admin_2026!
REDIS_URL=redis://localhost:6379/0
FPX_SECRET=not_the_real_secret_haha
ERLANG_COOKIE=monster
```

**判读**：`f4ke_p4ss` / `not_the_real_secret_haha` / `monster`（Erlang 教程默认 cookie）
⇒ 这是**诱饵**。但它的字段结构恰好覆盖 5 条 vulns 的**全部前置**：
`ERLANG_COOKIE`→distribution RCE(=Code.eval_string)、`FPX_SECRET`→XOR 密钥、
`ADMIN_PASSWORD`→admin 面、`DATABASE_URL`→SQLi。
⇒ 作者设计的是**全链**，而 HTTP 侧只部署了 mock。

**它不是静态目录**：`/%2e%2e/.env` → 404、`..%2f..%2fflag` → 404、其它全部点文件 → 404
⇒ 是**显式硬编码路由**，**无路径穿越**，别指望任意文件读。

## 2. 全部真实路由 = 5 个（这是本题最硬的负结果）

| 路由 | 行为 |
|---|---|
| `GET /` | 200，2921B 静态 HTML |
| `GET /api/v1/health` | 200，229B（`uptime_seconds` 变，其余恒定） |
| `GET /api/v1/pipelines` | 200，546B，恒定 5 条 |
| 任意方法 `/graphql` | 200，**恒定 183B 静态桩**（连 OPTIONS/HEAD 也是） |
| `GET /.env` | 200，274B（上表） |

**其余 ~285 条候选全部 404 且 body 恰为 `{"error":"Not found"}`**（21B）。

## 3. 负结果矩阵（按假设分组，全部有原始日志 `work/12062b/ev/stage-*.log`）

| 组 | 假设 | 条数 | 结果 |
|---|---|---|---|
| A | 根页 4 张功能卡的**裸资源名**（rules/transforms/metrics/alerts/policies/sandbox） | 8 | 全 404 ⇒ **假设证伪**，功能卡是纯装饰文案 |
| D | 漏洞#2 Debug 端点 + ETS（`/api/v1/debug`、`/debug`、`/ets`、`/debug/ets`…） | 5 | 全 404 |
| — | 内省类（state/config/introspect/system/version/flag/admin/internal） | 12 | 全 404 |
| B | **方法面**：OPTIONS/HEAD 的 Allow 头 | 6 | `/graphql` 任意方法都 200 桩；`pipelines` 的 HEAD/OPTIONS 是 404（`Plug.Router` 的 `get` 只匹配 GET） |
| B | **GraphQL 真 query document**（旧代理只测过参数名，这是真空缺） | 7 | **恒 183B 桩**；仅 `Content-Type: application/graphql` → 500（Plug.Parsers 拦的）⇒ 确证纯静态 |
| C | 版本/前缀/大小写（`/api/v2`、`/v1`、裸 `/pipelines`、`/api/v1/Pipelines`…） | 7 | 全 404（尾斜杠 `pipelines/` 同 200 同内容） |
| C | **health 的 verbose 模式**（`?full=1`/`?verbose`/`?debug`/`?all`/`?format`） | 5 | 全部 229B，**逐字节只差 uptime** ⇒ handler 忽略参数 |
| C | 裸静态文件（`/flag`、`/flag.txt`、`/robots.txt`、`/mix.exs`、`/.git/config`…） | 8 | 只有 `/.env` 200，其余全 404 |
| C | 内容协商 / 认证上下文（Accept xml|text|v2、Bearer、XHR） | 6 | 输出**逐字节相同** ⇒ 无第二视图 |
| D | 更多点文件/配置（`.env.bak/.local/.example`、`.erlang.cookie`、`docker-compose.yml`、`Dockerfile`…） | 12 | 全 404 |
| D | 路径穿越（`/../.env` 只是规整化、`%2e%2e`、`..%2f..%2fflag`） | 6 | 无穿越 |
| D | 用泄漏的 `ADMIN_PASSWORD` 开"无口令 404"的 debug 面（3 种头） | 6 | 全 404 ⇒ **不是口令门控** |
| E | 根级文件/文档（README/swagger/openapi/docs/backup.sql/dump.sql/log/k8s 探针/login…） | 31 | 全 404 |
| F | **日志/审计头 SQLi**（UA、XFF、X-Real-IP、Referer、X-Request-Id 的单引号/布尔） | 10 | 全部 200 同长度 ⇒ 无 header 注入 |
| G | **POST-only 路由**（`Plug.Router` 对方法不匹配回 404，GET 枚举会全漏） | 36 | 全 404（含 `{"command":"id"}`/`{"expression":"1+1"}` 三种 body） |
| H | 根级配置名（`/config` `/env` `/secrets` `/keys` `/fpx.conf` `/.flag` `/getflag`…） | 20 | 全 404 |
| I | **根级**裸路由（`/fpx` `/ets` `/eval` `/exec` `/ws` `/console` `/shell` `/iex` `/observer` `/cookie`…，依据是 `/.env` 挂在根） | 55 | 全 404 |
| — | GET 请求体（Plug 会解析 GET body，旧代理只测过 POST body） | 5 | 546B 不变 |
| — | 矩阵参数 `;debug=1`、`/api/v1/HEALTH`、`/?debug=1`、`Host: localhost:4000` | 4 | 无差异 |

## 4. FPX/4001：这次是**健康容器上**的独立复核（推翻"旧代理假阴"的可能）

旧代理的 "Cowboy 400" 是在容器将死时测的，可能是假阴，所以我亲自复测（原始 socket）：

| 载荷 | 回包 |
|---|---|
| `GET /api/v1/health HTTP/1.1`（对照） | `HTTP/1.1 200 OK` |
| `FPX\r\n` | `HTTP/1.1 400 Bad Request` |
| `FPX\x01\x00\x0e` | **超时无字节**（Cowboy 在等更多 HTTP 头） |
| 纯二进制 `\x00\x01\x02\x03…` | **超时无字节** |

⇒ 4000/18768 是**纯 Cowboy HTTP，无首字节分派器、无协议复用**。FPX 真的不可达。
（`problem.json` 的 vulns ③④ 在本部署无入口。）

## 5. 我的结论与一个未解的矛盾

**证据指向"这套部署是 mock/未完成构建"**：5 个静态路由 + 诱饵 `.env` + 关键服务 4001 从未映射
+ 我两次独立确认无协议复用 + `problem.json` 自己写着 `stage: pending-review`。

**未解的矛盾**：解出数 12:34 **244** → 12:54 **268**，持续上涨，说明**有人现在能解**。
两种可能：(a) 那些解出来自其它组镜像（dz/qy/gz）或更早的完整部署；
(b) 存在一个我没打到的入口。**我没有证据在 (a)(b) 之间下结论。**

## 6. 运维：这次是**唯一一次没有打爆容器**的完整跑测

~290 条请求、**单 keep-alive 连接**、0.35s 间隔、每 15 条健康检查。
对照：第一次 24~30 并发 42k 请求 → 整机 ECONNREFUSED。
**结论：本容器只惩罚"新建连接"，不惩罚 keep-alive 请求量** —— 这是本题最实用的运维事实。
最后阶段响应从 0.11s 退化到 7.2s（再回 1.1s），我按"响应变慢立即停手"的判据主动收工，未重演打爆。

## 7. 证据

`work/12062b/ev/stage-{a,b,c,d,e,f,g,h,i}.log`（每条含请求行 + 原始 body）、
`stage-*.json`（结构化，含 status/len/body）。脚本：`stage_{a..i}.py`。
