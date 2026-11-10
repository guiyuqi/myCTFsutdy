> ⚠️ **本文是「本场平台事实」，只对 2026 第十届强网杯（线上赛）成立。**
> 下一场比赛前按同样方法重侦察：curl 首页 → 抓 `assets/*.js`（**brotli 压缩，curl 不自动解**）→
> 找 axios 拦截器 → 抓 API 宿主 / 签名算法 / 请求体字段 / 错误码 / 容器语义。
> 上游方法见 `notes/methods/platform-current.md`。

# 平台事实 · match.ichunqiu.com（第十届强网杯 · i春秋 / 奇安信）

**来源**：2026-10-30 赛前，① `assets/index.c5d0d0cc.js` 等 18 个 chunk 静态逆向
（`work/qwb-platform/`，brotli 解压后 5.1 MB）；② 匿名只读探测（`/match/detail`、`/match/question/class` 等 7 条）。
**这是赛前快照**：开赛后第一件事跑 `python3 scripts/qwb.py creds` 回源复核。

---

## 0. 一句话

**不是 CTFd，也不是 DASCTF。** API 在**独立宿主** `https://apiterminator.ichunqiu.com`，
全部 `POST` + JSON body，**每个请求带 `SIGN` 头签名**，鉴权靠 body 里的 `token`（登录态）+ `k`（比赛 key）。

```bash
cd ~/ctf-2026
source ~/re-tools/fw-env.sh
python3 scripts/qwb.py creds          # 凭据 + 连通性自检（脱敏）
python3 scripts/qwb.py detail         # 比赛详情（公开，含容器配额）
python3 scripts/qwb.py surplus        # 距开赛/剩余时间
python3 scripts/qwb.py classes        # 题目分类（公开）
python3 scripts/qwb.py list           # 题目清单（需登录）
python3 scripts/qwb.py submit <题号> '<flag>'   # 走 verify-flag 门禁
```

---

## 1. 比赛事实（2026-10-30 22:5x 实测，`/match/detail` 公开返回）

| 项 | 值 |
|---|---|
| 名称 | 第十届“强网杯”全国网络安全挑战赛 |
| 开赛 | **2026-10-31 09:00:00** |
| 结束 | **2026-11-01 12:00:00**（共 **27 小时**） |
| writeup 截止 | 2026-11-01 20:00:00（`wp_number_limit: 5`） |
| **全队容器上限** | **`team_docker_limit: 2`** ← ⚠️ 2026-10-31 **08:10 实测从 3 降为 2**；队长分配，全队只有 2 台 |
| **单人容器上限** | **`user_docker_limit: 1`** ← 每人同时只能 1 台 |
| 赛制 | `mode_type:1`、`score_type:9`（动态积分）、`plate_type:1` |
| 网络/对抗 | `is_network:2`、`red/blue` 未启用 ⇒ 纯解题制 |
| 人脸 | `face_login:2`、`face_answer:2` ⇒ **不强制**摄像头答题 |
| 游客可见 | `is_visit:true`、`is_view:1` |
| `s_source_id` | **`9FZ4dGtRk0I`** ← 登录 token 在 localStorage 里就是以它为键 |
| `view_key` / `login_class_key` | `demo` / `esports`（⇒ 前端跑的是 `demo/` 那套 view，见 §6.1） |
| 排名看板 | 解题总榜 `/situation/problems`，积分总榜 `/situation/integral` |

### 1.5 本队状态（2026-10-30 实测，`/match/team/*` 登录后返回）

| 项 | 值 |
|---|---|
| 队名 / 学校 | **<team>** / <team> |
| team_id | `AhnwK-ZcjvvCj3OD` |
| 队员数 | **7**（`/match/team/users` 的 `total`） |
| 队长标记 | `role_id: 1` |
| **platform 回的 teamtoken** | 与队长给的一致（`/match/team/info` → `data.token`） |
| 当前分数 | `total_score: 0`（未开赛） |

⇒ `qwb.py` 的 `creds` 会打「队伍 <team>」= 登录态健康的判据；
teamtoken 存在 `~/.config/ctf/creds.env` 的 `QWB_TEAMTOKEN`，**不进工作区**。

> **容器口径以平台公告为准**：`team_docker_limit=3` 是**赛前**快照值，
> 开赛前平台可能在公告里改（用户提示：看准时段的公告）。以 `qwb.py detail` 现拉的为准。

---

## 2. 鉴权（最容易卡住的地方）

| 事实 | 依据 | 影响 |
|---|---|---|
| **`__jsluid_s` 只是加速乐反爬 cookie，不是登录态** | 用户给的 curl 里唯一的 cookie 就是它 | 只有它 + `k` 只能读**公开**接口（比赛详情/分类） |
| 真实登录态 = body 里的 **`token`** | 拦截器 `e.data.token = r.user.token \|\| localStorage[s_source_id].token` | 所有题目/容器/提交接口没它一律 `code 100/114 请登录平台` |
| token 存法 | `localStorage["9FZ4dGtRk0I"]` → JSON，字段 `.token`（`HP()=JSON.parse(localStorage.getItem(id))`） | 浏览器 F12 Console 可一行取出 |
| `k` = 比赛 url_key | 地址栏 `?k=` 那串；也可从 `/match/detail` 回包 `data.url_key` 取 | `k` 给错 → `code 101 无法访问比赛` |
| 匿名 token | `/common/account_token` 返回 `not_login:<md5>` | 这是**游客**标识，调不动题目接口 |
| 人脸登录 | `face_login:2` = 关；`code 130` = 需要人脸，本场不会出现 | 见到 130 才处理 |

**token 怎么拿（两种，都不落工作区）**

```bash
# A. 浏览器里登一次，把 token 贴进来（无回显，写 ~/.config/ctf/creds.env 0600）
bash ~/ctf-2026/scripts/set-token.sh          # 若脚本支持 QWB_TOKEN 则直接复用；否则见 B
#   Console 一行：JSON.parse(localStorage["9FZ4dGtRk0I"]).token

# B. 直接写 creds.env 的 QWB_TOKEN=...（chmod 600 已设）
python3 ~/ctf-2026/scripts/qwb.py creds       # 回源验证
```

> 登录接口 `/match/login` 的 `account`/`password` 要 **XXTEA 加密后 base64url**
> （key `9633369c7144a6b2290016fc494207ff`，即前端 `Ng()`），且带 `img_code` 图形验证码
> ⇒ **不要指望脚本登录**，用浏览器登录后取 token 更省事。

---

## 3. 请求签名（已实测通过）

```python
# body 里每个请求都会补 4 个字段
d["k"]     = <比赛 url_key>
d["stamp"] = int(time()*1000)
d["token"] = <登录 token>
d["rs"]    = md5( str(时间戳) + str(random) + "icq" )       # 服务端似乎不校验，但照发
# 签名头
SIGN = sha1( "&".join(sorted(f"{k}={v}" for k,v in d.items())) + "&" + SALT )
SALT = "7637b08bdb0b29e08300a976b24ca672"
```

- 排序按**字段名**，值用原始字符串拼（布尔/数字按 JS 的 `String()` 形态）。
- `SIGN` 少了或错了会直接被网关挡（不是业务错误码）。
- `X-Lang: zh-CN` 一并带上（前端拦截器会加）。

**踩点**：`curl` 直接下 `assets/*.js` 拿到的是 **brotli 裸流**（`file` 认成 `data`），
必须 `brotli.decompress()` 才能 grep。参考 `work/qwb-platform/*.dec.js`。

---

## 4. 错误码（前端全部按 `code` 判）

| code | message | 含义 | 应对 |
|---|---|---|---|
| 0 | 操作成功 / 查询成功 | 成功 | — |
| 100 | 请登录平台 | 无 token / token 失效 | 换 token |
| 101 | 无法访问比赛 / 缺少参数 / 参数错误 / miss route | 参数或 `k` 不对，**不是** flag 错 | 查 payload |
| 114 | 请登录平台 | 未登录（题目列表） | 换 token |
| 116 | 暂无数据 / 暂无队伍信息 | 空结果（未开赛常见） | 正常 |
| 130 | — | 需要人脸认证（本场关） | 忽略 |
| 201 | **比赛未开始** | `surplus_time` 专用，`data.match_time` = 距开赛秒数 | 正常 |

---

## 5. 端点清单（payload 取自前端调用点原文）

### 公开（无 token 可调，已实测）

| 用途 | 路径 | body |
|---|---|---|
| 比赛详情 | `/match/detail` | `{url_key, is_encrypt:1}` ←**必须 `is_encrypt:1`**，否则 101 |
| 剩余时间 | `/match/surplus_time` | `{}` |
| 游客 token | `/common/account_token` | `{}` |
| 题目分类 | `/match/question/class` | `{is_hidden:0, show_num:""}` |
| 分类(另一形态) | `/match/question/category` | `{is_hidden:0, attribute:0}` |

**本场分类（公开）**：Misc / Crypto / Reverse / PWN / Web / 安全知识（id 4796–4801）。

### 需登录

| 用途 | 路径 | body |
|---|---|---|
| 题目清单 | `/match/question/lists` | `{category_id, child_id, type_ids, is_brief, page_index, page_size}` |
| 分类清单 | `/match/category/lists` | `{is_brief, is_hidden}` |
| 一血/血榜 | `/match/question/blood` | `{is_hidden}` |
| 开题记录 | `/match/question/open_record` | `{question_id}` |
| **提交 flag** | `/match/flag/submit` | 见 §6（形状未定，需实测） |
| 提交记录 | `/match/flag/submit_lists` | `{question_id, page_index, page_size}` |
| 提交详情 | `/match/flag/submit_detail` | 同上 |
| 我的队伍 | `/match/team/info` | `{}` |
| 队员 | `/match/team/users` | — |
| 队伍积分 | `/match/team/point` | — |
| 容器日志 | `/match/team/docker_log` | — |
| 动态排名 | `/match/solved_dynamic` | `{page_index, page_size}` |
| 公告 | `/match/notice/lists` | `{type:1, page_index:1, page_size:20}` ← **`type` 必填**（缺了 → 101 缺少参数）；实测匿名可调，2026-10-30 返回 `116 暂无比赛公告信息` |

### 容器（**必须走 `scripts/container-pool.py`**）

| 动作 | 路径 | body |
|---|---|---|
| 查靶机 | `/match/docker/info` | `{question_id}` |
| 申请靶机 | `/match/docker/apply` | `{question_id}` |
| 轮询进度 | `/match/docker/process` | `{uuid}` |
| 延时 | `/match/docker/delay` | `{uuid}` |
| 关闭 | `/match/docker/close` | `{uuid, close_type}` |
| 重置 | `/match/docker/reset` | — |
| 场景列表 | `/match/docker/scene_lists` | — |

> 与羊城杯相同的教训：**名额只减不增**，cap 只有 3（队）/1（人）。
> 每台用完立刻 close，并隔几分钟回查 `docker/info` 确认真的释放了。

---

## 6. ★ 提交接口的 payload 形状：**赛前实测未通，已改为「原样重放」**

### 6.1 先锁定模板：本场用 `demo` 视图集

`/match/detail` 回 `template_id:1`、`view_key:"demo"`、`login_class_key:"esports"`。
前端路由是 `import.meta.glob` 编译出的映射表，`demo/` 那套 chunk 是：

```
demo/level/components/answer.vue     → assets/answer.38a07de6.js   ← 答题页（提交按钮在这里）
demo/level/components/flagDialog.vue → assets/flagDialog.50abb487.js ← 批量 flag 弹窗
demo/level/components/checkList.vue  → assets/checkList.14b847f2.js
demo/level/index.vue                 → assets/index.c6df95d4.js
```

⇒ 我们分析的就是**本场真正在跑的**那几个文件，不是别场模板。三条提交路径（`question.854c7d16.js` 导出映射已解）：

| 前端位置 | 实际调用 | body 形状（静态推断） |
|---|---|---|
| 答题页「提交」按钮（`ot()`，`Ta` = 导出 `p`） | **`/match/red/submit`** | `{question_id, answer, img_url}`；`img_url` 无人脸时传死值 `f97fae4e1ffdb1ee3b65231aa693ea85` |
| 批量 flag 弹窗（flagDialog，`xe` = 导出 `y`） | **`/match/against/submit`** | `{answer_str: "flag1=-=-=flag2"}`（最多 100 个，`=-=-=` 分隔） |
| 直接封装（导出 `h`，本 bundle 内无人调用） | `/match/flag/submit` | 由调用方传 `t` |

### 6.2 2026-10-30 实测：字段猜不出来（记录在此，别再重试）

带登录 token、**不带任何真实 flag**（`question_id` 用 0/999999），逐条试（证据 `evidence/qwb-route-probe-20261030.txt`）：

| 请求 | 回包 |
|---|---|
| `red/submit {}` / `{question_id}` / `{question_id,answer,img_url}` / 字符串型 id / 带 `flag` 字段 | **恒 `101 缺少参数`** |
| `flag/submit {}` / `{question_id}` | **`101 请求错误`** |
| `against/submit {}` / `{question_id}` | **`101 请求错误`** |

⇒ 赛前无题、无真实提交可以参照，**静态推不出必填字段**。**停止猜**（继续变体试探既是浪费，也接近 fuzzing 边界）。

### 6.2b ★ 零消耗抓包（2026-10-31 08:2x 实测跑通无头路线）

抓包不是为了"抢开赛瞬间"——第一次真实提交通常在开赛后几十分钟到几小时，**这不是赛跑**。
关键是：**怎么抓不花提交次数**。答案是**在浏览器里把它拦住**：

```python
# Playwright：抓到就 abort，请求不出网 → 服务器不记账
ctx.route("**/apiterminator.ichunqiu.com/**", on_route)   # 命中 /match/*submit* 时 route.abort()
```

两条可用路径（都已备好）：

| 路线 | 做法 | 成本 | 备注 |
|---|---|---|---|
| **A. 我做（`scripts/qwb-capture.py`）** | 无头 Chromium + 注入登录态 + 拦截 abort | **0 次提交**，不需要人 | ★ 已实测能进登录态（见下） |
| B. 人类做（自己浏览器） | Console 贴 hook + 点一次提交 | **0 次**（hook 里 abort）/ 1 次（不 abort） | 30 秒，最稳 |

**无头注入的两个坑（实测）**：

1. **只注入 `{token}` 会掉回登录页**。路由守卫判的是 `r.user.user_id`（不是 token）：
   `r.user.user_id ? … : 去登录`。所以注入对象必须带**真值** `user_id`。
2. `user_id` 取哪个**不影响鉴权**：请求带的仍是我们 token，服务端按 `token` 认人
   （`/match/team/users` 里任取一个有 `user_id` 的成员即可；脚本自动取）。

实测结果：注入 `{token, user_id, is_admin:0}` 后，页面直接渲染「<team> / 得分 / 退出登录 / 比赛关卡 /
暂未放题，请稍等…」⇒ **无头浏览器已经是登录态**，开赛后可直接用它抓提交请求、兜题面 DOM。

> ⚠️ **Console hook 的坑（2026-10-31 实战炸过一次，记录在此）**：
> 手写 hook 时两件事必须做对，否则会 `RangeError: Maximum call stack size exceeded`：
> ① 必须同时 hook `open` 把 URL 存到实例上（否则判断恒假、永远抓不到）；
> ② `const s = XHR.prototype.send` 在**重复粘贴**时会抓到上一次的 wrapper，
>    wrapper 调 `s.apply` 就是调自己 ⇒ 无限递归，把页面所有轮询一起打挂。
> 正确写法见 **`scripts/grab-submit-hook.js`**（幂等、原始函数先存闭包、只拦 `/submit$`、
> 可 `__QWB_UNHOOK()` 卸载）。已在无头浏览器实测：拦截成功、递归 0、卸载可恢复。

```bash
cd ~/ctf-2026
pwpython scripts/qwb-capture.py --probe --dump-dom      # 验证登录态 + 打印候选选择器
pwpython scripts/qwb-capture.py --capture <题号>         # 开赛后：拦截式抓提交（零消耗）
```

> 兜底：`--dump-dom` 输出的 `inputs/buttons/cards` 现在是空的（没题目），
> 开赛后先跑它拿真实选择器；实在抓不到再让人类用 Console hook（见 §6.3）。

### 6.3 定案做法：开赛抓一次包 → 原样重放

开赛第一次提交时，浏览器 F12 → Network → 选中那个 `/match/...` 请求 → **Copy as cURL**，
存 `evidence/`，然后**原样重放**（客户端已支持，不必等我去改代码）：

```bash
python3 scripts/qwb.py submit <题号> 'flag{...}' \
    --path /match/red/submit \
    --body '{"question_id":"123","answer":"__FLAG__","img_url":"..."}'
```

- `--body` 直接作为请求体发出（`__FLAG__` 会被替换成本次 flag，方便存一份模板复用）；
- 仍然**必须**先 `verify-flag.py check` 拿票，仍然记账，仍然串行；
- 台账里 `via` 会记成 `raw:<path>`，方便赛后复盘用了哪条路径。

---

## 7. 提交纪律（沿用以太杯/羊城杯教训，未变）

1. 平台**每题有次数上限**（i春秋通常 50 次/题，队内共享）——**只有可复现 flag 才提交**。
2. `qwb.py submit` **强制**先跑
   `python3 scripts/verify-flag.py check <题号> '<flag>' --evidence <artifact> --agent <角色>` 拿一次性票，
   票绑定 flag 摘要 + 300 秒有效 + 一次性。
3. 台账 `evidence/submit-log.jsonl`（含平台原始回包），便于复盘。
4. `code 100/114/101/116` **都不是 flag 错**，别记成"题不可解"。
5. 写「不存在/不可解」前必须先看平台「已答出 N 次」（`verify-flag.py verdict`）。

---

## 8. 与上一场（羊城杯 DASCTF）的差异对照

| 维度 | 羊城杯 DASCTF | **强网杯 i春秋（本场）** |
|---|---|---|
| API 宿主 | 同源 `/slab-match/api/v1` | **独立宿主 `apiterminator.ichunqiu.com`** |
| 方法 | GET 查询 | **全 POST** |
| 鉴权 | 头 `authorization: Bearer <jwt>` + 头 `matchId` | **body `token` + body `k`** |
| 签名 | 无 | **头 `SIGN`（sha1+salt）** |
| 成功码 | `"00000"` | **`0`** |
| 容器接口 | `build/check/expire-exercise-env` | `docker/apply|info|process|close|delay` |
| 容器上限 | 4 | **2（队）/ 1（人）**（10-31 08:10 实测；昨夜曾显示 3） |
| 客户端 | `scripts/ycb.py`（本场**用不上**） | **`scripts/qwb.py`** |
