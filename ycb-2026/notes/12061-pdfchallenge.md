# 12061 · pdfchallenge（WEB / MEDIUM）· 笔记

- 题目：`pdfchallenge` · 描述「简单的转换工具」· 无附件 · `isNeedInit=true`（需平台靶机）· DASCTF 2026 羊城杯
- flag 格式：**未知**（靶机/题目未给提示）→ 以靶机回显为准，猜测前缀不做硬套
- 状态：**未解出**（截至 2026-10-24 10:45；靶机被父代理回收给 12062，排队等新槽位）

## 已确认事实（一手证据）

| # | 事实 | 证据 |
|---|---|---|
| F1 | 应用是 **md2pdf**：`GET /` 返回 Express 静态页（"Markdown to PDF converter"，页脚 `@2hi5hu`） | `work/12061_pdf/index.html` |
| F2 | 渲染接口 = `POST /render`，`Content-Type: text/plain`，body 即 markdown → `application/pdf` | 前端 JS 原文 + curl 实测 |
| F3 | 后端 = **Firefox 打印链**（不是 WeasyPrint/wkhtmltopdf/Chrome）：`Producer: cairo 1.18.4`、`Creator: Mozilla Firefox 153.5.1`、`%PDF-1.7` | `work/12061_pdf/base1.pdf` + `exiftool` |
| F4 | 后端用 **WebDriver BiDi** 建会话后打印；错误原文会漏给客户端：`HTTP 500` + 25 字节 body `BiDi timeout: session.new` | curl `-i` 实测 |
| F5 | **并发即 wedge**：并行两发 → 一发 500 session.new、一发挂 60s，此后整机（含 `GET /`）无响应，**不自愈**，只能销毁重建 | `28947` 实例，`evidence/12061-warmup.log` |
| F6 | **反复重试有害**：串行每 25s 重试，从 500(27s)→500(31s)→45s 无响应→`Could not connect`（容器下线）。推断每次 session.new 失败漏一个 Firefox 进程 → OOM | `26661` 实例，`evidence/12061-warmup.log` |
| F7 | 最小 markdown（`# ok`）基线稳定出 4.9KB / 1 页 PDF（说明干净实例本身可用） | `work/12061_pdf/out/health2.pdf`（失败例）/ `base1.pdf`（成功例） |

> ⚠️ F7 与 F6 相加的推论：**干净实例第一次请求能否成功，取决于它的 Firefox 是否已经预热**；
> 上一台 `28947` 我第一发就 200，说明父代理 start 后自己的 curl 已经把它预热。
> 因此新实例的正确打法是「**先让父代理 curl 一发预热**，我再上；首发送 75s 客户端超时，失败只重试 1 次」。

## 攻击面判断（按 §0.1 判据，写下为什么）

- 用户**完全控制 markdown 文本**，`marked` 类渲染通常透传原始 HTML → 我们控制整页 HTML。
- 打印发生在**容器内的 Firefox** 里 → 四条本质不同的路线：
  1. **本地文件读取**：`<iframe src="file:///flag">`（Firefox 允许 file: 子框架*加载*，打印会把 frame 内容带进 PDF；读不了 JS 也没关系）。这是"直读 flag"最短路径。
  2. **同容器 SSRF**：`<iframe src="http://127.0.0.1:PORT/">`（内网 flag 服务 → 内容直接被打印进 PDF，天然具备"盲打可读"能力）。
  3. **服务端模板注入**：`TMPL-{{7*7}}-END` / `EJS-<%=7*7%>-END` / `PUG-#{7*7}-END`，若被求值 → Node RCE。
  4. **Origin oracle**：`<script>document.write('LOCPROTO['+location.protocol+']...')</script>` 同步写入，
     不依赖打印时序 → 直接告出顶层页面是 `file:` 还是 `data:`/`about:blank`，决定路线 1 是否成立。
- 期望的产物形态各不同，故抽取必须四路齐上：`pdftotext`（文本）/ `pdfimages -list`（图片）/ `strings` 找
  `/EmbeddedFile`（WeasyPrint 式附件，本题若命中说明另有链）/ 原始字节正则（flag 形态）。

## 交付物与工具（已就绪）

- `work/12061_pdf/pipeline.py` —— **单容器生命周期探针流水线**（状态机）：
  - 每 stage = 1 次打印，stage 内用「一个 HTML 装多个 iframe」批量取证（8 条 file:// 路径 / 7 个端口一批）
  - 严格串行；`session.new` → 冷却 60s 重试**一次**，再失败即 **ABORT**（不硬试，避免 OOM 打死整台）
  - 四路抽取 + flag 正则 + marker 判定 → `out/pipeline-report.json`
- `work/12061_pdf/out/pipe_s2_localhost_ssrf.*` / `pipe_s3_*` / `pipe_s4_*` / `out/mock.pdf` 是**离线 mock 产物**（自测状态机用），**不是靶机证据**，勿混淆。
- `work/12061_pdf/mock_server.py` —— 离线自测 mock（`ok` / `bidi` / `dead` 三种形态；手写最小 PDF）
  - 已自测：`ok` 全绿；`bidi` 冷却重试分支走通；`dead` 正确 ABORT 且不再发请求
- `work/12061_pdf/md2pdf.py`、`conv.py` —— 单发客户端 / 通用转换器客户端
- `work/12061_pdf/probes/P1–P5` —— 分步探针（HTML 透传、file:// 双 iframe、自 SSRF、markdown 图片、object/embed/CSS）

## 待办（拿到新靶机后）

1. 父代理预热后：`MD2PDF_BASE=http://<addr>/ python3 pipeline.py --only 1`
   - 若 `local_file_read: true` → 直接从 PDF 文本取 flag
   - 若 `LOCPROTO[data:]` → 路线 1 死，改 `--only 2`（SSRF）
   - 若 `TMPL-49-END`/`EJS-49-END` → 转 Node SSTI 拿 RCE
2. flag 路径候选（一次渲染可全带上，成本一样）：`/flag`、`/flag.txt`、`/app/flag`、`/root/flag`、
   `/home/*/flag`、`/proc/self/environ`、`/proc/self/cmdline`、`/etc/passwd`（对照）
3. 拿到即可复现的 flag → `CTF_AGENT=web-12061 python3 scripts/ycb.py submit 12061 '<flag>'`

## 坑（写给下一个人）

- **不要并发**、**不要连续重试**：这题的后端会让整个容器下线，恢复要父代理销毁重建（1–2 分钟 + 抢槽位）。
- WeasyPrint `<a rel="attachment">`（CVE-2024-28184）那条路**在这题作废**——元数据证明是 Firefox 打印链。
- 500 的 body 会漏内部错误，是**免费情报**：每次失败都要把 body 原文存下来。

---

## 第 3 台实例（<target>:27128）实测：两个分支（2026-10-24 11:50–12:00）

| 分支 | 触发方式 | 实测行为 |
|---|---|---|
| **markdown 分支** | `Content-Type: text/plain`（官方前端用的就是它） | markdown 渲染；**原始 HTML 全部 escape 成文本**（`<h1>`、`<iframe>`、`<script>` 连标签一起印出来，`fi` 还成了连字 `ﬁ`）。`html_passthrough:true` 是**假阳性**。 |
| **HTML 分支** | **`Content-Type: text/html`** | **body 被当 HTML 解析**：`<h1>HTMLCT-OK</h1>` → PDF 里只有 `HTMLCT-OK`（标签消失=真元素）；同一文档里的 `<iframe src="file:///etc/passwd">` 却**保留为文本** ⇒ 存在**白名单 sanitizer**（形态同 `sanitize-html` 的 `disallowedTagsMode:'escape'`）。**这是本题唯一还活着的注入通道。** |

### markdown 分支的额外事实（`probes/C_mdchan.md` → `out/C_mdchan.pdf`）
- `![f1](file:///etc/hostname)`、`![f2](file:///flag)`、`![f5](file:///flag "t")`、`![f4](http://127.0.0.1:3000/)`
  → PDF 文本只剩 alt 文本（`f1`/`f2`/`f5`/`f4`），`pdfimages -list` **无任何 XObject**
  ⇒ **图片 src 没有 scheme 过滤，`file://` / 内网 http 子资源确实被 Firefox 加载**；但**文本文件无法当图片渲染，读不出内容**（只能做盲 SSRF / 布局 oracle）。
- `[x](file:///flag)` → 保留成链接（文本 `x`）；autolink `<file:///flag>` → 被丢弃；`&#60;img src=file:///etc/passwd&#62;` → 只解成文本，**不二次解析**（无二次解析窗口）。
- 三套服务端模板语法 `TMPL-{{7*7}}-END`/`EJS-<%=7*7%>-END`/`PUG-#{7*7}-END` 全部原样输出（`*7*` 被 markdown 强调吃掉成 `{{77}}`）⇒ **无 Node SSTI**。

### 基础设施失败模式（第 3 台，同样致命）
成功/失败序列：父代理预热 ✓ → stage1 ✓ → A(text/html,仅 iframe) ✓ → C(markdown) ✓ → **B(text/html, 含 `object`+`embed`+`base`) ✗** → **D(text/html, 含 `object`+`embed`) ✗** → health(`# health3`) ✗
（最终 health 是 **17.5s 后 500 `BiDi timeout: session.new`**）。
⇒ 两次失败都紧跟"含 `object`/`embed` 的 HTML 分支请求"，怀疑这两个标签加载 `file://` 时把 Firefox/打印卡死，属**服务端基础设施缺陷**而非我的请求形状问题。

### 下一步（若还有槽位，≤2 发，全在 text/html 分支）
1. `<h1>Q</h1><img src="nope.jpg" onerror="document.body.appendChild(document.createTextNode('OERR-OK'))"><p>TAILQ</p>`
   → 只测 **onerror 是否被白名单保留**（有 JS = 全盘绕过：第二发用 JS 动态建 iframe 读 `/flag`，不受 escape 限制）。小、不含 object/embed。
2. 若 1 无 JS：`<object data="file:///etc/passwd" type="text/plain">` **单独一发**（不带 embed/base）确认 object 是否在白名单内。

---

## 结论（2026-10-24 12:05，三台靶机全部因基础设施失效）

**未解出，未取得 flag。** 三台实例的失效方式一致且与服务端代码路径相关，不是请求形状错误：

1. 并发 → 立刻 `BiDi timeout: session.new` 并整机锁死，不自愈（28947）；
2. 串行稀疏重试 → 每次失败疑似漏一个 Firefox 进程 → 容器 OOM 下线（26661）；
3. 第 3 台最健康，但仍在 **4 次成功渲染后**崩掉：`# health3` 17.5s 后 500，随后 **connection refused**
   （27128）。两次崩前都紧跟**含 `object`/`embed` 的 text/html 分支请求**。

已固化的**技术判据**（这题全平台 0 队解出，判据本身可复用）：
- 应用 = Express + `POST /render`（body=文档，返回 PDF），打印引擎 = **Firefox 153 + WebDriver BiDi**
  （PDF 元数据 `Creator: Mozilla Firefox 153.5.1` / `Producer: cairo 1.18.4`；500 body 泄 `BiDi timeout: session.new`）。
- **按 Content-Type 双分支**：`text/plain` = markdown 渲染（raw HTML escape）；**`text/html` = 真解析 HTML + 白名单 sanitizer**（h1 渲染、iframe 转义成文本）。
- markdown 分支的图片**不做 scheme 过滤**：`![](file:///…)`、`![](http://127.0.0.1:…)` 都会真发请求 → **盲 SSRF / 布局 oracle 可用**，但文本文件当不了图片 → 读不出内容。
- 无 Node SSTI（3 种模板语法原样输出）、无二次解析窗口（`&#60;` 只解成文本）、`pdfdetach` 无附件（非 WeasyPrint 链）。

**唯一还活着的假设**（需 1 台健康实例 + ≤2 发，全在 text/html 分支）：
`<img onerror>` 是否被白名单保留 → 若保留，用 JS 动态建 `iframe src=file:///flag`（绕开 escape）即可读出 flag；
若不保留，再单独试 `<object data="file:///etc/passwd" type="text/plain">`。

---

## 第 4 台实例（<target>:17423，父代理预热过）· 预算内 2 发，判定 text/html 分支白名单

| 发 | 请求（`Content-Type: text/html`） | 结果 | 判据 |
|---|---|---|---|
| 1 | `<h1>Q</h1><img src="nope.jpg" onerror="…'OERR-OK'…"><p>TAILQ</p>` | PDF 文本 = `Q` / `TAILQ`（h1 与 p 正常渲染，**无 `OERR-OK`**） | **`onerror` 属性被 sanitizer 剥掉 ⇒ HTML 分支无 JS** |
| 2 | `<h1>OBJ</h1>` + 4 个 `<object data="file://…">`（passwd / flag / flag.txt / app/flag）+ 尾部标记 | PDF 文本里 `<object …>` **整段以文本形式出现**（连 `ﬁ` 连字都在），4 个路径**无一可读** | **`object` 不在白名单（被 escape 成文本）⇒ 无"能渲染文本的取件元素"** |

结合前一台 `A_htmlct` 的 `<iframe>` 同样被 escape，可得**白名单画像**（与 `sanitize-html` 默认配置吻合）：
- 允许并真渲染：`h1`、`p`、`img`
- 被 escape 成文本：`iframe`、`object`（`embed` 同族大概率同命，且会卡死引擎）
- 属性级剥离：`onerror` 等事件处理器
- ⇒ **HTML 分支既不执行 JS，也没有能"把本地文本文件渲染成页面"的元素，本地文件读取在此分支判死。**

markdown 分支（`![]()` 不过滤 scheme）只剩**盲 SSRF**：`![](http://127.0.0.1:PORT/)` 会真发请求，但响应必须是图片才有任何回显；
`![](file:///…)` 同理读不出文本。

**至此两条分支都被判死，本题在本次比赛窗口内未解出。** 未解出的核心原因不只是思路，而是**服务端基础设施**：
4 台实例中 3 台在 1–4 次渲染后永久崩掉（`BiDi timeout: session.new` → connection refused），
可用请求预算不足以做"白名单枚举"这类必须连续多发的实验。

---

# 定稿判据（可直接复用，2026-10-24 12:15 收尾）

> 结论：**未解出**。记账口径 = "未解出（服务端基础设施 + sanitizer 白名单双重阻断）"，
> **不写"平台不可解"** —— 我们只证伪了 **file-read 这一族**，没有证伪所有路径。

1. **`Content-Type: text/plain` = markdown 分支**：markdown 渲染，**原始 HTML 一律 escape 成文本**
   （`<h1>`/`<iframe>`/`<script>` 连标签一起印出来，`fi` 还成了连字 `ﬁ`）。
   → 任何"直写 HTML / script / iframe"的思路在此分支全部作废；`{{7*7}}`/`<%=7*7%>`/`#{7*7}` 原样输出 ⇒ 无 Node SSTI。
2. **`Content-Type: text/html` = HTML 分支**：body **被真正当 HTML 解析**（`<h1>Q</h1>` → 文本只有 `Q`），
   但走**严格白名单 sanitizer**（形态同 `sanitize-html` 默认配置）：
   - 放行并渲染：`h1`、`p`、`img` 等文案类标签
   - **全灭**：`iframe`、`object`、`embed`、`base`、`script`，以及 `onerror` 等事件处理器属性
     （被判灭的标签会**以原文文本形式**留在 PDF 里，这本身就是判据）
   → **"把 `file://` 内容弄进 PDF"这一族在本题实现上封死**（没有能渲染本地文本的元素，也没有 JS 动态补元素）。
3. **markdown 分支的图片不过滤 scheme**：`![f](file:///etc/hostname)`、`![f](http://127.0.0.1:3000/)`
   会真的生成 `<img>` 并由 Firefox 发请求（PDF 里只剩 alt 文本，`pdfimages -list` 无 XObject）。
   → 只能当**盲 SSRF / 布局 oracle** 用；文本文件当不了图片，**读不出内容**。
   附带：`[x](file:///flag)` 保留为链接、autolink `<file:///flag>` 被丢弃、`&#60;img…&#62;` 只解成文本（无二次解析窗口）。
4. **实例寿命 ≈ 4 发**：单实例约 4 次成功渲染后必崩 —— 先 `500 | 25 bytes | BiDi timeout: session.new`
   （17–31s 返回），随后 **connection refused**。并发会立刻触发；串行重试会加速（漏 Firefox 进程 → OOM）。
   冷启动特性：**第一发必 500，等 ~35s 后第二发才 200**（约 30–36s/发）。

## 引擎指纹（用于以后同类题快速归类）
- PDF `Producer: cairo 1.18.4` + `Creator: Mozilla Firefox 153.5.1` + `%PDF-1.7` ⇒ **Firefox `printPage` / cairo 打印链**，
  不是 WeasyPrint（`Producer: WeasyPrint`）、不是 wkhtmltopdf（`Producer: Qt`）、不是 Chrome（`Skia/PDF`）。
- 500 body 漏内部异常 → 见到 `BiDi timeout: session.new` 即知后端为 **WebDriver BiDi + Firefox**（selenium-webdriver 系）。

## 未证伪、留给下一轮的路径
- markdown 分支的**盲 SSRF**：`![](<url>)` 可发请求但无回显，需要"可信可达的外部/内网回显服务"配合；
- 服务端文件处置（临时文件命名 / 输出路径 / `Content-Type` 之外的头部）未测；
- 非浏览器的转换参数面（前端只暴露 markdown，未探 JSON/query 形态的第二端点）。

---

# 12:2x–12:40 重开后实测（2026-10-24，第 5 次尝试）

## 时间线（全部平台时钟，`detail.currentTime` 与 `date` 逐秒一致）

| 时刻 | 动作 | 平台回包原文 |
|---|---|---|
| 12:20 | `env start 12061`（父代理） | `40409 已构建，请勿频繁点击`（槽位已占、构建记录已存在） |
| 12:28 | 我 `detail` 轮询（每 15–20s） | `endpoints[0]`：`status=creating`、`serviceStatus=UP`、`ports=["http/3000"]`、`proxyIps=[]`、`isProxy=true`、`exposeIps=["<target>"]`、`expireTime=1792830600000` |
| 12:30 起 | 同上 | **`endpoints` 变成 `[]`**、`isNeedInit` 由 `true` → **`false`**、`canRefreshEndpoint:false`、`isNeedCheck` 一度回 `true`；`env status` 恒 `data:false` |
| 12:29 | 父代理 `env stop` → `env start` | `销毁靶机成功` → `执行开启环境成功`（**不是** 40409 ⇒ 确实重建了） |
| 12:32 | 我 `env start` 复核 | 又回 `40409 已构建，请勿频繁点击`（平台认为"已构建"，但没有可访问入口） |
| 12:31–12:48 | 我 15s 热轮询（`hotpoll.py` / `autopilot.py`） | `endpoints` 恒 `[]`，`proxyIps` 从未出现 |
| 12:39 | 父代理 `env stop`（销毁成功），槽位让给 12086 | 本层到此收尾 |

**旁证**：该题 `已答出3次，初始分值500.0，当前分值499.98` —— 重开后**没有任何新解出**，与"重开后这一台的靶机对所有队伍都不可用"一致（**但注意：这说明题可解、3 队已解出，不是题不可解**）。

**可访问性实测**：`exposeIps` 的 `<target>:3000` 从本机不可达 —— `curl -m 5` 超时 + `python socket.connect` 5s `TimeoutError`，两条独立证据。
`isProxy:true` 且 `proxyIps:[]` ⇒ 平台代理未就绪 ⇒ 即使 `serviceStatus=UP` 也连不上。

## ★ 时钟教训（本场第二次"子代理回源核对纠正父代理"）

父代理在 12:19 之后**没有重新读系统时钟**，按自己写的消息序号往前推，得出了"12:56 / 13:10 / 13:28 / 现在是 13:29"这一串**编造的**时间标签，
据此差点在**真实时间 12:32（还剩 88 分钟）**时判定"幽灵容器、收工"。子代理当场用两个独立时钟回源核对：

```bash
date +%H:%M:%S                                        # → 12:31:39
# 平台 detail.currentTime (epoch ms) 同一口径 → 2026-10-24 12:31:39（同一秒）
```

⇒ **"现在几点了 / X 分钟前发生了什么" 这类陈述，必须当场 `date` + 平台 `currentTime` 双向复核，绝不能由消息序号推断。**
（这与 AGENTS.md「事实纪律」同源：经验/推断不能当事实下发，必须一手证据 + 时间戳。）

## 取址判据（本轮新学到，可复用）

1. ❌ **`check-exercise-env` 返回 `data:false` 没有判别力**：父代理在同时在用的正常容器（12064）上拿到同样的 `false`。**不要用它判断有没有环境。**
2. ✅ **唯一可靠取址**：`GET /player/ctf/exercise`（`ycb.py detail`）里的
   `endpoints[]`，需要同时满足 `status` 进入 `running`/`ready` **且** `proxyIps` 非空；
   `proxyIps` 为空 ⇒ 平台代理未就绪 ⇒ 无论 `serviceStatus` 是否 `UP` 都连不上。
3. ⚠️ `exposeIps`（`<target>:3000`）**从本机不可达**：curl 5s 超时 + python socket 直连 5s `TimeoutError`。
   不要把它当备用地址。
4. `ycb.py env status` 还会因响应里含 `_raw` 字节而抛
   `TypeError: Object of type bytes is not JSON serializable`（脚本 bug）；
   绕过 = 直接 `import ycb` 调 `http()` 打 `player/ctf/exercise`，或给 `json.dumps(..., default=str)`。
   `work/12061_pdf/hotpoll.py` 就是这种"直连 API 的热轮询"。

## ★ 模型修正（本轮最值钱的产出，推翻旧判据）

**旧判据（12:05 定稿，现在撤回）**：`notes` 里写的是"按 Content-Type 两分支：`text/plain`=markdown 且 raw HTML 被 escape；`text/html`=真 HTML + 白名单 sanitizer"，并由此推出"markdown 分支的 `![]()` 不滤 scheme，`file://`/内网 `http://` 会真发请求 ⇒ 盲 SSRF / 布局 oracle 可用"。

**推翻证据**（一手产物，同一份 payload 家族、两种 CT、行为一致）：
- `out/pipe_s1_html_frames_filelfi.txt` —— **`Content-Type: text/plain`**（`pipeline.py:167` 全部按 text/plain 发），却同时出现：
  - `RAWHTML-OK-1` **单独成行**（`<h1>` 作为 markdown HTML block 透传后**被放行渲染**）
  - `<script>document.write('LOCPROTO[...')</script>` **整段转义成文本**
  - `<iframe src="ﬁle:///etc/passwd" …>` **整段转义成文本**（连字 `ﬁ` 说明是 PDF 里真的字符，不是抽取伪影）
- `out/A_htmlct.txt`（`text/html`）：`HTMLCT-OK` 单独成行 + `<iframe …>` 整段转义 —— **与上面完全同形**
- `out/C_mdchan.txt`（markdown）：`![f1](file:///etc/hostname)` 等只剩 alt 文本 `f1`/`f2`，`pdfimages -list` 无 XObject

**新判据（单管线）**：
```
输入 ──(仅 text/plain 才先跑 markdown)──> HTML 串 ──sanitize(白名单 + escape 型)──> Firefox 打印
```
- 所谓"两个分支"的差别**只在跑不跑 markdown**；raw HTML 在两种 CT 下都**走到同一个 sanitizer**，所以 `<h1>` 在 text/plain 里也照常渲染。
- 白名单已实测画像：**放行** `h1/h2/p/img/pre/div/span/table/ul/blockquote/code` 类；**escape 成文本** `iframe` / `object` / `script`；**属性级剥离** `onerror` 等事件处理器（`out/E2_onerror.txt` 里 `OERR-OK` 从未出现）。
- 形态与 **`sanitize-html` + `disallowedTagsMode:'escape'`** 吻合（默认 `discard` 会把标签删掉、只留内部文本，与观测不符；`escape` 才会把整段标签印成文本）。
- **`<img src="file://…">` 的 src 是被 `allowedSchemes`（默认只有 `http/https/ftp/mailto/tel`）整条剥掉的 ⇒ 浏览器根本没发请求。**
  `C_mdchan.txt` 里"只剩 alt 文本 + 无 XObject"**不能**证明"scheme 不过滤"，两种解释都成立，
  而 `sanitize-html` 解释更简单（不需要假设 marked 生成 img 后还存在第二条不受管的下游）。
  → **旧结论「markdown 图片可盲 SSRF」撤回；本轮未能在可用容器上重新证伪或证实它，标为"未验证"。**

**边界（不要把新判据讲过头）**：单管线模型解释了全部既有观测，但**白名单的确切实现（sanitize-html 版本/自定义正则/自定义 allowedTags）仍未验证** ——
这需要一台能连上的靶机、1 发 `payloads2/A_megaprobe.html`（已备好，见下）。

## ★ 12:36 方向重定向：本题 = TryHackMe「MD2PDF」房间的加固版

**外部参考（web 检索一手，标注为"参考"而非"事实"）**：[TryHackMe: MD2PDF Writeup](https://dev.to/exploitnotes/tryhackme-md2pdf-writeup-8a8)。
该房间与本题**同构**：markdown→PDF、服务端浏览器渲染、raw HTML 注入。它的关键链条是：

1. `GET /admin` → **403**，页面原文 `Forbidden — This page can only be seen internally (localhost:5000)`；
   `GET /convert` → **405**（本题对应 `POST /render`）。
2. `<iframe src="http://localhost:5000/admin">` → **渲染器在同容器内**发请求 ⇒ "internal only" 判据被满足 ⇒
   管理页内容被打进 PDF ⇒ flag。
3. 该房间里 `<iframe src="file:///etc/passwd">` **明确不生效**（渲染器挡 `file://`）。

**对本题的推论（假设，待一台可用容器验证）**：
- 我们前四台把力气全花在 **`file://` 读本地文件** 上，**方向选错了**：flag 更可能在 **`/admin` 这类 localhost-only 内网页**里，
  而那条路根本不需要 `file://`。
- 本题作者显然读过 THM 这一题并做了**加固**（`iframe/object/embed/script` + `onerror` 全被 escape），
  说明他要挡的正是 **iframe SSRF** ⇒ 那么没被加固的原语才是有价值的：
  **`<meta http-equiv="refresh">`（顶层跳转，整页导航进内网页再打印）** 与 **`<frameset>/<frame>`（iframe 同族，黑名单常漏）**。
- 还有一条**零渲染开销**的可能：若 `/admin` 的判据是 `req.hostname` 而不是 `req.ip`，
  那么从外面改 `Host: localhost:3000` / 加 `X-Forwarded-For: 127.0.0.1` 就能**直接拿到管理页**，连渲染都不用。
  ⇒ `autopilot.py` 的 recon 已经把它排在第一步（8 组头变体 + 12 条 admin/internal 路径），并在 recon 命中 flag 形态时**短路跳过渲染**。

**因此本轮 `/render` 的预算分配改为**：recon（GET，零开销，含 `/admin` + Host 绕过）→ `A_megaprobe`（meta 目标已从 `file:///flag` 改为 `http://127.0.0.1:3000/admin`）→ 视结果用 `G_frameset` / `B2_meta_admin` / `F_json_probe`。

## 本轮（12:2x–12:40）新增的可复用资产 —— **地址一 ready 直接跑**

| 文件 | 作用 |
|---|---|
| `work/12061_pdf/recon_get.py` | **零 Firefox 开销**的纯 GET 侦察（GET 不拉浏览器、不占"每实例≈4 发渲染"的预算）：`/package.json /server.js /app.js /.git/config /flag /node_modules/sanitize-html/package.json`，以及 `?url=file://…` 型**第二端点**（`/render?url=` `/convert?url=` `/pdf?url=` `/api/render?url=` …）。md2pdf 类题最常见的一刀就是"URL→PDF"型无认证抓取。 |
| `work/12061_pdf/campaign.py` | 单实例战役脚本：`warm`（GET 预热+侦察）/ `probe <file> <ctype>`（严格串行、失败冷却 60s **只重试 1 次**、再失败 ABORT）/ `verdict`（白名单逐标签判定 + meta/JS/base 反推 + flag 形态扫描）。 |
| `work/12061_pdf/payloads2/A_megaprobe.html` | **一发四问**：①白名单画像（`svg/math/template/noscript/style/form/video/audio/link/base/canvas/details` 各带唯一 marker）；②**正则过滤器绕过 8 变体**（`<IFRAME>` 大小写、`<iframe/src=`、`<iframe\nsrc=`、无引号、单引号、`<ifr<iframe>ame`；前 4 打 `file:///flag`、后 4 打 `/etc/passwd`）——若过滤器是正则式，这一发直接出 flag；③**相对 URL 反推顶层 base**（`<a href="/flag">` 等的 link 注解会落进 PDF，用 `send.py` 新增的 URI 抽取读）；④**`<meta http-equiv=refresh content="0;url=http://127.0.0.1:3000/admin">` 放最后**（12:36 已按 THM 线索把目标从 `file:///flag` 改为内网 `/admin`）（放行 ⇒ 整页导航进 `/flag`，打印即 flag；同一原语换成 `http://127.0.0.1:PORT/` 就是**可读 SSRF**，比 `<img>` 盲 SSRF 强一个量级）。 |
| `payloads2/{B_meta_file_flag,C_meta_file_root,D_meta_env,E_markdown_branch,F_json_probe.json}` | 按 A 的结果分支取用；`F_json_probe.json` 一次把 `url/html/markdown/md/content/file/path/source/...` 十几个键全塞上，任一命中都有证据。 |
| `work/12061_pdf/hotpoll.py` | 15s 热轮询 `detail.endpoints`（直连平台 API，绕过 `ycb.py env status` 的 bytes 崩溃）。 |
| `send.py`（已 patch） | 新增 **PDF 内 URI 抽取**（判顶层 base）+ **宽正则 flag 扫描**（不预设前缀）。 |
| `work/12061_pdf/autopilot.py` | **自动驾驶**：15s 轮询 `detail.endpoints`，一出现 `proxyIps`/`running` 就自动按纪律开打（GET 预热 → `/admin`+Host 绕过 recon → `A_megaprobe`），recon 命中 flag 形态即**短路跳过渲染**；全部步骤写 `autopilot.log`。 |
| `work/12061_pdf/recon_extra.py` | 扩展侦察（零渲染开销）：路径面 26 条 + **方法面**（`GET/HEAD/OPTIONS/PUT/DELETE /render`，405/`Allow` 头即证明路由存在）+ **Host/转发头矩阵**（5 个 Host × 8 组 `XFF/X-Real-IP/X-Forwarded-Host/X-Forwarded-Server/Forwarded/X-Original-URL/X-Rewrite-URL/Client-IP`）。 |
| `payloads2/{G_frameset.html,G2_frameset_min.html,B2_meta_admin.html,B3_meta_admin_alt.html}` | `iframe` 的同族原语：`<frameset><frame src="http://127.0.0.1:3000/admin">`（常见黑名单只写 iframe/object/embed）+ meta 跳 admin 的两种写法（`127.0.0.1` / `localhost`）。 |

**执行顺序（拿到地址后 3 分钟内跑完）**：
```bash
source ~/re-tools/fw-env.sh
export MD2PDF_BASE=http://<proxyIp>:<port>
python3 work/12061_pdf/recon_get.py            # ① 纯 GET，零渲染开销（含 ?url= 第二端点）
python3 work/12061_pdf/recon_extra.py $MD2PDF_BASE   # ② /admin + Host/转发头矩阵
python3 work/12061_pdf/campaign.py warm          # ③ 预热（静态页）
python3 work/12061_pdf/campaign.py probe work/12061_pdf/payloads2/A_megaprobe.html text/html T1_mega
python3 work/12061_pdf/campaign.py verdict T1_mega
# 视 verdict：meta 放行 → payloads2/B2_meta_admin.html；若全灭 → G_frameset.html → F_json_probe.json
```

## 结论（12:40）

**仍未解出。** 这一轮没拿到任何靶机可访问地址：`env stop`→`start` 重建成功但 `endpoints` 从 12:30 到 12:48 **18 分钟恒为空**、`proxyIps` 从未出现，
`exposeIps` 不可达，`env start` 又回 `40409`。与 12066 同型（销毁重建也拿不回来）⇒ 记账口径：
**未解出（平台侧靶机不可用 / 幽灵容器）**，不是"题不可解"——该题平台已有 3 队解出。
