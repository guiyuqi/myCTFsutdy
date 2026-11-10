# 12064 · DataPulse（WEB / HARD / 500）— 未解出

> 状态：**未拿到 flag**（全平台 0 队解出）。靶机 `<target>:22179`（容器内 `nc/8000`）。
> 平台原文：`work/ch_12064/detail.json`（`attachment: []`、`endpointType=monopoly`、`isNeedInit=true`）→ **纯黑盒，无附件**。
> 所有实验产物：`work/12064_datapulse/`。

## 1. 应用测绘（全部实测，非字典猜）

- 栈：**Flask + gunicorn**（`Server: gunicorn`，404 自定义 HTML；500 是 `<p></p>` 自定义模板）。
- 认证：`POST /login/`、`/register/` 用 JSON，成功下发 `dp_session`（32 字符、**服务端会话**）+ `api_token`（64 hex）。`api_token` 实测**不能**用作任何 header（Bearer/X-API-Token/X-Api-Key 全 401）。
- 完整路由表（逐条打到、有响应体）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/` `/login/` `/register/` `/logout/` `/dashboard/` | 服务端渲染 HTML |
| GET/POST | `/tasks/list/` | 仅返回**自己**的任务，query 参数全被忽略 |
| POST | `/tasks/create/` | `{name,type,parameters,webhook_url}`，返回服务端生成的 UUID |
| GET | `/tasks/<uuid:>/` | 任务详情（`parameters`/`result_summary`/`webhook_url`） |
| POST | `/tasks/<uuid:>/retry-webhook/` | body `{"url":...}` → **SSRF 点**；task 必须已配 webhook_url，否则 `No webhook URL configured` |
| GET | `/tasks/<uuid:>/webhook-logs/` | 回显 `{url,status_code,response_body,error,created_at}` |
| GET | `/api/v1/status/` | `components: web/task_queue/cache healthy`（无鉴权） |
| GET/POST | `/api/v1/profile/` | 会话鉴权；返回 `username/email/role/api_token` |
| ANY | `/api/v1/admin/` | **403 诱饵**（见 §3.1） |
| GET | `/api/v1/export/` | **503 诱饵**（见 §3.2） |

任务类型只有三种：`csv_analysis`（rows/columns/headers/sample）、`statistics`（count/mean/min/max/sum）、`aggregation`（需 JSON data，返回 record_count/type）。`Invalid task type` 拦掉 10 个猜测类型（flag/debug/cache/admin/exec/shell/system/health/internal/stats）。

## 2. 真突破：**完整回显型 SSRF**

`POST /tasks/<id>/retry-webhook/ {"url":"<X>"}` 由**服务端**发起请求，结果（含 `response_body`）原样落进 webhook-logs。

- 校验：host 与 `{127.0.0.1, localhost, 0.0.0.0}` **精确匹配**才拦；scheme 只放 **http/https**（`file:`/`ftp:`/`data:`/`FILE:` 全 400 `Invalid webhook URL`；`HTTP:` 大写可行）。
- **可用绕过（实测 200 + 回显）**：`127.1` · `2130706433` · `0x7f000001` · `127.0.0.1.nip.io` · `[::ffff:127.0.0.1]`。
- 出网可用：`https://httpbin.org/post` 回显证明 hook 是 **POST**、UA `DataPulse-Webhook/2.4`、body `{"task_id","status","result"}`（`retry` 与 worker 自动投递同一个 UA）。
- 传输库是 **urllib**（错误串 `<urlopen error ...>` / `HTTP Error 404: Not Found`）⇒ 无 gopher，CRLF 被 `http.client` 拒绝 ⇒ **Redis 不可达**。
- 自定义 header/method 完全不生效：`{"headers":{...}}` 被忽略；`{"method":"GET"}` 打 `httpbin.org/get` 仍 **405**。

## 3. 两个诱饵（都已用对照实验否证，别再走）

### 3.1 `/api/v1/admin/` — IP 白名单诱饵
```
403 {"error":"Access denied","detail":"Your IP is not in the admin whitelist. Contact system administrator.",
     "required_role":"platform_admin","whitelist_check":"failed"}
```
- **关键否证实验**：从服务端自己发起 SSRF 打 `http://127.1:8000/api/v1/admin/`（remote_addr 必为 127.0.0.1）→ **仍然 403**；同一 task 打 `/api/v1/status/` → 200 ⇒ 白名单**不含 loopback**。
  故"SSRF 天然过白名单"这个假设**不成立**（父代理假设，实测推翻）。
- 已排除：XFF/X-Real-IP 伪造、`[::ffff:127.0.0.1]`、经公网代理回环、方法变换(POST/PUT/DELETE/OPTIONS)、`?_method=GET&ip=127.0.0.1`、`/api/v1/admin/flag`→404、注册 `username=admin`（成功但 role 仍 `analyst`）、`/api/v1/profile/` PATCH 全字段 `role/is_admin/is_staff/permissions/groups/whitelist/ip/trusted_ips` 全部无效。
- 判决：**静态 403 诱饵**（任何输入返回同一 172B body）。

### 3.2 `/api/v1/export/?filename=&format=csv|json|xlsx` — 503 诱饵
- 合法文件名 → 恒定 `503 export worker is being upgraded, retry_after 3600`（`flag.csv`/`report_2024.csv` 一致）。
- 路径穿越/绝对路径/无扩展名 → `400 Invalid filename format`。实测绕过全都 400：`../flag.csv`、`..%2fflag.csv`、`%2e%2e%2f`、`....//`、`flag.csv/.`、`flag.CSV`、`flag.csv.`、`flag.csv%00.png`、全角 `／`、重复参数 `filename=a.csv&filename=../flag.csv`、`filename[]`。
- 注意：**扫描/卡死期间**出现的 ReadTimeout 是**单 worker 被我自己打满**造成的假象，干净状态下同一 payload 秒回 400 —— 不要当"穿越成功"。

## 4. 内部面

- `127.0.0.1:8000`(Flask) + `127.0.0.1:6379`(**Redis**，"Remote end closed connection without response"=端口通) 是唯一两个监听；15 个常见端口 + `172.17/172.18/172.19/10.0.x` 全 `Connection refused`；`worker/redis/admin/api/backend/db/postgres/queue/rabbitmq/cache/...` 全部 DNS `Name or service not known` ⇒ **单容器**。
- `/tasks/list/`、`/api/v1/profile/` 从 SSRF 打 → **401**（内部无鉴权捷径）；`/dashboard/` → 302 到登录页。
- Redis 无法用 urllib 触达（无 gopher；HTTP 请求行 `POST ...` 也不是合法 RESP/inline 命令；body 是 JSON 转义过的，注入不进换行）。

## 5. 已排除的其余方向

- 任务字段命令注入：name/parameters 塞 `;id` `$(id)` `` `id` `` `|id` `&&id` → result 里**无 uid=/gid=**，纯字面量（`csv_analysis` 把头行原样回显）。
- SQLi：login 用户名、task name 单引号/`OR 1=1--`/`DROP TABLE` 全部正常落库，无报错无差异。
- XSS/SSTI：用户名 `{{7*7}}` 注册后在 dashboard **原样输出**（不渲染）。
- IDOR：`/tasks/<uuid>/` 跨用户 `Task not found`；`?user_id=1`、`?impersonate=1`、`X-User-Id` 头全被忽略；非 UUID 直接 404（路由是 uuid converter）。
- 客户端注入 task_id/status/result/user_id（mass assignment）无效：服务端自生成 UUID。
- 源码/配置路径 `/app.py /main.py /wsgi.py /requirements.txt /.env /.git/config /static/` 全 404（无 static 路由）。
- `/api/v1/{cache,queue,worker,webhook,users,me,tasks,system,debug,logs,metrics,health,flag}` 全 404。

## 6. 结论 / 卡点

**漏洞已确证且可复现：完整回显型 SSRF（webhook URL 黑名单精确匹配绕过）。** 但 SSRF 的落点全是诱饵：admin 的 IP 白名单不含任何可达地址（连 loopback 都被拒），export 恒定 503，Redis 因后端是 urllib 而无法上 gopher/RESP，容器内无第二服务、无其他 vhost/域名。

**BLOCKED：** 需要 (a) 容器内的非 HTTP 出网能力（gopher/dict）以打 6379 Redis；或 (b) 出题人确认 admin/export 是否就是这样设计的（若 admin 白名单里本应含 127.0.0.1，则是部署 bug）；或 (c) 源码/附件。

## 7. 可复用资产

- `work/12064_datapulse/ssrf.sh` —— 单次 SSRF（retry-webhook）并解析回显
- `work/12064_datapulse/task.py` —— 建任务 + 轮询 webhook 日志 + 从 httpbin 回显解码 worker 的 `result`
- `work/12064_datapulse/scan_ports.py` —— 串行端口探测（用 SSRF 当 oracle）
- `work/12064_datapulse/probe.py` —— 首轮侦察（限速、40 请求上限）

---

# 追加（13:40–14:48，新容器 `<target>:28731`）：**真链 = gopher SSRF → Redis**

## ★ 必须先纠错：我上一版的"无 gopher"判据是错的

上一版我根据 **urllib 的错误串**（`<urlopen error ...>` / `HTTP Error 404: Not Found`）推断"后端是 urllib ⇒ 不支持 gopher"。
**这条推断不成立**：错误串只能说明*错误类型*来自 urllib 风格，不能说明 **scheme 支持集**。
实测：校验器放行 **http / https / gopher**（`file`/`ftp`/`dict`/`data` 仍 400 `Invalid webhook URL`），
而投递端**真的能发 gopher**：

```
{"url":"gopher://127.1:6379/_PING%0d%0a"}  ->  {"status_code":200,"response_body":"+PONG\r\n"}
```

**教训**：判"某库不支持 X scheme"必须直接打一次，不能从错误消息风格反推。

## Redis 全权限（工具：`work/12064_datapulse/redis.py`）

`gopher://127.1:6379/_<percent-encoded RESP or inline>`，响应体原样回显 ⇒ 等于一个 **Redis 客户端**。
注意：每次 retry-webhook 是**新连接**，多命令必须在同一 payload 里用 `\r\n` 连发（`SELECT 1\r\nKEYS *\r\n`）。

已确认：

| 项 | 值 |
|---|---|
| 版本 | `redis_version:7.0.15`，`executable:/app/redis-server…` ⇒ 应用目录 `/app` |
| db0 | 25 × `celery-task-meta-<uuid>` + `_kombu.binding.celery` / `.pidbox`，**没有 flag** |
| db1 | 5 × `:1:django.contrib.sessions.cache<sid>`：**Flask 服务端会话（裸 pickle）** |
| 诱饵 | `…cachefake_admin_session_1/2` → 值是 `{user_id:771, role:'admin', _auth_user_hash:'fake_hash_do_not_use'}`；用该 cookie 打 `/api/v1/profile/` → **401 Invalid session** ⇒ 纯诱饵 |
| 禁用 | `CONFIG` 被禁用（`unknown command 'CONFIG'`）⇒ **无法 CONFIG SET dir + SAVE 写 webshell/定时任务** |

## 尝试过但未成功（给下一个打这题的人省时间）

1. **Celery pickle 注入**（`work/12064_datapulse/celery_rce.py`）：向 `celery` 列表 LPUSH 一条
   `content-type: application/x-python-serialize` + base64(pickle) 的 kombu 消息。
   结果：消息**被 worker 立刻消费**（`LLEN celery == 0`）但 **payload 未执行**（`GET pwnd` = nil）
   ⇒ worker 的 `accept_content` 是 JSON-only，反序列化前就把消息丢了。
2. **会话 pickle 投毒**（`work/12064_datapulse/session_rce.py`）：`SET :1:django.contrib.sessions.cache<sid>` 写入
   `__reduce__ = (eval, (code,))` 的值，再带 `dp_session=<sid>` 打一次。
   结果：应用确实**读了**这个键（之后请求回 **401 Authentication required**），但**代码没执行**
   （`GET pwnd` 空）⇒ 大概率是**受限 Unpickler（find_class 白名单）**，或 payload 里 `redis`/`socket` 导入失败。
   下一步应换成"只依赖 builtins、且能在 find_class 白名单内"的 gadget（例如 `builtins.getattr` 链），
   或先用 `(eval, ("{'user_id':2,'role':'analyst'}",))` 这类**返回 dict** 的 payload 验证 eval 是否真被调用。
3. 会话里的 `user_id`/`role` 字段对鉴权**无效**：改成 771/1/2/3/0 打 `/api/v1/profile/` 返回的都是同一个用户
   ⇒ 用户身份不是从这两个字段来的（`_auth_user_hash` 更可能是关键，但真实 hash 不可得）。
4. Celery 后端里没有历史任务的 flag；`_kombu.binding.celery` 只存路由键，不含任务名。

## 结论（截至 14:48）

**完整可达链已证实：webhook URL 校验绕过（`127.1`/`opaque IP`/`nip.io`）→ gopher → 127.0.0.1:6379 Redis 读写。**
差最后一步：Redis 7.0.15 且 `CONFIG` 被禁 ⇒ 没有"写文件"这一路，只能靠**反序列化**（Celery 消息 或 会话 pickle）。
flag 大概率在容器文件系统（`/flag`）或某个只有 worker/web 进程能读的位置 ⇒ 最后一步应是 RCE，
而不是继续在 HTTP 面上找端点（HTTP 面已穷尽：`/api/v1/{status,profile,admin,export}` + `/tasks/*`）。

---

# ✅ 已解出（14:5x）：会话反序列化 RCE

**FLAG**: `DASCTF{61384818490737473322962843864311}`（提交裸串 `61384818490737473322962843864311`）
**SUBMIT**: `{"code":"00000","message":"解题成功!","result":true,"data":{"isCorrect":true,"hasCheated":false,"eventId":87845,"correct":true}}`
**成品脚本**: `scripts/12064-solve.py <base_url>`（从零跑通：注册 → 建任务 → gopher → 写会话 → /readflag → 读回）

## 最后一步是怎么破的

上一节卡在"会话 pickle 投毒后 401、但代码没执行"。**关键实验**（一次请求定性）：

```
投毒 payload  = (eval, ("{'user_id':2,'role':'analyst'}",))     # eval 返回一个 dict
结果          = /api/v1/profile/ 回 200
```

⇒ **`eval` 在 `find_class` 白名单里，会话 unpickle 路径完全可控**（之前 401 是因为 payload 抛异常，不是被拦）。
立刻换成真正 payload（把 `/readflag` 的输出写进 redis，再从 gopher 通道读回）：

```python
(lambda r: r.set('flag01', __import__('subprocess')
    .check_output('/readflag', shell=True).decode()))(__import__('redis').Redis())
```

结果：`uid=1000(ctf)`；`/flag.txt` 是 `-r-------- root`（读不了），但根目录有 **setuid `-rwsr-xr-x /readflag`** → 直接出 flag。

## 一条链（最终版）

1. **SSRF 源点**：`POST /tasks/<id>/retry-webhook/ {"url": ...}`（服务端发请求，body 回显进 webhook-logs）
2. **归一化弱点**：host 只做**精确匹配** `{127.0.0.1, localhost, 0.0.0.0}`，scheme 白名单 **放行 gopher**
   → `127.1` / `2130706433` / `0x7f000001` / `127.0.0.1.nip.io` / `[::ffff:127.0.0.1]` 均可
3. **可达目标**：`127.0.0.1:6379` Redis 7.0.15（容器内唯一第二个监听）
4. **下游凭证/权限**：Redis db1 的 `:1:django.contrib.sessions.cache<sid>` 是**裸 pickle 会话**；
   全新随机 sid + 一个 pickle dict 就能被接受（实测 profile 200）→ **写 `(eval, code)` 即 RCE**
5. **落地**：`/readflag`（setuid root）

## 三个诱饵（别再走）

- `/api/v1/admin/` 403：白名单**不含 loopback**（服务端自打同样 403），role/方法/头全无效 → 静态 403
- `/api/v1/export/` 503：合法文件名恒 503，穿越一律 400 → 静态 503
- `fake_admin_session_1/2`：`_auth_user_hash: fake_hash_do_not_use` → 401 Invalid session

## 我这轮踩的三个坑（都写进判据）

1. **从错误消息风格反推库能力**：看到 `<urlopen error ...>` 就断定"urllib ⇒ 无 gopher"，实际校验器放行 gopher 且投递端能发。**判 scheme 支持必须逐 scheme 实打一次**。
2. **单 worker Flask 会被自己的扫描打爆**：`flag.csv/../../flag` 的 ReadTimeout 是负载假象，干净复测是 400。别把超时当突破。
3. **投毒后 401 ≠ 被拦**：payload 抛异常和 payload 被拦都回 401。必须用"返回合法 dict 的 payload"区分——这一步省下了一个小时。

## 复现

```bash
python3 scripts/12064-solve.py http://<proxy-ip>:<port>
# FLAG: DASCTF{61384818490737473322962843864311}
# submit content: 61384818490737473322962843864311
```
