# 第六届「长城杯」网络安全大赛暨京津冀蒙网络安全技能竞赛（初赛）Writeup

> **赛事**：第六届「长城杯」网络安全大赛暨京津冀蒙网络安全技能竞赛（初赛）
> **平台**：i春秋 / 春秋云境
> **题目**：共 6 大组题（含 4-1..4-6、5-1..5-3，合计 13 个 flag），全部解出
> **flag 格式**：`flag{...}`

## 目录结构

| 路径 | 内容 |
|---|---|
| `wp-ccb2026.md` | 完整 Writeup：6 大组题逐题题解 + 成绩统计 + 复盘（2130 行） |
| `scripts/` | 从 Writeup 正文重建的完整利用脚本（8 个） |

> 本场为**应急响应/靶机类**比赛，题目靶机由平台动态下发、赛后统一回收，因此仓库内**没有题目附件**；
> 原始附件内容已内联在 Writeup 正文与 `scripts/` 的脚本中。

## 题目分类与成绩

| 分类 | 解出 / 总数 | 题目 |
|---|---|---|
| Web | 2 / 2 | OOOOOOAuth（OAuth 绑定回调归属校验缺失）、configcenter（PHP 反序列化长度错位 + `sudo tar` 提权） |
| Reverse / Pwn | 1 / 1 | ghostpatch：FGT/1.0 信道解密 → 镜像丢包修复 → patchd 堆利用 ROP |
| 应急响应 | 9 / 9 | 沉默的数据管道 4-1..4-6（6 个 flag）、workorder_defense 5-1..5-3（3 个 flag） |
| AI 应用安全 | 1 / 1 | TicketSage：元数据越权 + 检索投毒 + 间接提示注入 + 自研编码逆向 |
| **合计** | **13 / 13** | 全部解出 |

## 脚本清单

| 脚本 | 对应题目 | 作用 |
|---|---|---|
| `scripts/01-oauth-exploit.py` | 1 · OOOOOOAuth | 注册 → 取合法 state → 取 code → 诱导管理员访问回调 → 会话切到 admin → 读 flag |
| `scripts/02-configcenter-exploit.py` | 2 · configcenter | 反序列化长度错位注入 → 管理员会话 → `system()` RCE → `sudo tar` GTFOBins 提权 |
| `scripts/02-configcenter-decrypt.py` | 2 · configcenter | 还原站点自研编解码（`SITE_KEY` 异或 + 位置偏移 + base64），批量解密源码常量 |
| `scripts/03-ghostpatch-fgt.py` | 3 · ghostpatch | FGT/1.0 客户端：48-bit DH 握手 + RC4 双向流 + 分帧 |
| `scripts/03-ghostpatch-gp.py` | 3 · ghostpatch | patchd 维护控制台驱动（stage / verify / hotfix / rollback / dispatch） |
| `scripts/03-ghostpatch-pwn.py` | 3 · ghostpatch | 完整 EXP：off-by-one NUL → tcache/unlink → 任意读写 → 栈上 ROP 读 `/flag` |
| `scripts/03-ghostpatch-decode.py` | 3 · ghostpatch | 抓包解码器：按 `seq` 重排 DATA 帧 + 空洞/覆盖冲突报告 |
| `scripts/06-ticketsage-exploit.py` | 6 · TicketSage | 侦察 → 投毒 → 提示注入 → 自研编码逆向（另支持 `--decode` 离线解码） |

> 第 4、5 组（应急响应）的操作以命令与配置片段形式内联在 Writeup 正文中（判分数据读取、热修 MBean、
> 缺陷修复补丁、11 项加固处置），未单独成脚本。

## 本场特点

- **判分口径必须先读**：任务 1 问「首次被服务端成功处理（200）的漏洞请求」，任务 4 问「真正取得代码执行、完成植入的人与最早时刻」—— 同一份日志能读出两个都「看起来正确」的答案，猜错直接判错。
- **环境随时回收**：靶机由平台动态下发、空闲即回收，所有结论都要在当前实例上重新核对。
- **修复类题目的核心教训**：「不清洗 ≠ 修复」「静默清洗 ≠ 修复」，非法输入要显式拒绝而不是静默改写；改完必须重载。
- **如实记录未收口项**：Writeup 保留了两处当时未能收口的点（`memoryshell` 双马运行期仍存活、`rc.local` 判据在容器内不可满足），没有粉饰。

## 复现说明

- 靶机赛后已全部回收，脚本中的地址统一为 `<target>` 占位，需替换为自建环境。
- Writeup 中记录的「判分数据 / 官方答案」读取操作，仅在比赛授权的靶机内执行；本仓库不含任何真实凭据。
- 脚本由 Writeup 正文的内联代码重建，仅做提取与缩进规范化，未改动逻辑。

## 声明

所有测试均在比赛授权的靶机与本人环境中进行。本仓库已移除战队名、队员姓名、个人主机路径与真实靶机地址；Writeup 内容仅用于技术交流。
