# xCn4gbGUPAea4Iw_ · ezphp（Web）

- 平台：759 队解出（快照 2026-11-01 11:52）；我方状态：平台已解出（队友提交，我方无 submit-log 正确记录）
- flag：未在本地记录（我方**从未取得实例、未提交、未留任何文件**；flag 串、回包、思路、脚本全在队友处，不编）

## 我方实际做了什么

**零留痕（有据，不是"没找到"）**：本题我方**没有派过任何代理碰它**。

- `evidence/submit-log.jsonl`（749 行）**无 `xCn4gbGUPAea4Iw_` 任何一行**；
- `evidence/` 下本题 **0 个文件**；`work/` 下**无同名草稿目录**；`notes/` 下**无笔记**；
- `work/TEAM-BOARD.md` 该行**代理列 = `—`**（同表其他已解题都有 agent uuid）；
- 全工作区 `grep -i ezphp` 在 `evidence/`、`notes/` 中零命中。

⇒ 我方在这一题上的技术产出为 **0**：没有 banner、没有响应头、没有一条 HTTP 回显。
本题是**容器 Web 题，容器由队长统一分配/在队长手里**，我方从未拿到实例。

已知平台事实（抄自 `team/ezphp/README.md`，**不是解法**）：

- 提交者 **彭艺棋**，平台 solved_time **10-31 10:33:19**；镜像 **`eci_2026qwb_ezphp`**；**零附件**（`file_list=[]`、`file_url=""`）。
- 题面原文（一字不改）：`ezphp, how 2shell???(The container startup takes 1 minute.)`
  ⇒ 终点是**拿/写 shell**（PHP 侧 RCE 类）；**起服约 60 秒**，别把首连超时误判成地址错。
- 解出增长极快（09:18 快照 1 队 → 10:04 复拉 29 → 10:33 106），分值轨迹 1000 → 445 → 250 随解出衰减
  ⇒ 属常规路径，不是 0day。
- 队友容器 `https://eci-2ze6bij3pcxb7tw62haw.cloudeci1.ichunqiu.com:443` 系**队友开的**，整理时可能仍在运行 ⇒ **处置前先问队友，不要自己 close**。

**为什么是零**：共享环境 + 队友已在做（`team/INDEX.md` 记「人做出来了、机器没参与」）。
「未派单」是推测，非事实。

## 交接口径

需**彭艺棋**提供 5 样（`team/ezphp/README.md` 开头「材料缺口」表，5 项全为"没有"）：
1. **flag 串**（或脱敏后半段 + 长度）；
2. **平台提交回包**（`result:true` 的 `code`/得分/时间）或平台答案页截图；
3. **拿到 shell 的那条请求**（URL + payload 原文）；
4. **一句话洞点名**（如"上传后缀绕过""`assert` 拼接""`disable_functions` 绕过"）；
5. **容器内落地动作**（写到哪个路径 / 执行了什么命令）+ 容器回滚/释放记录。
**只需 ①③④ 就够写一版可用 WP**；只拿到①（无过程）时只登记事实，不写解法。
拿到后：回填 `evidence/submit-log.jsonl` 一条并**注明"队友账号提交"**，再补 `team/ezphp/README.md` §解法待补。

## 证据

**无。** `evidence/` 0 个文件、`work/` 无目录、`notes/` 原无笔记、`submit-log.jsonl` 0 条。
可复核的只有二手平台情报：`team/ezphp/README.md`（107 行）、`team/ezphp/EVIDENCE.md`、
`work/TEAM-BOARD.md`（代理列 `—`）、`work/team-board.json`、`notes/FLAGS.md:32`（记 ⬜ 未解出）。
