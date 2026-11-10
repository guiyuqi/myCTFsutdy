# YE8hQxcU1oTsgksE · ezcms（Web）

- 平台：463 队解出（快照 2026-11-01 11:52）；我方状态：平台已解出（队友提交，我方无 submit-log 正确记录）
- flag：未在本地记录（我方**无提交、无证据、无草稿、无笔记**；连本地情报也是零，不编）

## 我方实际做了什么

**零留痕（有据）**：本题是我方四道"已解出无笔记"题里**留痕最少的一道**。

- `evidence/submit-log.jsonl`（749 行）**无 `YE8hQxcU1oTsgksE` 任何一行**；
- `evidence/` 下本题 **0 个文件**；`work/` 下**无同名草稿目录**（`work/` 里也没有 `ezcms`/`YE8h*` 任何变体）；
- `notes/` 下**无笔记**；全工作区 `grep -i ezcms` 在 `evidence/`、`notes/`、`work/` 中零命中；
- `work/TEAM-BOARD.md` 该行**代理列 = `—`**（无 agent）；
- **连 `team/ezcms/README.md` 本身都是空的**：192 字节 / 4 行，只有一句 `---` 与页脚链接，
  **没有题面、没有分值、没有情报、没有可疑点** ⇒ 本地连"二手情报"都没有。

已知平台事实（仅来自 `work/team-board.json` / `work/TEAM-BOARD.md` / `team/ezcms/EVIDENCE.md`）：

| 项 | 值 |
|---|---|
| 题号 / 题名 / 分类 | `YE8hQxcU1oTsgksE` / ezcms / **Web** |
| 类型 / 分值 | 容器（`type_id=2`、`dyn_flag=1`、`answer_limit=0`）/ 1000 |
| 平台解出 | **463 队**（快照 2026-11-01 11:52） |
| 我方状态 | `is_solved=true`，`solved_time` **11-01 08:11:44**（晚于其他三题，**成因未记录**） |
| 提交者 | **未记录 / 不猜**（`team/INDEX.md` 记「提交者平台未按题拆开 ⇒ 不猜」） |
| 镜像 / 题面 / 附件 | **均未记录**（本地无任何抓取） |

**为什么是零**：容器 Web 题，容器一直在队长手里；我方未取得实例、未提交、未留文件。
「未派单」是推测，非事实。

## 交接口径

需队友（**提交者本身待确认**：`team/INDEX.md` 记 ezcms 属"平台 `is_solved=true` 但提交者平台未按题拆开 ⇒ 不猜"）提供：
1. **flag 原文**（或脱敏后半段 + 长度）+ **谁提交的**（彭艺棋 / 丁枫洳 之一，需本人确认）；
2. **平台提交回包 `result:true`** 或平台答案页截图（唯一凭证）；
3. **一句话解法链路**（入口 → 绕过 → 落点）+ 漏洞类型（ezcms 题名暗示 CMS，但**这点未经任何材料证实，不得据此推演**）；
4. **解题脚本 / 请求原文 / 截图** → 进 `evidence/`；
5. **容器回滚/释放日志 + 容器内落地动作**（改了哪个文件、拿到什么回显；镜像名未知，需一并问）。
拿到 1+2 后回填 `evidence/submit-log.jsonl` 一条（**注明"队友账号提交"**），再补 `team/ezcms/README.md`（现为空）。
在拿到材料前，本题**只能登记平台事实，不得写解法**。

## 证据

**无。** `evidence/` 0 个文件、`work/` 无目录、`notes/` 原无笔记、`submit-log.jsonl` 0 条。
可复核的只有平台台账：`work/team-board.json`（`solved_teams:463`、`solved_time:"11-01 08:11:44"`）、`work/TEAM-BOARD.md`、`team/ezcms/EVIDENCE.md`、`team/EVIDENCE-INDEX.md`、`team/INDEX.md:10`（提交者未按题拆开）。
