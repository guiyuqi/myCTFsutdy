---
name: tool-plan
description: 动手前先把"能用什么工具"列出来——防止重复造轮子
when: "任何新题 triage 或换方向时"
bind_tools: [tools.search]
acceptance: ["tool_plan 非空", "每个候选工具标出用/不用理由"]
failure_modes:
  - {symptom: "花 20 分钟自己写解码器，而环境里已有", fix: "先 tools.search"}
---

## 做法

1. 用题面关键词 + 附件类型检索：`tools.search("<aes zip>")`、`("astc")`、`("oodle")`、`("gdb")`、`("smt")`。
2. 把结果写成三列：**工具 / 是否可用 / 用不用（理由）**。
3. 只用"可用且判据明确"的；没有就写"需自写"，并把自写脚本登记到 ledger。

## 判据

- `tool_plan` 存在且非空 ⇒ 才允许进入 ACTIVE。
- 自写脚本 ≤3 个/题；超过说明工具没查够。

## 本场实例

- 12080：`pyzipper` 已装却手写 20 行 HMAC；`zip2john`/`john` 也在（可交叉验证）。
- 12084：`texture2ddecoder` 缺、`astcenc` 缺 ⇒ 才该自写/装 venv。
