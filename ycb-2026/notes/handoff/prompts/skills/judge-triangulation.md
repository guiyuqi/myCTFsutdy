---
name: judge-triangulation
description: 写"不存在/不可解/未命中"之前必须过的三重对照
when: "任何负结论落盘或提交前"
bind_tools: [board.claim, board.verdict, platform.score]
acceptance: ["正向对照记录", "负向对照记录", "external_solve_count 读数"]
failure_modes:
  - {symptom: "扫描零命中就下结论", fix: "先用已知 200 的路径验证扫描器"}
  - {symptom: "解出人数 >0 仍写不可解", fix: "直接驳回"}
---

## 做法

1. **正向对照**：拿一个已知为真的样本喂判据（例：`/api/v1/health` 必须被记为命中）。
2. **负向对照**：只改一个变量，看判据是否翻转（例：同 task 打 status 与 admin）。
3. **外部反证**：`detail.score` 的 `已答出N次`；N>0 ⇒ 负结论错误，回去补覆盖。

## 判据

- 三段记录齐全才算"结论"；缺一段只能写"假设"。
- 措辞必须收窄："在我枚举的 N 个候选里不存在"，而不是"不存在"。
