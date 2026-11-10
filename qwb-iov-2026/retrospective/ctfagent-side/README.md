# ctfagent 侧复盘（第二份）

本目录是 ctfagent/引擎侧会话的独立复盘，与隔壁 `../RETRO-2026-11-08.md`（比赛辅助侧）互为交叉核对：
- `RETRO-ctfagent-side.md`：逐 run 数据、planner 无凭据事故、patch 0001–0006、模型能力评估
- `WP-98091.md`：`misc-么什有里包量流` 的深挖（三层结构、可复现解密、卡点与 oracle）
- `digests/`：15 个正式 run 的机器摘要（时间线/工具/事实/死路/每代最后动作）
- `*.py` / `apply-*.sh`：分析脚本与可重放的补丁应用脚本
口径差异（与辅助侧复盘的 292 代 / 641 次 planner 失败）：本文用 15 个正式 run 的 generation 去重（225 代）
与 usage 表行数（1081 条 0-token 记录）；详见 RETRO 第 7.6 节。
