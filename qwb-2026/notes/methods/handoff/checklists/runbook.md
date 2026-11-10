# 开赛 Runbook（按角色执行）

## T-7 天
- [ ] 装备：Android x86_64 模拟器 + system image、Windows 模板 VM（≥32 GB 宿主）、`astcenc`/`texture2ddecoder`、`pandoc` 或 LibreOffice、`~/re-tools/venv`
- [ ] 自检升级：不只测"命令存在"，还要测"库能 import、浏览器能起（`HOME` 可写）、解码器能出图"
- [ ] 脚本：`envd`、`gate`、`board`、`ledger`、`verify-flag`、`md2pdf`、`wp-proof`
- [ ] Skills 2.0：8 个方法技能 + 5 个角色提示，装进 DSH 技能目录

## T-0（前 15 分钟）
- [ ] Triage：全部题出 `type/judge/rounds_est/needs_env/tool_plan/acceptance`
- [ ] Warden：按 Triage 顺序取前 4 台环境，写状态表
- [ ] Scribe：建台账骨架；Planner：定首攻顺序（分值为王，但要乘"类型清晰度"）

## T+0–180
- [ ] 每 60 分钟：Planner 重排一次；检查 parked 的 `revisit_at`
- [ ] 任何 flag：Verifier 双签 → 提交一次 → 记账
- [ ] 任何负结论：过 `verdict.md`
- [ ] 任何 20 分钟无新证据：park（带 missing/next_action/revisit_at）

## T+180–结束
- [ ] 停开新题；只做高确定性项
- [ ] Scribe 实时补 WP；结束前 30 分钟定稿
- [ ] 数据刷成终态（分值/解出数）+ 逐字节对账 + 生成 PDF
