# 赛后资料索引（2026 羊城杯）

| 文件 | 内容 |
|---|---|
| `YCB2026-WP.pdf` | **提交用 WP**（按官方模板重排，14 页 / 3.3 MB）：请注意 → 团队信息（<team> / <name>）→ 解题情况（平台截图 + 台账）→ 具体WP（WEB/PWN/REVERSE/MISC/AI）。每题含步骤、关键代码、**「平台页面截图 + 提交回包」双拼证据** |
| `wp.md` | WP 的 Markdown 源（改这份，再跑 `scripts/md2pdf.py`） |
| `notes/REPORT-YCB2026.md` | **本场完整报告**（总账）：结果 + 方法 + 逐题要点 + 缺陷 + 复盘 + 装备缺口 + Runbook + 索引 |
| `notes/ARCHITECTURE-PROPOSAL.md` | 新框架架构提案（envd/board/ledger+verifier/gate/tools + Skills 2.0） |
| `work/handoff/` | **给新工作区的交接包**（SPEC / METHODS / 6 角色提示 / 9 技能 / 3 检查表） |
| `notes/POST-MORTEM-YCB2026.md` | 赛后复盘（工程 + 方法）：装备缺口实测、编排缺陷、8 个可迁移方法、差距分析、Runbook、未解出题阻塞分类、6 次假结论 |
| `notes/RESEARCH-AGENT-CTF.md` | 外部调研（EnIGMA / D-CIPHER / CAI / Cybench / ctf-agent-workstation），与本场缺陷逐条对应 + 10 条可采纳设计 |
| `notes/ENV-DEFECTS.md` | 平台/部署异常 31 条 |
| `notes/FLAGS.md` | flag 台账（10 题 `result:true` + 终态分值） |
| `notes/YCB2026-RETRO.md` | 早期复盘（部分观点已被 POST-MORTEM 取代） |
| `evidence/submit-log.jsonl` | 19 条提交原始回包 |

## WP 素材与重建

```
assets/wp/
  solve-status.png          # 平台答题情况页（团队 <team>，绿色=已解答）
  summary.png               # 提交台账汇总（result:true 记录）
  shot-<题号>.png           # 每题的平台题目详情页截图（显示「已解答」+ 题目分值）
  flag-<题号>.jpg           # 双拼证据图 = 平台截图（上）+ 提交回包（下），由脚本生成
```

重建：

```bash
work/12084e/venv/bin/python scripts/wp-proof.py --list      # 合成证据图并列出缺图
work/12084e/venv/bin/python scripts/md2pdf.py wp.md YCB2026-WP.pdf
```

- 截图与题号的对应关系可**从截图的「题目名称」逐一核对**（不要仅依赖文件名/修改时间）。
- 如有上传体积限制，`scripts/wp-proof.py --jpeg` 生成 JPEG 版（当前 WP 即此版本，3.3 MB）。
