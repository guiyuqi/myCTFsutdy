# 强网杯 2026 · 车联网安全专项赛（CTF 遴选赛）· 归档

> **仓库说明**：本目录是从个人归档里抽出的**脱敏发布版**。
> 只发布 `README.md`、WP 正文、`notes/`、`scripts/`（部分赛事另有 `tooling/`、`retrospective/`）；
> 归档里的 `attachments/`（题目附件）、`evidence/`（证据台账）、`deliverable/`（打包件/PDF）**不随仓库发布**，
> 所以下面目录表里提到的这些子目录，在本仓库中可能不存在。
> 真实靶机地址已替换为 `<target>`，个人主机路径已替换为 `~`，队名/姓名已替换为 `<team>` / `<name>`。

> 队伍 **<team>**｜赛程 **2026-11-08 09:00–12:00 CST**（3 h）
> 终盘 **630 PT / 解出 3 题 / 第 48 名 / 一血 1 个**
> 架构 **ctfagent + muteki + pi worker**（模型 deepseek-flash，即 DeepSeek-V4.1-Flash）
> 归档于 **2026-11-08 晚**｜本 README 是入口，细节按下面的表跳。

---

## 1. 成绩与分工

- **解出 3 题，全部由 AI agent 解出**（本次为单人 + agent，无队友协作题）：
  - `iov-重生的种子`（REVERSE）— `flag{BCM_MLKEM_s33d_r3us3_und3r_v0lt4g3_gl1tch}`
  - `re-Route97 的副歌`（REVERSE）— `flag{R0ute97_Ch0rus_Encore_2026}`
  - `NL-BCM 车身控制器（BCM_UPDATE.fwpk）`（REVERSE）— `flag{767a9ca2-ef9a-44b8-a0a3-7656457b0907}`
- 未解出 8 题（`iov-车内总线摆渡` / `re-LastIgnition` / `iov-静默译码` / `iov-猎隼折翼` /
  `iov-Autopilot` / `misc-CAN言乱语` / `misc-日志的秘密` / `misc-么什有里包量流`），
  **每题的硬结论与卡点见 `notes/`，完整分析见 `retrospective/`**。

## 2. 目录结构

| 路径 | 内容 | 备注 |
|---|---|---|
| `wp-qwb-iov-2026.md` | 提交用 WP（索引 + 3 篇逐题） | 原名 `wp-<team>-2026-11-08.md`；与 `deliverable/wp-qwb-iov-2026.pdf` 同内容 |
| `retrospective/` | **自包含复盘包**：`RETRO-2026-11-08.md`（完整复盘，455 行）+ `digests/`（29 个 run 逐份摘要）+ `runs.csv/json` + 赛前计划 `QWB-IOT-2026.md` | 交接首选，先读 `RETRO-README.md` |
| `notes/` | 11 题逐题笔记（题面/结论/最后事实/可复用资产）+ `notes/methods/`（planner 根因、派单与止损、wine/oracle/瘦身三技） | **方法论比题目更值钱** |
| `scripts/tools/` | 自研运维工具：`dispatch.py`（单题派单）、`board.py`/`run_events.py`（看盘）、`keep_light.py`/`compact_events.py`（事件流瘦身）、`watchdog.py`（墙钟刹车）、`package_upload.sh`（打包+自动脱敏）、`md2pdf.py`、`wp_from_run.py`、`retro_scan.py`/`retro_digest.py`、`wine_run.sh` | 下次可直接用 |
| `scripts/recipes/` | 子代理产出的可复用配方：`oracle.py`（离线判定 0.115ms）、HQC `solve.py`/`brute.py`、Falcon `solve2.py`+候选集、`vmcode.bin`+VM 模拟脚本 | 对应未解出的 4 题 |
| `evidence/` | 台账 `ledger.jsonl`、`run-logs.tar.gz`（15 个 run 的压缩事件流）、`platform-命令台账.db`（223 次 resolve 等命令记录）、`watchdog.log`、`gate-evidence/` | 只留文本/可压缩 |
| `attachments/` | 平台附件（`iov-*.zip` 三件 + 各 run 上传的题包） | 24 MB |
| `deliverable/` | 提交件：`wp-qwb-iov-2026.pdf`（含内嵌清单；原名 `wp-<team>-2026-11-08.pdf`，重复的 `<team>.pdf` 已合并）、`qwb2026-iov-conversation-package.tar.gz`（AI 对话+事件流+台账，24 MB，已放网盘） | 压缩包 sha256 见下 |

`deliverable/qwb2026-iov-conversation-package.tar.gz` sha256：
`d30e69256f02a38a3fd22aafc82016cd3b1568aea3dfd02dd96bb3daae48cd5b`

## 3. 一句话结论（详见 `retrospective/RETRO-2026-11-08.md`）

**本场最大的问题不是模型智商，而是 planner 从搭建当晚起就是坏的**：641 次 planner 调用全部返回 0 字符、
29/29 个 run 的 draft 从未 `committed`，导致 66% 的执行代判死；三道解出的题都是绕开 planner 的形态。
其次才是成本放大器（94% 事实重复、223 次 reopen 重置预算 ⇒ 214M token ≈ $64）与靶场中途挂掉
（`<target>:32945` 10:45 起持续 refused，而 agent 之前已挖到 `gateway-calibrator` 的 `argc==31337` 隐藏密钥）。

## 4. 从归档能直接复现什么

```bash
cd ~/self/ctf/qwb-iov-2026
# ① 复盘数字复算（需要工作区的 muteki 运行态；归档内含压缩事件流，可解压到任意目录后改路径）
tar -xzf evidence/run-logs.tar.gz -C /tmp/qwb-iov-logs
python3 scripts/tools/retro_scan.py   # 需按你的目录调整 EVENTS 常量
# ② 提交件完整性
sha256sum deliverable/qwb2026-iov-conversation-package.tar.gz   # = d30e6925…8cd5b
pdfinfo deliverable/wp-qwb-iov-2026.pdf | head -5
# ③ planner 根因复现（1 分钟，见 notes/methods/PLANNER-ROOT-CAUSE.md）
```

## 5. 未归档清单（有意丢弃，需要时可从原处再取）

| 内容 | 大小 | 原位置 | 为什么不留 |
|---|---|---|---|
| 全部 run 的工作区（附件解包、中间镜像、dump） | **13 GB** | `~/.ctfagent/state/sessions/` | 二进制中间产物；结论已进 `notes/` 与 `retrospective/` |
| muteki 原始完整事件流（含 reasoning） | ~430 MB | `~/.ctfagent/state/muteki/*.jsonl.full` | 99% 是 token 级思考；压缩版已在 `evidence/run-logs.tar.gz` |
| 两份材料包目录 | 218 MB | `~/.ctfagent/upload-1108-1040/`、`upload-1108-1048/` | 内容已进 `deliverable/*.tar.gz` |
| wine prefix / test 目录、`.tmp` 草稿 | 2.6 GB | `~/.ctfagent/.tmp/` | 可重生 |
| 平台附件之外的容器/镜像 | — | 平台侧 | 需平台账号重新下载 |
