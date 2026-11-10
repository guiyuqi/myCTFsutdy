# 强网杯 2026（第十届）线上赛 · 归档

> **仓库说明**：本目录是从个人归档里抽出的**脱敏发布版**。
> 只发布 `README.md`、WP 正文、`notes/`、`scripts/`（部分赛事另有 `tooling/`、`retrospective/`）；
> 归档里的 `attachments/`（题目附件）、`evidence/`（证据台账）、`deliverable/`（打包件/PDF）**不随仓库发布**，
> 所以下面目录表里提到的这些子目录，在本仓库中可能不存在。
> 真实靶机地址已替换为 `<target>`，个人主机路径已替换为 `~`，队名/姓名已替换为 `<team>` / `<name>`。

> 队伍 **<team>**（<team>）｜赛程 **2026-10-31 09:00 → 11-01 12:00 CST**（27 h）
> 终盘 **1201.57 分 / 解出 12 题 / 排名 532**（`work/team-board.json` 11-01 11:55:05 复拉）
> 平台 41 题：Misc 6 / Crypto 6 / Reverse 3 / PWN 17 / Web 9
> 归档于 **2026-11-05**｜433 文件 / 150.8 MB｜本 README 是入口，细节按下面的表跳。

---

## 1. 成绩与分工

- **解出 12 题**；其中 **AI 代理直接解出 2 题**：
  - 宇宙微波背景辐射（`KVlvgNuOwJXPAyAQ`，Misc 静态）— `flag{S3cr3t_0f_cM6_h1dd3n_1n51d3_5tr34m}`
  - 问卷调查（`4yUAPAGmS0zRzdjp`，Misc）— 关键点：结尾必须是**全角 `！`（U+FF01）**
- **队友解出 10 题**（frozen / vmshare / ELFStudy / babysilent / easytl / oldsvr / cwp / ezphp / ezcms，以及 `vaultlink`）
- `vaultlink` 的分数来自**平台公告补偿**（00:24 公告授权提交固定串 `flag{see_you_revenge}`），
  **不是我方解出**，`wp-qwb-2026.md` 第 3 节已写明。

逐题证据（41 张证据卡，含赛后对照官方 WP 的「赛后修正」）：`evidence/cards/EVIDENCE-INDEX.md` → `evidence/cards/<题名>/EVIDENCE.md`。

---

## 2. 目录结构

| 路径 | 内容 | 备注 |
|---|---|---|
| `wp-qwb-2026.md` | 提交用 WP（3 节：CMB 完整解法 / 问卷调查 / vaultlink 补分说明） | 原名 `wp.md`；首行是网盘链接与压缩包 md5 占位 |
| `retrospective/` | **自包含复盘包**（README / HANDOFF / 一页纸结论 / 完整复盘 / 4 份方向对照 / 17 题修正 / 台账统计 / firmware 自包含复现） | 交接首选，先读它的 `README.md` |
| `notes/` | 逐题笔记 + `notes/methods/`（方法论，含 `POST-MORTEM-QWB2026.md`、`BETTING-AND-STOPPING-2026-11-04.md`）+ `notes/briefs/`（派单规则） | 方法论比题目更有复用价值 |
| `scripts/` | 平台工具（`qwb.py`/`qwb-board.py`/`container-pool.py`/`verify-flag.py`/`wp-pack.py`/`wp-check.py`/`evidence-index.py`/`triage-auto.sh`）+ 逐题解题脚本；`scripts/drafts/` 是赛中草稿（CMB 重提、vmshare 扫表等） | 平台 SDK 下次可直接改凭据复用 |
| `evidence/cards/` | 41 题证据卡 + 各题 README + `EVIDENCE-INDEX.md` + `AGENT-FINDINGS` + `team.rar`（队友材料） | 复盘主线（原 `team/`） |
| `evidence/` | **只保留文本类**（.md/.txt/.log/.csv/.jsonl/.json）：提交台账 `submit-log.jsonl`（749 条）、门禁台账 `gate-log.jsonl`、triage 输出、各题 findings | 二进制/图片/大文件未归档（见 §4） |
| `attachments/` | 本题的 21 个附件目录（`qwb<题号>_<题名>/`，24 个文件） | 46 MB |
| `deliverable/` | 提交压缩包 `qwb2026-writeup-20261101-1157.zip` | **97.8 MB，md5 `f74eb7fbcf72715eb9b91f44ddef5171`**，sha256 `9bed4a95…8d22b`，内含 70 份会话 JSONL + 全部笔记/脚本/证据/team |

---

## 3. 从归档能直接复现什么

```bash
cd ~/self/ctf/qwb-2026
# ① firmware：赛后用我们赛时已有的两个中间量 + 一行 SM4-CTR 解出官方 flag（包内自带 176 B 密文）
python3 retrospective/05-evidence/fHU0uVIVw6pkWNhv-firmware-repro.py
# ② 复盘数字复算（需要 ~/.dsh 会话库；归档不含会话库）
python3 scripts/sess-stats.py --store ~/.dsh/sessions/--home-fragranstea-ctf-2026--
# ③ 交付包完整性
md5sum deliverable/qwb2026-writeup-*.zip    # 应等于 f74eb7fbcf72715eb9b91f44ddef5171
```

---

## 4. 未归档清单（有意丢弃，需要时可从原处再取）

| 内容 | 大小 | 原位置 | 为什么不留 |
|---|---|---|---|
| CMB 原始视频附件（zip） | 579 MB | `~/ctf-2026/firmware/宇宙微波辐射_*.zip` | 平台可再下载；方法已在 `retrospective/` 与 `notes/methods` |
| `work/` 全量草稿 | 9.9 GB | `~/ctf-2026/work/` | 草稿区，赛后按规则清空；被引用的 7 个脚本已入 `scripts/drafts/` |
| 会话库（多帧 zstd） | 133 MB | `~/.dsh/sessions/--home-fragranstea-ctf-2026--`（201 会话） | 已整包进 `deliverable/*.zip`（70 份窗口内 JSONL） |
| `evidence/` 二进制与图片 | 16 MB | 原 `evidence/`（.bin/.png/.npy） | 保留其对应的 .md/.txt 判据即可 |
| `decompiled/`、`ghidra-proj/`、`unblob.log` 等中间产物 | < 1 MB | 原工作区顶层 | 可重生 |

---

## 5. 一句话复盘（给下一个我）

> 这场的失分不在难度，而在**投注与停止**：赛程窗口内 41% 的会话在写文档、5 道题**一次解题派单都没有**、
> firmware / license / NeuronShuffle 各只跑了 38 / 11 / 8 分钟就转成文档；而赛后对照官方 WP，
> firmware 只差一行 `SM4-CTR(SM3(P)[:16], B[:16])`、Dreambound 只差一次坐标下降、vmshare 只差大小写。
> 详见 `notes/methods/POST-MORTEM-QWB2026.md` §2.5 与 `notes/methods/BETTING-AND-STOPPING-2026-11-04.md`。
