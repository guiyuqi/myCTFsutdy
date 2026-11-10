# 强网杯 WriteUp 与 AI 对话记录 · 合规要求与执行手册

> **依据**：裁判 2026-10-30 的口径（队长转述，已确认）。这条规则的风险等级最高——
> 不是丢分，是**按作弊处理 + 取消队伍排名**。所以它和「拿 flag」一样是硬指标。
> 相关：`scripts/wp-pack.py`（打包器）、`notes/methods/deliverables.md`（交付物清单）。

---

## 1. 裁判原文（不要再转述，按原文核）

> 比赛结束后 8 小时内，排名前 50 名的参赛队须上传每道成功解出赛题详细的解题报告（WriteUp）。
> 各队伍赛后提交 writeup 时，需提供**详细的分析过程及截图、解题脚本**；
> 若使用 AI 辅助解题，参赛选手需保留**完整的 AI 对话记录**（包括但不限于对话导出、图片、视频等形式）
> （例如 claude code 在 `~/.claude/projects/` 下，一个会话一个 `.jsonl`），
> 并**打为 zip 压缩包后上传至百度网盘**。
> 在提交 writeup 时，需**将链接附在文档开头**，同时需要**附上 zip 的 md5 值**。
> **如不按规范撰写、提交，或相应的会话记录无法支撑题目解出，则相应赛题按作弊处理，并取消队伍排名。**

---

## 2. 拆成可执行的 6 条

| # | 要求 | 我们的做法 | 由谁保证 |
|---|---|---|---|
| 1 | 每道解出题一份详细 WriteUp | `wp.md` 每题一节（`deliverables.md` 统一格式） | `wp-check.py` 自查 |
| 2 | 分析过程 + 解题脚本 | 每题 `notes/<题号>-<题名>.md` + `scripts/<题号>-solve.py` | 派单 brief 强制要求 |
| 3 | 截图 | **本队以 agent 解题，不强求出截图**（队长确认）；有浏览器/终端截图则一并放 `evidence/` | 人工 |
| 4 | **完整 AI 对话记录** | 打包 DSH 会话：`sessions/plain/*.jsonl`（可读）+ `sessions/raw/*.jsonl.zstd`（原件） | `wp-pack.py` |
| 5 | zip → 百度网盘；**链接放文档开头 + 附 md5** | `wp-pack.py` 生成 `WP-HEADER.md`（含 md5/sha256/文件数），贴到 `wp.md` 顶部 | `wp-pack.py` |
| 6 | **会话记录必须能支撑题目解出** | `wp-pack.py` 出「题号 ↔ 会话」支撑矩阵，缺一个就报警 | `wp-pack.py --dry-run` |

> 第 6 条是最容易死人的地方：**"我们确实解出来了"不等于"记录能证明是我们解出来的"**。
> 所以下面 §6 的支撑矩阵要当场看，不能赛后才发现缺。

---

## 3. 我们的"等价物"是哪种（重要，别答错）

裁判举例的是 claude code 的 `~/.claude/projects/*.jsonl`。**本队用的是 DSH（DeepSeek Harness），位置和格式都不同**：

| | claude code | **本队（DSH）** |
|---|---|---|
| 目录 | `~/.claude/projects/<项目>/` | **`~/.dsh/sessions/<工作区编码>/<会话id>/`** |
| 工作区编码 | — | 把绝对路径的 `/` 换成 `-` 再裹 `--`：<br>`~/ctf-2026` → **`--home-fragranstea-ctf-2026--`** |
| 文件 | `<session>.jsonl` | **`session.v3.jsonl.zstd`** |
| 格式 | 明文 JSONL | **JSONL，但是 zstd 压缩，且是"多帧追加"** |
| 一个会话几份 | 1 个 .jsonl | 1 个 `.jsonl.zstd`（+ 一个 0 字节 `session.lock`） |

所以提交时要在 index 里**写清楚这是 DSH 的记录、怎么打开**（`plain/*.jsonl` 就是明文，评委不需要装工具）。

---

## 4. ★ 解压这个文件的坑（2026-10-30 实测）

`session.v3.jsonl.zstd` **不是单个 zstd 流，而是几百个帧首尾相接**（每条记录追加一帧）。
实测那个会话文件里 `28 b5 2f fd`（zstd magic）出现 **389 次**。

| 方法 | 结果 |
|---|---|
| `python3 -c 'zlib/zstandard...'` / Node `zlib.zstdDecompressSync` | **只解第一帧** → 得到 **206 字节 / 1 行**（只有 session 头），会让人误判"记录是空的" |
| `7z x -so session.v3.jsonl.zstd` | **正确**：2,351,591 字节 / **679 行**，`user/message`、`assistant/message`、`tool/call`、`tool/result` 全在 |
| 本机有没有 `zstd` 命令 / python `zstandard` | **都没有**（`7z` 和 node 有） |

⇒ `wp-pack.py` 里 `decompress_zstd()` 优先用 7z，node 那套是"逐帧切割后再解"的退路。
**别用 `zstdDecompressSync` 一把梭，会静默少 99% 的内容。**

---

## 5. 打包流程（赛后 20:00 前）

```bash
cd ~/ctf-2026

# ① 排练（不写文件）：看会话在不在、哪道题缺支撑
python3 scripts/wp-pack.py --dry-run

# ② 真打包（默认窗口 = 2026-10-31 09:00 至今）
python3 scripts/wp-pack.py
#   → work/writeup-bundle/            目录（可复核）
#   → work/qwb2026-writeup-<时间>.zip  要上传的包
#   → 屏幕打印 md5 / sha256 + 可贴的 wp 头部

# ③ 传百度网盘，拿到链接+提取码后重跑一次，把链接写进头部
python3 scripts/wp-pack.py --link 'https://pan.baidu.com/s/xxxx 提取码:yyyy'

# ④ 把 work/writeup-bundle/WP-HEADER.md 的内容粘到 wp.md 最顶部
# ⑤ 交付前自检
python3 scripts/wp-check.py
```

**包内结构**

```
wp.md                      # 主文档（顶部就是链接 + md5）
WP-HEADER.md               # 上面那 6 行，粘贴用
REDACTION.md               # 脱敏记录（抹了什么、几处、为什么；哪些有意没抹）
sessions/
  INDEX.md                 # 会话清单 + 「题号 ↔ 会话」支撑矩阵
  plain/<会话id>.jsonl     # 明文对话记录（评委直接看这个）
  raw/<会话id>.jsonl.zstd  # 原件（防篡改/可复核）
notes/                     # 每题分析笔记
scripts/                   # 解题脚本（含 qwb.py 等工具）
evidence/                  # 提交台账、抓包、日志
```

---

## 6. 支撑性自检：怎么算"会话记录支撑了题目解出"

`wp-pack.py` 对**每道 `evidence/submit-log.jsonl` 里 `result:true` 的题**做三项核对：

| 项 | 判据 | 不合格意味着 |
|---|---|---|
| 会话里出现过题号 | 在该题窗口的会话明文里按**词边界**匹配 `<题号>`（避免 `12` 命中 `1208`） | ★ 最严重：记录里找不到这道题，等于"没有 AI 解题痕迹" |
| 有 `notes/<题号>-*.md` | 文件存在 | 缺分析过程 → 不满足"详细分析过程" |
| 有 `evidence/<题号>*` 或 `scripts/<题号>*` | 文件存在 | 缺可复现证据 |

结论列只有三种：`可提交` / `缺笔记（补 X）` / `★ 会话里没找到该题 → 现在按作弊风险处理`。
**只要出现第三种，先补材料再交，别赌。**

> 为什么可能"找不到"：题目是队友用**自己电脑/别的工具**解出来的，会话不在本机；
> 或者解题过程被压缩在别的会话里（时间窗口没覆盖）。
> 处置：① 让队友导出他那边的记录一起打包；② 或在本机把过程复述复现一遍并留痕（脚本+笔记+会话）。

---

## 7. 脱敏：为什么必须做，为什么只抹凭据

会话里**必然**出现本队凭据：我们讨论过 token、把它写进过 `creds.env`、在命令里回显过。
原样传百度网盘 = 把登录态和 teamtoken 公开出去。

`wp-pack.py` 默认**按真实值脱敏**（从 `~/.config/ctf/creds.env` 读值精确替换，
连"裸值"形态一起抹），替换成 `<REDACTED-LOGIN-TOKEN>` / `<REDACTED-TEAMTOKEN>` /
`<REDACTED-CDN-COOKIE>`，并在 `REDACTION.md` 里逐条记录处数与理由。

**实测覆盖**（2026-10-30 自测）：会话原文里的裸 token、带前缀的 `login:match_1483:<hex>`、
teamtoken、`__jsluid_s` cookie —— 打包后逐一 `grep`，**命中数均为 0**。

**有意不抹**的：比赛 `k`（`url_key`）、平台域名、接口路径、签名 salt。
理由：`k` 单独无法读题/提交（实测匿名只带 `k` 只有比赛详情和分类能读），
保留它评委才看得懂请求在打哪场；抹了反而降低记录的可读性和可信度。

> 如果裁判明确要求"未脱敏原始件"：`--no-redact`（会打警告）。默认不要用。

---

## 8. 赛中必须守住的 5 条（赛后补不回来的）

1. **不许删/清会话**。`~/.dsh/sessions/` 里的 `session.v3.jsonl.zstd` 就是证据本体，
   删了 = 这题的 AI 记录没了 = 按作弊处理。要"清理环境"也别碰这个目录。
2. **继续用同一个会话说**。同一道题尽量在一条会话线里做完；不要为了省 context
   开一堆短会话又不留痕（多开会话不会丢，但分散会让支撑矩阵变散、评委难读）。
3. **每题落笔记**：`notes/<题号>-<题名>.md`，哪怕只有 10 行。支撑矩阵的另一半靠它。
4. **提交台账必须真**：`wp.md` 里的 flag 必须能对上 `evidence/submit-log.jsonl` 的
   `result:true`（`wp-check.py` 会逐字节比对）。对不上就是"提交了但没证据"。
5. **截图不强制但很划算**：有终端/浏览器截图就丢进 `evidence/`，成本几乎为零，
   评审时对"这真是你们打的"帮助最大。

---

## 9. 时间线（UTC+8）

| 时刻 | 动作 |
|---|---|
| 2026-10-31 09:00 | 开赛 |
| 2026-11-01 12:00 | 停手（平台 `end_time`） |
| 2026-11-01 12:00 起 | 立刻跑 `wp-pack.py --dry-run` → 补支撑、补笔记 → `wp-pack.py` → 传网盘 |
| **2026-11-01 20:00** | **WriteUp 提交截止（`wp_stop_time`）；逾期视为放弃排名** |

> 8 小时看起来很宽，但支撑性核对 + 上传（百度网盘可能限速）会吃掉一大半。
> **12:00 就打包第一次**，别等到 19:00。
