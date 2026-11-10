会话附件百度网盘链接：<待上传后回填> md5值：f74eb7fbcf72715eb9b91f44ddef5171

# 强网杯 2026 线上赛 · WriteUp · <team>（<team>）

> 压缩包：`qwb2026-writeup-20261101-1140.zip`（92.9 MB，md5 **24c43267d17017117838123ee5b657a1**，sha256 `995cfeeeccc89e8892cfec6bd3535283eacfc483d2610311c7365350117a7683`）
> 包内 469 个文件：**每个 agent 会话一份完整 JSONL**（`sessions/plain/*.jsonl`，原始 `sessions/raw/*.jsonl.zstd` 一并保留）+ 每题笔记 + 解题脚本 + 提交证据；脱敏范围见包内 `REDACTION.md`。
> 本文只收录**我方自行解出**的题目；其余题目由队友完成，不在本文范围。

---

### KVlvgNuOwJXPAyAQ · 宇宙微波背景辐射（Misc，静态 flag）

### 1.1 答案

- **flag**: `flag{S3cr3t_0f_cM6_h1dd3n_1n51d3_5tr34m}`

```
flag{S3cr3t_0f_cM6_h1dd3n_1n51d3_5tr34m}
```

### 1.2 附件结构

附件内是一条 631 MB 的 mkv，`ffprobe` 共 6 条流：

| 流 | 内容 |
|---|---|
| 0 | h264 主视频（真实 PBS Space Time S5E12，1039 s） |
| 1 | aac 音频 |
| 2 | **0.389 fps「雪花」视频轨**（400 帧 1280×720 二值噪声） |
| 3 | subrip 轨（200 条 cue，正文其实是**二值 PNG 的 hex 转储**） |
| 4 / 5 | attachment：`g2.tar` / `g4.tar`，各含 **200 张 1280×720 二值噪声 PNG** |

⇒ **五个噪声载体**：`g2.tar`(200)、`g4.tar`(200)、srt(200)、雪花轨前半(0–214)、雪花轨后半(215–399)。题面"从雪花里看出名堂"即指载荷在噪声帧中。

### 1.3 核心方法：逐像素「帧间翻转率」

载荷**不在单帧、也不在平均图**里，而在**翻转率的低频空间结构**里：

```python
d[i] = (img[i] != img[i+1])     # 相邻帧逐像素是否翻转
flip  = mean_i d[i]             # 每像素翻转率
```

真随机二值噪声的 `flip` 恒为 `2p(1-p)≈0.4992`（常数）；实测其**低频分量远超理论**（k=64 方块平滑后是理论的 **8.4×**）。对 `flip` 做 `box(k)` 均值滤波 + 1%/99% 分位归一化，**文字直接浮现**：

```python
def box(a, k):                          # 积分图实现均值滤波，无需 scipy
    h, w = a.shape; k2 = k // 2
    p = np.pad(a, ((k2,k2),(k2,k2)), mode='reflect')
    c = p.cumsum(0).cumsum(1); c = np.pad(c, ((1,0),(1,0)))
    return (c[k:,k:] - c[:-k,k:] - c[k:,:-k] + c[:-k,:-k]) / (k*k)

def flipmap(paths, thr=125):
    S = np.empty((len(paths),) + np.array(Image.open(paths[0])).shape, np.uint8)
    for i, f in enumerate(paths):
        S[i] = (np.array(Image.open(f).convert('L')) > thr)
    return (S[:-1] != S[1:]).mean(0)

b = box(flipmap(sorted(glob.glob('g4/*.png'))), 20)
lo, hi = np.percentile(b, [1, 99])
Image.fromarray(((b-lo)/(hi-lo)*255).clip(0,255).astype(np.uint8)).save('g4.png')
```

### 1.4 第六个载体：主视频尾部 201 帧噪声

前五个载体只凑出 39 个字符，缺少含 `}` 的收尾。**主视频全片平均看不到字**——载荷只占 4156 对中的 203 对（≈4.9%），被稀释 20 倍。

**定位办法（可复用）**：逐帧统计 `mean/std/dark/bright`，找满足

```
mean ∈ [100,170] & std > 40 & dark < 0.15 & bright < 0.15
```

的**连续段** ⇒ 锁定 **t = 1030.97–1039.31 s 的 201 帧纯噪声**（此前是正常的 PBS 白卡片尾）。对这 201 帧套同一方法（`flip` 均值 0.4932 vs 理论 0.4992，min 0.327 / max 0.654），`box(20)` 后读出 **`5tr34m}`**。

### 1.5 六段文本与正确段序

| 载体 | 文本 |
|---|---|
| 雪花轨 0–214 | `S3cr3t` |
| 雪花轨 215–399 | `0f_cM6` |
| `g4.tar` 200 PNG | `h1dd3n` |
| srt（hex→200 PNG） | `1n51d3` |
| `g2.tar` 200 PNG | `3cr3t`（与首段 `S3cr3t` 重叠，拼装以首段为准） |
| **主视频尾 201 帧** | **`5tr34m}`** |

**正确拼装**（本题最大坑）：

```
S3cr3t + 0f_cM6 + h1dd3n + 1n51d3 + 5tr34m}
```

语义为 **"S3cr3t of cM6 hidden inside stream"**，**不是**直觉的 "S3cr3t hidden inside of cM6 stream"。按直觉拼的 440+ 个候选（6 种段序排列 × 7 种形近/大小写替换 × `flag{`/`f1ag{`/`f1a9{` 三种前缀）**全部判错**。

### 1.6 字形客观裁决

- 六个 `flip` 图统一尺度（`box(K=10)` + z 归一化）后发现**文字 cap-top=343 / baseline=487 / cap 高=145 完全一致**，可跨载体比较；
- 列投影切出 **40 个 glyph**（g2 6 / g4 7 / sub 7 / vA 6 / vB 7 / tail 7），与字符数逐一相等；
- 字体识别：54 字体 × 24 无歧义字 ⇒ **Lato-Semibold**（mean NCC 0.860）；
- 逐字 NCC 打分，分差 <0.05 标"歧义"并人工放大 8× 复核；
- `1` vs `l`/`i` 用**零字体假设**的 advance 位置最小二乘锁死：`h1dd3n_` RMS **4.35 px** vs `hidd3n_` 28.9 / `hldd3n_` 29.9。

### 1.7 教训

1. **「限流 ≠ 判错」**：平台有提交节流（`对不起，您的操作太过频繁！`）。正确串一度就在候选表里，却因 `result=null` 被当作"已试"跳过——**必须重试到拿到真正的判定**。这是本题多花 3 小时的根本原因。
2. 判据要选对：`mean` 类统计在 p≈0.5 时**无检出力**（黑底 +Δ / 白底 −Δ 各半 ⇒ 均值恒 125）；正解是**翻转率**。
3. 逐帧 `mean/std/dark/bright` 分段定位，比全片平均灵敏 20 倍。
4. 字符裁决不要靠肉眼看缩略图（JPEG/缩放会伪造形变），要用模板 NCC + 零假设几何判据。

---

### 4yUAPAGmS0zRzdjp · 问卷调查（Misc）

题面：`感谢您的参与！请完成调查问卷获取flag：https://v.wjx.cn/vm/Pul1S19.aspx`

完成问卷后取得：

- **flag**: `flag{强网杯十年有我！}`

```
flag{强网杯十年有我！}
```

**★ 关键细节**：结尾感叹号是**全角 `！`（U+FF01）**。半角 `!` 会被判"答案错误"（实测：08:04:40 半角 → `code 101 答案错误`；08:04:49 全角 → `code 0 恭喜您，回答正确`）。

---

## 3. AI 使用说明

本文所有分析由 dsh agent 会话完成，完整会话记录按 `.jsonl` 逐会话打包（见文首 md5）。打包脚本 `scripts/wp-pack.py`，会话原始位置 `~/.dsh/sessions/<workspace>/<session-id>/session.v3.jsonl.zstd`（多帧 zstd，可用 `7z x -so` 解压）。

---

### ZvAQO9Mw5mvCyfj8 · vaultlink（Web，平台公告补分，非我方解题）

本题不是我们解出来的，也不存在解题过程，单独说明以免与真正的 WP 混淆。

2026-11-01 00:24:33 平台公告（原文纪要，见 `evidence/vaultlink-free-flag.md`）：
vaultlink 因环境问题产生非预期解，环境重启后该非预期解失效，为保证公平，
**所有队伍均可获得本题分数**，方式为手动提交固定字符串。

- **flag**: `flag{see_you_revenge}`

08:01:50 提交，平台返回 `答案正确，该题目已被攻克，不计分`（`submit-log.jsonl` 第 270 行）。
即：该分来自公告补偿，**不构成任何解法**；我们未对 vaultlink 做任何攻击性尝试。
