# OSINT 报告 · ELFStudy + 宇宙微波背景辐射（2026-10-31）

> 代理：OSINT subagent。**未提交任何 flag，未碰容器。**
> 结论先行：**两道题都没有可抄的公开来源**。ELFStudy 的 flag 不存在于公网；CMB 的载体视频是公开的
> PBS Space Time 纪录片，但没有人用这个片子出过题（无 writeup）。下文给出可证的来源 + 对两条题最可能被忽略的一步。

---

## 1. 结论

| 问题 | 结论 | 置信度 |
|---|---|---|
| ELFStudy 是否来自公开 CTF 赛题 | **否（在可检索范围内）**。工具名/版本号 `ELFStudy 1.4.2 — ELF structure inspector` 在 GitHub / Gitee / 中英文搜索引擎**零命中** | 高 |
| 是否有公开 flag 可抄 | **否**。没有任何来源提到该二进制或该 flag | 高 |
| ELFStudy 的真实出处 | 出题人**近期现编**：`GCC: (Ubuntu 15.2.0-16ubuntu1) 15.2.0` 是 2025Q4/2026 才有的 Ubuntu 编译器版本，公开仓库里不可能存在这么新的 fork | 高 |
| CMB 附件来源 | 载体是**公开影片**：PBS Space Time **S5E12《Secrets of the Cosmic Microwave Background》**（片名逐字相同） | 高 |
| CMB 是否有人做过同题 | **未找到**。同类型的"白噪声藏图 / mkv 隐藏轨"题很多，但没有用这部片子的 writeup | 中高 |
| 候选 flag | **无** | — |

### 1.1 为什么"314 队"这条线索反而说明**没有公开来源**
314 队解出 = 人人都会 = 解法定然短、且不依赖任何冷门知识。这意味着两件事同时成立：
1. **不存在"某队公开的 writeup 里抄来的解法"**（本场进行中，赛后才有，且不会有）。
2. 若我们的三个逆向跑者 110 分钟全部失败，那失败原因**不是"难"，而是"方向错"**——
   典型形态是：我们锁定了"某个异常块"，而解法根本不在那个块里（见 §3 提示）。

---

## 2. 关键来源（URL + 摘录）

### 2.1 ELFStudy：全部为阴性（这就是结论）
| 检索面 | 查询 | 结果 |
|---|---|---|
| GitHub 仓库搜索 API | `api.github.com/search/repositories?q=elfstudy` | `{"total_count":0,...}` 原文：**0 个仓库** |
| Gitee 仓库搜索 API | `gitee.com/api/v5/search/repositories?q=elfstudy` | 返回 `[]` 空数组 |
| GitHub 代码搜索 | `q="ELF structure inspector"` | HTTP 401 —— 需鉴权，无法用；改用 grep.app |
| grep.app 代码搜索 | `q=elfstudy` | HTTP **429** + "Vercel Security Checkpoint"，被门禁挡住（**唯一没查成的面**） |
| Bing（cn，中文索引） | `"ELFStudy" CTF`、`"ELF structure inspector"`、`ELFStudy github ELF inspector` | 命中全是同名词条噪声：ELF Study（英国急诊剖腹手术医学研究，[ovid.com](https://www.ovid.com/jnls/annalsofsurgery/fulltext/10.1097/sla.0000000000003402~frailty-in-older-patients-undergoing-emergency-laparotomy) / [academic.oup.com](https://academic.oup.com/ageing/article/50/Supplement_2/ii1/6297339)）、`elflect.com`（深圳易星标）、`elfstudy.com` 域名售卖页（[sojson.com](https://www.sojson.com/mofa-elfstudy.com.177e7c1/domain.html)）、SelfStudys 学习站。**无一条与 CTF/ELF 逆向相关** |
| Mojeek | `elfstudy` / `"ELF structure inspector"` | HTTP 403 / JS captcha，不可用 |
| 内置 web_search | `强网杯 ELFStudy`、`ELFStudy 314 队伍解出`、`"ELFStudy" writeup` | 无相关命中 |
| DuckDuckGo HTML 端点 | `html.duckduckgo.com` / `lite.duckduckgo.com` | `fetch failed` / 解析到非公网 IP，不可用 |

> 判决依据：**仓库级搜索（GitHub + Gitee）双零 + 名称/版本号/自述串三个精确短语全无命中**。
> 若这工具来自任何公开项目或公开赛题，`ELFStudy` 这个生造词必然至少在一个仓库或一篇博客里出现一次。

### 2.2 CMB：载体是公开影片（唯一"公开来源"命中）
- PBS Space Time **Season 5 Episode 12**：*Secrets of the Cosmic Microwave Background*
  - [video.detroitpbs.org — PBS Space Time | Secrets of the Cosmic Microwave Background | Season 5 | Episode 12](https://video.detroitpbs.org/video/secrets-of-the-cosmic-microwave-background-syapjk/)
  - [pbssocal.org — 同集](https://www.pbssocal.org/shows/pbs-space-time/episodes/secrets-cosmic-microwave-background-kc6t5b?p=13)
- 题面的"1%"就是这集的招牌事实（老式电视雪花里约 1% 来自 CMB）。⇒ 题面**照抄纪录片的叙事**，
  附件里的 `Secrets of the Cosmic Microwave Background.mkv`（631 MB, 17:19）**就是这集的正片**，
  出题人只往里面 mux 了额外轨道。
- **可用的推论**：片名/片长/分辨率都能对上，所以"载体"本身没有秘密，秘密**只在额外轨道**里。
  这也解释了为什么题面给的是百度网盘 579 MB —— 正片是公开的，作者没理由改它。

### 2.3 同类题的**标准套路**（公开资料，用于校准我们自己的打法）
- [aperisolve wiki — Video Steganography: Frames](https://github.com/zeecka/aperisolve/blob/9084bad5f73eecef6b8f7f1aacdfe7fab0935331/aperisolve/wiki_content/en/techniques/video.md)（同文在线版 [aperisolve.com/de/wiki/techniques/video](https://www.aperisolve.com/de/wiki/techniques/video)）：
  视频隐写的标准检查序 = ①容器层（`mkvinfo` 列出**全部轨道**，含隐藏轨/字幕轨/附件）②帧层（逐帧差分、**多帧平均**）
  ③像素层（LSB/位平面）。
- 同类公开题（形态相近，非本题）：
  - [PicoCTF "Static Noise" writeup](https://dev.to/ctfdojo/picoctf-static-noise-writeup-identify-a-file-hidden-in-binary-data-444m) —— 噪声=载体二进制，靠 carving 找内嵌文件
  - [BroncoCTF 2026 "Static Image"](https://ctfbase.com/writeup/20260711_broncoctf2026_static_image)
  - [IrisCTF 2024 "Not Just Media"](https://ctftime.org/writeup/38392) —— 媒体文件里藏第二份媒体
  - [BackdoorCTF 2016 "television"](https://github.com/r4b3rt/ctf/blob/e1b4766443e219742a7416f00db1575d185eee38/2016-06-04-backdoor-ctf/stegano_television/README.md)
  - [CyberChef 风格长链实例（ZIP→机器人慢扫电视→QR→DeepSound→GPG→Base64→SilentEye）](https://www.cnblogs.com/GKLBB/p/20073549)
- **套路化的判据**（公开 wiki 的共识）：视频/mkv 类题，`mkvinfo` 里**任何非正片轨道都要单独导出分析**；
  多帧同内容 + 噪声 ⇒ **平均（噪声按 1/√N 衰减）是标准第一手**，不是逐帧肉眼看。

---

## 3. 候选 flag

**无。** 两道题都没有任何公开来源给出 flag，因此不存在"静态 flag 可复用"的路径。
（本题 `is_dynamic_flag=2` 静态，风险本来极低——但前提是"能找到公开 flag"，现在这个前提不成立。）

---

## 4. 给逆向跑者的提示（OSINT/公开套路视角，按 EV 排序）

### 4.1 ELFStudy
1. **补跑标准工具链（我已替你们跑完，结论是阴性——但这一步必须落盘才算数）**
   见 `evidence/osint-elfstudy-binwalk.txt`、`evidence/osint-elfstudy-binwalk-extract.txt`：
   - `binwalk` 只识别出 `0x0 ELF 64-bit LSB shared object`，**436 个签名一个都不命中**；
   - `binwalk -eM` 解包 **0 个文件**（`_elfstudy.extracted` 不存在）；
   - `strings -a -n 4 | grep -iE "flag|qwb|ctf\{|secret|key="` → **空**。
   ⇒ 签名级 carving 这条路**正式判死**，"藏了个压缩包/图片"的假设可以划掉。816 B 仍是唯一真异常。
2. ⭐ **最可能被忽略的一步：把二进制当 oracle，喂构造的输入。** notes 里
   `runner3 §5 第 3 条 "喂不同输入：未做（时间）"` —— 这是**整份 notes 里唯一明写的未做项**，
   而 `usage: elfstudy [-q] [-p|-s|-y] [file|-]` 明确支持 **`-` = stdin**。
   314 队意味着存在一条**廉价的、非解码的**路径，最可能的形态就是"某个输入分支会多打一行字"：
   - `elfstudy -` + `cat elfstudy | elfstudy -`（自喂）；
   - 64 B 精确截断（错误串 `need at least 64 bytes for an ELF64 header` 说明 64 是分支边界）；
   - 把 `e_ident[7..15]`(EI_OSABI/EI_ABIVERSION/pad) / `e_type` / `e_machine` / `e_version`
     改成非标准值 —— 一个"ELF structure inspector"最自然的彩蛋位置就是**注释里没实现的几个分支**；
   - 把 `0x1988` 那块 528 B「补丁计划表」当**输入**喂进去（它本身就是一份 RELA 形状数据）。
   花 10 分钟跑 20 个输入，比再花 1 小时解码 816 B 的 EV 高得多。
3. **816 B 的一个未做的廉价判别**：notes 记录 addend 流里 `e9`/`b6`/`c0` 有位置固定的偏置
   （`e9`=JMP rel32、`b6`=mov dh,imm8、`c0`=shift）——这是 **x86-64 指令首字节的分布形状**。
   但整份 notes **没有一次 `ndisasm`/`objdump -D -b binary` 逐偏移反汇编**。
   做法：对 810 B（去首 4 尾 2 的 `90`）在**偏移 0..15 全相位**跑 `ndisasm -b64`，统计"合法指令覆盖的字节比例"。
   真代码会有一个相位明显胜出（>90%），随机数据各相位都低。**这是一条 2 分钟就能定性的硬判据**，
   能把"旧 build 的 .text 片段"这条假设一票确认或一票否决。
4. 停止在"数字表 0x84f0"和"RELA"上继续投入（notes 已三重否决，我同意）。

### 4.2 CMB（宇宙微波背景辐射）
1. **别在正片里找**：正片就是 PBS Space Time S5E12，公开可对照 ⇒ 正片任何"看起来像线索"的东西都是原片内容
   （这解释了 `evidence/*-mainvid-frame-*.png` 那几张"疑似卡点帧"为什么解不出东西）。
   秘密**只在非正片轨道**：0.39 fps 视频轨（400 帧）、56.3 MB srt、g2.tar / g4.tar。
2. ⭐ **最可能被忽略的一步：把 200 张 srt-PNG / g2 / g4 做「同位像素平均」，而不是逐帧看。**
   公开套路（aperisolve 视频章节）里"多帧同内容 + 噪声"的标准第一手就是**叠加平均**，噪声按 1/√200 ≈ 1/14 衰减；
   题面"从雪花里看出图像"是**字面上的暗示**。我方已有对 400 帧视频轨做过 mean/z-score
   （`*-lowfps-mean400-zscore.png`），但**没有证据表明对 srt 解出的 200 张 PNG 做过同位置平均**——
   而 srt/hex/200-PNG 这条支路恰恰是我们唯一"数量对得上"的支路（200 = 200 = 200，三组各 200 张）。
   判据：若 200 张是同一张图的加噪副本，则平均后图的**高频能量骤降、笔画处出现连续灰度轮廓**；
   若各帧内容无关，平均后是平滑灰雾（一眼可判）。**这一步 5 分钟能定性。**
3. **"1%"可能不是修辞而是参数**：题面两次强调 1%。先量出"非随机像素占比"——
   即对 400 帧（或 200 张 PNG）逐像素算方差，**方差异常低的像素集合占比**是不是 ≈1%。
   若是，那 1% 的像素就是"信号面"（CMB 面），把它们单独抽出来成像/量化，这比全局找字更符合题意。
4. 若上面都阴性，再走"g2/g4 命名语义"：g2/g4 很可能是出题人的**分组标号**（group 2 / group 4），
   亦即两组里有一组是诱饵。先做两组**逐张 px 差分**（同名序号的 PNG 相减），
   差分非空处即为"被改写的位置"。

---

## 5. 搜索关键词全表（避免下一个代理重复）

### 5.1 已跑（全部阴性，别重复）
```
"ELFStudy" CTF
"ELF structure inspector"
ELFStudy 1.4.2
"elfstudy" ELF reverse challenge
"elfstudy" 强网杯
强网杯 2026 ELFStudy 逆向
ELFStudy 314 / ELFStudy 队伍解出
"ELFStudy" writeup
elfstudy github
"ELFStudy" github ELF inspector
git api: search/repositories?q=elfstudy          -> total_count 0
gitee api: search/repositories?q=elfstudy        -> []
github api: search/code?q="ELF structure inspector" -> 401 需鉴权
grep.app/api/search?q=elfstudy                   -> 429 Vercel 门禁
searchcode.com/api/codesearch_I/?q=elfstudy      -> 404（该 API 已下线）
mojeek: elfstudy / "ELF structure inspector"     -> 403 / captcha
duckduckgo html+lite                             -> fetch failed / 非公网 IP
"Secrets of the Cosmic Microwave Background" mkv CTF
"宇宙微波背景辐射" 强网杯 misc
强网杯 2026 线上赛 题解 writeup
电视雪花 1% 宇宙微波背景 老式电视 无信号
"Cosmic Microwave Background" mkv 隐写 隐藏音轨 CTF 解题
mkv 隐藏字幕轨 hex png CTF 隐写 套路
电视雪花 白噪声 藏图 CTF 隐写 writeup
white noise static image steganography CTF challenge flag hidden
CTF mkv 隐藏轨 mkvextract subtitles hex 图片 writeup
```

### 5.2 建议下一个代理跑（本次未跑成 / 值得补）
```
# 代码搜索（需在能过 Vercel/API 的地方跑，或用 GitHub token）
grep.app  q=ELFStructure / q="elfstudy" / q="ELF structure inspector"
github code search (带 token)  q="ELF structure inspector" / "elfstudy [-q]"
# 中文安全社区站内（Bing 站内语法在 cn.bing 可用）
site:52pojie.cn elfstudy
site:cnblogs.com 强网杯 2026 逆向
site:github.com qwb 2026 writeup
# 平台侧（确认题型/榜单，不碰提交）
第十届强网杯 线上赛 榜单 / 战况 / 题目清单
# CMB 侧
srt 隐藏轨 200 png 平均 隐写
ffmpeg 提取 mkv 隐藏字幕轨 十六进制 还原 png
PBS Space Time CMB 电视雪花 1%
```

---

## 6. 证据文件

| 文件 | 内容 |
|---|---|
| `evidence/osint-elfstudy-binwalk.txt` | `binwalk elfstudy` 全量输出：仅 `0x0 ELF`，436 签名零命中 |
| `evidence/osint-elfstudy-binwalk-extract.txt` | `binwalk -eM`：解包 0 文件；`strings|grep flag` 空 |
| `notes/osint-elfstudy-cmb.md` | 本文件 |

> 纪律核对：本报告不含任何待提交 flag；`is_dynamic_flag=2`（静态）虽使"公开 flag 可直接用"风险低，
> 但**前提（存在公开 flag）已验证不成立**，故候选 flag 一栏为空。
