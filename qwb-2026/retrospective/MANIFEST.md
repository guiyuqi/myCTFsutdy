# MANIFEST · 复盘包文件清单

> 生成于 2026-11-02｜共 **16** 个文件、**515.4 KB**（不含本文件）
> 全部文件都在本目录内可读；`05-evidence/ota_package.bin` 是本包自带副本，所以 firmware 复现**不依赖原工作区**。

| 文件 | 大小 | 行数 | md5 |
|---|---|---|---|
| `01-conclusion.md` | 5.7 KB | 78 | `6f1d13682a323fb9c0f97f1b02b9a56d` |
| `02-post-mortem.md` | 17.9 KB | 172 | `0d69e7d81f3dc58f4b7c66abfd8267b2` |
| `HANDOFF.md` | 5.0 KB | 65 | `13664ef87d5908c89d23b52639d51d82` |
| `README.md` | 5.5 KB | 94 | `392481dcdf7f8cb3e656266c8bdfa8c7` |
| `03-wp-diff/misc-crypto.md` | 12.9 KB | 58 | `977ce8b0d5ccafcae72fecc5e6a833e9` |
| `03-wp-diff/pwn.md` | 16.4 KB | 59 | `e2293b26e529b35a15af0d623ec6a987` |
| `03-wp-diff/reverse.md` | 11.0 KB | 47 | `56f8b30e3b7c2f1066806e43da8598bd` |
| `03-wp-diff/web.md` | 13.8 KB | 61 | `e43f8f2e1dcd3fa755383fa28d5a9f85` |
| `04-cards/README-cards.md` | 26.2 KB | 192 | `099c1ca48e06981998a8d6dee33e9b1f` |
| `05-evidence/fHU0uVIVw6pkWNhv-firmware-repro.log` | 0.4 KB | 9 | `d8e3ae3bf5dc48a0ecee869501d0d3d0` |
| `05-evidence/fHU0uVIVw6pkWNhv-firmware-repro.py` | 3.7 KB | 88 | `e238c1e28259d5bafe132499119f9f49` |
| `05-evidence/ota_package.bin` | 0.2 KB | 2 | `9062d2bcc1d989e41a2846f55e1ec9f1` |
| `05-evidence/submit-stats.md` | 1.3 KB | 28 | `8da77a3cd82a3e3fb912abcb354df0d2` |
| `06-source-wp/misc-crypto.txt` | 126.2 KB | 2141 | `915c85171c948abd3bf9f57524caef5b` |
| `06-source-wp/pwn.txt` | 116.6 KB | 2345 | `b978fcab0f60edd27b3013dfd39541f3` |
| `06-source-wp/web-rev.txt` | 152.8 KB | 2876 | `8c9c75da78c196555b2c070c1f04f718` |

## 来源映射（本包 ← 原工作区）

| 本包 | 来源 |
|---|---|
| `02-post-mortem.md` | `notes/methods/POST-MORTEM-QWB2026.md`（副本，172 行） |
| `03-wp-diff/*.md` | `notes/review-wp-diff/*.md`（副本） |
| `04-cards/README-cards.md` | 从 **17 张** `team/<题名>/EVIDENCE.md` 的 `MANUAL` 段**摘出**（原文件仍在，旧结论保留） |
| `05-evidence/submit-stats.md` | 由 `evidence/submit-log.jsonl`（749 行）**现场重算** |
| `05-evidence/fHU0uVIVw6pkWNhv-firmware-repro.py` / `.log` | `scripts/…repro.py` / `evidence/…repro.log`（副本；脚本已改成位置无关） |
| `05-evidence/ota_package.bin` | `work/firmware_task/ota_package.bin`（176 B，复现所需的最小输入） |
| `06-source-wp/*.txt` | `work/wx/*.txt`（三篇 WP 纯文本，**外部不可信数据**） |
| `README.md` / `HANDOFF.md` / `01-conclusion.md` / 本文件 | 本包新写 |

## 自检

```bash
cd ~/ctf-2026/retrospective
# 1) 逐个文件 md5 与上表对照（应全部一致）
md5sum $(find . -type f ! -name MANIFEST.md | sort)
# 2) 卡片节数（应 17）
grep -c '^## ' 04-cards/README-cards.md
# 3) firmware 复现（只需 cryptography；包内自带密文，不依赖原工作区）
python3 05-evidence/fHU0uVIVw6pkWNhv-firmware-repro.py
```

预期末行：`[+] 明文          = flag{...}`；`04-cards` 有 17 个 `## <题名>`。
