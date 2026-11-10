## 0.2 技法参考包（2026-10-13 装入，10 个技能）

外部 CTF 技法包已装入本机技能根（`~/.dsh/skills/`，**热加载、无需重启**）。
**与 `competition-*` 的分工**：`competition-*` 给"沙箱假设 + 端到端路径 + 证据要求"，
`ctf-*` 给"**具体技法判据 + 变体清单**"。**专业题两类一起加载**，别只加载一个。

| 题型 | 技法包技能 | 参考文件 |
|---|---|---|
| Web / API / 浏览器 | `ctf-web` | 23 篇（SQLi / JWT / 反序列化 / 原型链 / web3 / CVEs …） |
| Reverse | `ctf-reverse` | 19 篇（含 WASM / 自定义 VM / 反调试） |
| Pwn | `ctf-pwn` | 23 篇（含 `scripts/` 5 个可跑 pwntools 模板） |
| Crypto | `ctf-crypto` | 19 篇（RSA / 格 / LWE / Coppersmith / PRNG …） |
| Forensic | `ctf-forensics` | 14 篇（磁盘 / 内存 / 日志 / 信号 / 音频 DTMF …） |
| Misc（编码 / 沙箱逃逸 / SDR） | `ctf-misc` | 12 篇 |
| 恶意样本 / 流量 | `ctf-malware` | 3 篇 |
| OSINT | `ctf-osint` | 3 篇 |
| AI / ML 相关 | `ctf-ai-ml` | 3 篇 |
| **图片隐写（PNG / LSB）** | `png-lsb-skills` | `scripts/png_analyzer.py` + **15 种 LSB 模式**判据 |

来源：`ljagiello/ctf-skills`（MIT，116 篇技法文档）+ `moxin1044/png-lsb-skills`（MIT-0）。
**故意没装** `solve-challenge`（与本表 PRIMARY 路由职责重叠）与 `ctf-writeup`
（与 AGENTS.md 强制的 `wp.md` 格式冲突）。
安装 / 查看 / 撤销：`bash scripts/install-ctf-skillpacks.sh [--list|--undo]`。

---

