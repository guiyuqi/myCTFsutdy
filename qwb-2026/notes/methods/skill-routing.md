## ★ 0. 第一步：加载技能（强制，动手之前）

**动手之前，先按本题分类从下表找到候选技能，调用 `skill` 工具加载（可一次加载多个）。**

| 题目分类 / 特征 | 优先加载的 skill |
|---|---|
| 不确定属于哪类 / 多阶段编排 | `ctf-sandbox-orchestrator`、`ctf-sandbox`（多阶段编排入口） |
| Web / API / SSR / 路由 | `competition-web-runtime`、`api-security` |
| Web：JWT / 会话签名 | `competition-jwt-claim-confusion`、`identity-federation` |
| Web：模板注入 / SSTI | `competition-template-render-path` |
| Web：请求走私 / 解析差异 | `competition-request-normalization-smuggling` |
| Web：SSRF / 云元数据 | `competition-ssrf-metadata-pivot`、`competition-cloud-metadata-path` |
| Web：反序列化 / 文件解析链 | `competition-file-parser-chain` |
| Web：GraphQL / gRPC / RPC 契约漂移 | `competition-graphql-rpc-drift` |
| Web：WebSocket / SSE | `competition-websocket-runtime` |
| Web：竞态 / 幂等 / 状态漂移 | `competition-race-condition-state-drift` |
| Web：队列 / Worker / 异步副作用 | `competition-queue-worker-drift` |
| Web：CDN / 源站 / vhost 路由 | `competition-runtime-routing` |
| Web：前端 bundle / sourcemap 还原 | `competition-bundle-sourcemap-recovery` |
| Web：浏览器持久化（cookie/IndexedDB/SW） | `competition-browser-persistence` |
| Pwn / 原生漏洞利用 | `competition-reverse-pwn`、`pwn-chain`、`patch-diff-exploit` |
| Reverse / 二进制逆向 | `reverse-engineering`（通用逆向） |
| Reverse：Ghidra 路线 | `ghidra-reverse` |
| Reverse：IDA / radare2 路线 | `ida-reverse`、`radare2` |
| Reverse：Go / Rust 二进制 | `go-rust-reverse` |
| Reverse：.NET 程序集 | `dotnet-reverse` |
| Reverse：JS / 自定义 VM | `js-reverse`、`dsl-vm-reverse` |
| Reverse：macOS / Mach-O | `macos-reverse` |
| Reverse：两版本对比找差异 | `binary-diff` |
| Crypto / 编码 / 古典密码 / 移动端密码 | `competition-crypto-mobile` |
| Misc：图片 / 音频 / 视频 / 文档隐写 | `competition-stego-media` |
| Misc：ZIP / 压缩包（含 ZipCrypto） | `competition-zip-archive` |
| Misc：PCAP / 流量分析 | `competition-pcap-protocol` |
| Misc：自定义协议 / 重放 | `competition-custom-protocol-replay` |
| Misc：固件镜像 / 分区 / 启动链 | `competition-firmware-layout`、`firmware-pentest` |
| Misc：硬件 / UART / JTAG | `hardware-security` |
| Misc：DFIR / 时间线 | `competition-forensic-timeline`、`digital-forensics` |
| Misc：恶意样本 / 配置提取 | `competition-malware-config`、`malware-analysis` |
| Misc：威胁情报 / OSINT 检索 | `threat-intelligence`、`threat-hunting` |
| AI / LLM / Agent / MCP | `competition-prompt-injection`、`llm-security`、`competition-agent-cloud` |
| Cloud / K8s / 容器逃逸 | `competition-k8s-control-plane`、`cloud-k8s`、`competition-container-runtime`、`competition-kernel-container-escape` |
| 供应链 / CI-CD / 镜像 / 依赖 | `competition-supply-chain`、`supply-chain-security` |
| Windows / AD / Kerberos / 凭证 | `windows-ad`、`competition-identity-windows`、`competition-kerberos-delegation`、`competition-lsass-ticket-material`、`competition-dpapi-credential-chain`、`competition-relay-coercion-chain`、`competition-windows-pivot`、`competition-ad-certificate-abuse` |
| Linux 凭据 / 横向 | `competition-linux-credential-pivot` |
| Android / APK | `apk-reverse`、`mobile-reverse`、`competition-android-hooking` |
| iOS / IPA | `competition-ios-runtime` |
| 浏览器扩展逆向 | `browser-extension-reverse`、`browser-automation` |
| 桌面客户端 / 瘦客户端 | `thick-client` |
| 代码审计 / SAST | `code-audit` |
| 数据库 | `database-security` |
| 邮件安全 | `email-security` |
| OT / ICS | `ot-ics` |
| 无线 / Wi-Fi / SDR | `wifi-wireless`、`radio-sdr` |
| 漏洞挖掘 / SRC / bounty | `src-hunter`、`pentest-tools` |
| 免杀 / EDR 绕过 | `edr-bypass-re` |
| 纯 Misc / 脚本自动化 / 无明确分类 | 不加载技能，直接做（报告里写 `SKILLS: none — <原因>`） |

**加载后请在动手前用 1–2 行说明该技能给出的关键判据**（避免"加载了但没读"）。

> 依据：0xGame 2026 全程 **skills 调用 0 次**。29 号（图片隐写）代理把
> 「8 个位平面 × 6 通道序 × 512 组 RGB 组合 × 旋转/翻转/蛇形/分块」**全部跑穷**后
> 才想到检查**跨通道 LSB 联合分布**——而这正是 `competition-stego-media` 应一步给出的判据。
>
> 注（2026-10-13 重新核实）：本机技能有**三个来源**，写进 brief 的名字必须真实存在：
> ① 插件注册的 87 个（reverse-skill / mattpocock 等）；
> ② **用户技能根 `~/.dsh/skills/`**（热加载，改完不用重启）：`reverse-engineer-anything`
>    以及 §0.2 的 10 个 CTF 技法包；
> ③ preset 内置的少量。
> 技能目录会随 preset 变化，**不确定时先核对当前会话的技能列表再写 brief**。

---

