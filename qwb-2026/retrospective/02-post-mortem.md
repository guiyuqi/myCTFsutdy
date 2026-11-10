# POST-MORTEM · 强网杯 2026 线上赛（2026-10-31 09:00 → 11-01 12:00）

> 队伍 **<team>**（<team>）｜终盘 **1201.57 分 / 12 题 / 排名 532**（`qwb-board.py`，11-01 **11:55:05** 复拉；名次仍在漂）
> 平台共 41 题（12 已解 + 29 未解）｜我方 agent **直接解出 2 题**（问卷调查、宇宙微波背景辐射），其余 10 题为队友解出
> 逐题证据：`team/EVIDENCE-INDEX.md` → `team/<题名>/EVIDENCE.md`（41 张证据卡）
> 提交台账：`evidence/submit-log.jsonl`（**749 条**，全部经 `scripts/qwb.py submit`）

---

## 1. 台账的硬数字（先看数，再看结论）

| 项 | 值 | 说明 |
|---|---|---|
| 提交总数 | **749** | 只用到了 **5 个题号**：CMB 477 / vmshare 268 / 问卷 2 / vaultlink 1 / 冒烟 1 |
| 判为正确 | **3** | CMB、问卷、vaultlink（其中 vaultlink 是平台公告补分，不是解出） |
| 判错 | **509** | 全部带 `答案错误` |
| **限流** | **235** | 223 条 `kind=throttle, result=null` + **12 条被误记成 `kind=param, result=false`** |
| 网络失败 | 1 | 10-25 的冒烟测试（`Errno 111`），不影响比赛 |
| 提交时间跨度 | 10-31 09:09 → 11-01 11:07 | 关键提交都压在最后一小时 |

**第一条结论**：我们的提交火力**极度集中**——749 条里 745 条砸在 2 道题上（CMB、vmshare），其余 39 道题几乎没有任何提交尝试。
这既是资源集中（对 2 道题打穿），也是风险集中（一错就是全错）。

---

## 2. 结构性问题（P1–P8，赛时视角；赛后对照官方 WP 的修正见 §2.5）

### P1 ★★ 把「限流」当成「判错」——本题直接多花 3 小时

- CMB 的**正确 flag 就在那 190 条限流未判候选里**，先是 `result=null`（`kind=throttle`），被枚举器按"已试过"跳过；
  最后用 `work/cmb-redo.py` 以 8 s 节奏重提，**第 5 条命中**。
- **同一个坑在 vmshare 又踩了一次**：12 条 `message=对不起，您的操作太过频繁！` 的记录被写成了 `result=false / kind=param`
  （`evidence/submit-log.jsonl` 10-31 09:09:36–09:09:41 段），任何按 `result=false` 去重的扫描器都会把这 12 条当成"已判错"。
- **根因**：`scripts/qwb.py` 早期版本把"回包里有 `答案错误` 字样"以外的异常一律记 `result=false`；
  限流与判错在台账里**长得一样**。
- **已修**：`kind=throttle` 独立成类；证据卡 §3 把「限流未判」单列成状态。
- **下次规则**：`result != true` 一律不许进"已排除"集合；限流候选必须有重试队列与重试计数。

### P2 ★★ 标准工具没先跑，锁死异常块 110 分钟

ELFStudy 平台 1431 队解出；我方 3 个跑者 ~110 分钟全部在**手工解码**（XOR/AES/RELA/字节置换/统计判据），
**从头到尾没人跑过 `binwalk` / `unblob` / `rabin2 -zz`**。已写进 `AGENTS.md` 的强制第一步（`triage-auto.sh`）。
- 证据：`team/ELFStudy/README.md`、`team/ELFStudy/EVIDENCE.md`。
- 一句话：**先认类型，再谈异常**；能用标准工具验证的，别先写解码器。

### P3 ★★ 容器题等于把 20 道题让给队长

- 29 道未解题里，**20 道零留痕**（无提交 / 无证据 / 无草稿 / 无笔记），其中绝大多数是容器题。
- 平台侧同期事实：`fault_web` 的队列排队 281 人、共享机器过载（`evidence/gMVQqQRNfKaNkYdy-recon.txt`）；
  我方在 `fault_web` 上已经拿到 teamtoken 登录与 `/api/team/status` 泄漏，**卡在排队而不是卡在技术**。
- 结论：容器是**赛制瓶颈**，不是能力瓶颈；下届若仍一队一容器池，必须赛前就把容器预算与排队策略写死
  （谁抢、抢几台、几点抢），否则 agent 的并行度全浪费在等待上。

### P4 ★ 证据/笔记归档滞后，已解出的题也要补材料

- 12 道已解题里，**6 道没有 `notes/`**（frozen、babysilent、oldsvr、cwp、ezphp、ezcms），打包自检会判"缺笔记 ⇒ 作弊风险"。
- 其中 `cwp` / `ezcms` / `ezphp` 是**我方零技术留痕**的队友解出题：本地没有脚本、没有截图、没有提交记录。
- 本次收尾已补：41 张证据卡 + 6 篇笔记（能写的写、不能确证的写"未记录"，不编）。
- **下次规则**：解题现场就要落 `notes/<题号>-<题名>.md`（哪怕只有 10 行），不要赛后回忆。

### P5 ★ 语义直觉当判据（CMB 的"读顺口"）

- 六段字形逐字都对（Lato-Semibold NCC；`1` vs `l` 用 advance-fit RMS 判：`h1dd3n_` **4.35 px** vs `hidd3n_` 28.9 px），
  但把段序想成 "S3cr3t hidden inside of cM6 stream"（顺口）⇒ 440+ 候选全灭；
  正解是 **"S3cr3t of cM6 hidden inside stream"**。
- **下次规则**：段序、字节序这类**离散未知量**不许用语义先验定；要做的是"穷举 + 真拿到判定"，而不是"想一个最像的"。

### P6 ★ 文档与证据自相矛盾（复盘时最容易被骗的一条）

收尾时逐题对照，**至少 4 处文档与证据/README 冲突**，全部已在证据卡里标注，不修不改写历史：

1. `crp-11741`：证据卡 §4 原先把 `evidence/4hwKpjMisN4Kx-Sw-static.md`（12:40 首稿：0 IOB / 228 LUT / `BRAM_L_X6Y75`）
   当权威入口，但该文件已被 `README §5.2` 判定为**错序假特征、作废**；现行结论在 `structure.md`（6 IOB / 151 LUT / `BRAM_L_X6Y25` / CARRY4 2 条）。
2. `babystar`：`notes/__vwNhULhZSlz4Fa-babystar.md` 写 TM APID `0x085`、差分 22 字节；逐帧重解析 34 份证据得到 **19 个 APID（含 `0x008`、无 `0x085`）**、
   `unsafe CFDP destination filename` 精确 **109 次**、差分 **29 B** ⇒ **README 对、notes 过期**。
3. `hoRRibleRing`：同一份 README 里 P2 在 §10:50 是"还差 P2"、在 §16:15 是"P2 否定结案"却仍保留"本机无 Sage 是硬缺口"；
   平台解出数同文出现 1 队 / 150 队 / 606 队三种（各自带时间戳）。
4. `frozen`：证据卡默认文本曾写"`work/` 均无本题文件"，而 `work/frozen/` 有 33 个文件 —— **自动统计与结论必须同源**，
   否则卡片会自我否定（已修生成器的判空条件）。

**规则**：历史快照保留、但**必须带时间戳**；引用处一律写"以 README 最新结论为准"，不要用"最新"这种相对词骗自己。

### P7 ★ 解出即失联（谁解的不知道）

- `ezcms`（11-01 08:11:44 解出）、`oldsvr`、`frozen` 三题，到终盘**队内都不知道是谁提交的**；`ezcms` 更没有脚本、没有截图、没有笔记。
- 根因：提交走的是队员各自账号，`evidence/submit-log.jsonl` **只记代理的 749 条**（且 `agent` 字段全写 `parent`，等于没记）。
- **规则**：提交台账必须记「题号 + 提交者 + 时刻 + 一句话洞点」四列，人工提交也要回填；`agent` 字段不许再用默认值。
- 附带事实：`crp-11741` 复盘时复拉 **0 队解出**（11:56，`qwb.py get`），我方 7 个证据文件 / 3814 features 的位流分析停在
  "prjxray-db 不给 `BYP_L≡BYP_ALT` 选择语义"，属"真没人做出来"的题，**不是**我方判断失误。

### P8 ★ 被门禁拒一次就放弃换写法

- `cwp` 唯一一次动态探测在 09:14:16 因命令里带 `sleep` 被门禁 `deny`（`evidence/gate-log.jsonl:82`），之后**整题动态证据为零**，
  而合规写法（`curl -i` 只读探 banner）一直是允许的。
- **规则**：门禁拒绝 ≠ 方向错；**换合规写法再试一次**，并把"被拒 → 换法"写进证据卡。

---

## 2.5 赛后对照官方/他队 WP：我们到底输在哪（2026-11-02 补）

> 官方/他队三篇 WP 已抓成本地文本：`work/wx/{pwn,web-rev,misc-crypto}.txt`（41 题全覆盖）。
> 逐题对照表：`notes/review-wp-diff/{pwn,misc-crypto,web,reverse}.md`。
> **本节要撤回前面几条"环境/赛制"结论**——赛后看清官方路径后，18 道动过手的题里**只有 3 道能归到环境/赛制**。

### 逐题一句话（官方一步 / 我们实际差在哪）

| 题（解出队数） | 官方关键一步 | 我们差在哪 | 归类 |
|---|---|---|---|
| **firmware**（438） | flag 密文 = **SM4-CTR**，`key=SM3(P)[:16]`、`iv=B[:16]`（`P=SM3("QWB2026::TWIN::DEVICE-A")[:16]`，`B=SM3("twin-ctr"‖A[:16])`） | **赛后已实跑复现**：用我方 README §2 现成的 `L=a652156b…`(=P) 与 `Y=74150ea8…`(=B)，一行 SM4-CTR 即解出 `flag{d230_5a75cf4_d8fb3e5_bae}`；我们却把密文归到"第 4 段棘轮 crc4"，`work/firmware_task/` 60 个文件里 **SM4 出现 0 次**，2³² 扫描全白 | **原语族猜错（猜想空间缺族）** |
| **vmshare**（899） | 24-bit 截断 ⇒ 3-lane 48-bit 指纹 MITM ⇒ 唯一 `0x174812/0x1AF718`，等价类 1936，提交作者原写法 `flag{3174812_31af718}` | 算法与官方**同路同结果**；输在书写先验：只提交了 `flag{3174812_31AF718}`（大写 AF），精确串 `…31af718` **一次都没提交** | **判据错（提交先验）** |
| **NeuronShuffle**（630） | 三组整数 = `default_rng(20261102).permutation(48/40/32)`；权重池由 `default_rng(20261101).normal(0,0.6,974)` 生成，靠 926 个唯一值全覆盖 + `k5[0]` 逐位相等反查种子 | 把三组整数钉成"每层类别编号"，14.6M 候选全建在错误语义上；种子窗口只到 3e5（正确 2.0e7），且判据比的是类标签 | **假设错** |
| **Dreambound**（429） | 批量**坐标下降**：固定 47 步枚举该步 4 个值 = 192 条/轮，全 4（170.51）→ 第 9 轮破 1000 → 1290.2621，纯 CPU 分钟级 | 有逐位吻合的离线 oracle，却只做随机搜索到 318，战术结论写成"梯度上升 + 退火"（官方实测 ST 梯度只有 28.26，比全 4 还差） | **没跑标准搜索** |
| **hoRRibleRing**（606） | 1025 维 Kannan 嵌入，LLL 后 **BKZ-β≈120** 顶出异常向量；判 0 要末位 ±1 行 + `BOUND=40` 复算 | **"缺环境"不成立**：fpylll 0.6.4 已装进 `work/InT2P9luOG_Em_Ee_hoRRibleRing/venv-lll`，`lll3.py:58` 已调用 `BKZ.reduction`，但 β 阶梯只到 `[10,20,30]`，随即写"不可行、勿再投入" | **判据停在试过的档位** |
| **ELFStudy**（1434） | 第一步读**元数据异常**：`TEXTREL`、`RELASZ` 比总和少一条、`0x7325` 全零后紧接高熵、`0x76c6` 是 `.rela.plt` 副本 ⇒ 重定位期自解密 | 3 个跑者 ~110 分钟手工解码，**从未跑 `readelf -lW`/`rabin2 -zz`/`binwalk`** | **没跑标准工具** |
| **oldsvr**（603） | `int16_t total` 在 65520 时截断成 0（malloc(0)+memcpy 65520）→ checked unlink 把槽指针写成 `T-0x18` → free@GOT（RELRO 只盖 `0x1ffe0–0x20000`）→ `free("cat /f*")` | 认证绕过与 unlink 都成了，但把"远端没崩"当"已触发"（实际被 `state->byte1` 静默丢弃）；`objdump` 不认 MIPS64 BE 就把"0 命中"当死代码（仓库里本有 `work/oldsvr/decompiled/server_.c`） | **判据错 + 工具失败升级成结论** |
| **babystar**（326） | 三张表当可信配置：CopyTable 第 6 条把 `0x1888+8` 的 136 B 搬到 `0x18B3+8`，MsgActs 发 0x18B3，AppMon 缺应用触发；投递走 **C 帧 APID 0x04/fc=0 三段式** | 只打通 C 通道一次性链，F 通道"无回包"就判 Proxy Put 未实现——**官方那条方向我们没打过** | **判据错 + 方向未覆盖** |
| **easytl**（1059） | identity[0x20]=`\x00` 绕过 strlen，`0x40304d` 源+长度双控；**fork 子进程 canary 相同 ⇒ 可并发 40 s 爆完** | 同一个洞已独立走到（本地 `PWNED-MARKER`），但 800–900 条连接押单线，靶机 52 ms→1–2 s 后停摆，canary 停在 4/8 | **资源 + 判据（未试并发）** |
| **babysilent**（535） | 用 CSU 拼任意 `read(3,..)`，把 flag 字节当 rbx 索引查 **256 项函数表**（命中 `leave;ret` 存活 / 未命中崩溃）⇒ 1 bit/探测 | 我们的比较式 oracle 只有"没 EOF=存活"这一负信号、会漂移（拼出 `flag{60f78P3f14` 被判错），VOTE=3 每字节 ~3 min | **判据错（无正对照）** |
| **license**（473） | 单步 SIGTRAP 解密隐藏指令 → 逐字节 gate 提取器 → 24 字节目标 → GF(2) 求逆 + 4 字节分组枚举 | 认出 stage-2 自解密、delta 派发机与三处诱饵，估 4–8 h 弃题 | **时间**（判断基本正确） |
| **cwp**（1340） | `/api/bulk` 的 `$matched`/`$checked` **双数组下标错位** → `owner_not_in` 字符串分支 implode 注入 → 改 `PUBLISH_AS` + `api_reload` → 无登录 staff → `skin_editor_write()` 落 PHP → 读 root flag | 完整链就躺在**我们已读**的 `engine.php:363-403`、`lib.php:223-228`；4 条候选里 ②`PUBLISH_AS`、③`skin_editor_write()` **命中**、④入口半命中，但我们只交了一张"可疑点清单" | **读过 ≠ 看见** |
| **fault_web**（133） | `PUT /auth/<providerID>.js`（静态后缀白名单绕鉴权）→ wellknown 配置 SSRF → `{env:}` 展开后爆 JSON 泄 Basic → `/pty`+WS 进 root → ARP 骗 runner 投毒 artifact cache | 我们拿到的 `<target>:9000` 是 **provision 门户**（`Request an Environment`，8 条 `/team/*`，自己发 `entry_url`/`public_port`），官方应用是另一套；且"0 队解出"是 13:31 快照，窗口在其后才开 | **门户≠应用 + 快照误读** |
| **Ironclad**（60） | 缓存失效条件写窄（`cmp %r10d,0x20(%rax)`），同一 DESC 跨槽 resize ⇒ UAF，再用 op14 的 SipHash 当 MAC 伪造机 | 只做了 `unzip -l` + `file`，**零反编译**——而官方发现链 100% 静态；`ironclad.sys` 42 KB 就在 `work/ironclad/attachment/` | **没跑标准工具** |
| **crp-11741**（0） | 官方 WP **没有这道题** | 我们的位流分析（151 LUT / 6 IOB / 3814 features / 帧序唯一）已到 prjxray-db 的边界 | 无人可解 |

### 三条要撤回/限定的旧结论

1. **"hoRRibleRing 缺 Sage/fpylll"→ 撤回**。fpylll 0.6.4 就在自建 venv 里，`lll3.py` 已经在调 BKZ，只是 β 只到 30。**我们把"试过的档位"写成了"路走不通"**，还写进 README 的禁区清单，断了下一棒的路。
2. **"vmshare 密钥位宽判错（28 vs 24 bit）"→ 撤回**。官方也确认 `and 0xffffff` 就是 24 bit 截断、等价类 1936；我们算法全对，**输在大小写**：精确串 `flag{3174812_31af718}` 从未提交（`submit-log` 里只有 `…31AF718`）。
3. **"fault_web 是资源/赛制，不是技术失败"→ 限定**。资源只体现在"始终没拿到应用实例（门户 entry_url 为 null）"，但真正的判据错是：**把"0 队解出 + 排队速率 −0.75/min"读成"这题没人能解"**，而官方窗口在 13:31 快照之后才开。

### 修正后的四个根因（按危害排序，取代 §2 的 P3 归因）

- **C1 判据停在"我们试过的档位"**：β 只到 30 就说不可行（hoRRibleRing）、canary 到 4/8 就停（easytl）、梯度只到 28.26 却继续写梯度方案（Dreambound）。⇒ 结论必须写成"β≤30 不够"，而不是"路不通"。
- **C2 假设钉错，枚举量再大都是零**：NeuronShuffle 14.6M、vmshare 268 次提交、firmware 2³² crc4（赛后用我们自己 README 里的两个量 + 一行 SM4-CTR 就解出了 flag）。⇒ **穷举 >10⁷ 全空时，先重写假设**。
- **C3 "静默/无变化"被当成"没有东西"**：babystar 无回包⇒判未实现（方向没打过）、oldsvr 没崩⇒判已触发（被门禁丢）、babysilent 没 EOF⇒判 alive（渠道会漂）。⇒ 任何静默结论必须附**同方向正对照**。
- **C4 "读过 ≠ 看见" / "门户 ≠ 应用" / "快照 ≠ 现状"**：cwp 的四条候选两条命中却拼不出链；fault_web 45 分钟花在门户上；"0 队解出"当死刑。⇒ 审计后必须回答"这个 handler 的输出能接上谁的输入"；拿到的入口先问"这是题目本体还是门户"；放弃前留**触发器**而不是结论。


---

## 3. 我方 agent 的实际产出（诚实账）

| 题 | 结果 | 我方贡献 |
|---|---|---|
| 宇宙微波背景辐射 | ✅ 已解出 | 队友给翻转率方法 → **我方补第六载体**（主视频 stream 0 尾部 201 帧）→ 父代理重提限流候选定段序 |
| 问卷调查 | ✅ 已解出 | 人类队员填问卷；代理只出票 + 提交（**全角 `！` U+FF01**，半角 9 秒之差判错） |
| vaultlink | 补偿分 | 平台公告授权提交固定串，**不是我方解出**，已在 `wp.md` 单列说明 |
| ELFStudy / vmshare / babysilent / oldsvr / easytl / frozen / cwp / ezphp / ezcms | 队友解出 | 我方做了并行分析但没拿到关键一步（详见各证据卡） |
| 其余 29 道未解 | ❌ | 9 道有实质投入（NeuronShuffle、hoRRibleRing、firmware、license、Dreambound、babystar、crp-11741、Ironclad、fault_web），20 道零留痕 |

**最该反思的一条**：我方把大量算力投在了**队友随后解出的题**上（ELFStudy 3 个跑者、vmshare 扫表、babysilent 全链），
信息没有互通 ⇒ 重复劳动。下届需要一条硬规则：**每题开跑前先问一次"这题现在谁在跑、跑到哪一步"**，
并把它写进 `team/<题名>/README.md` 的第一行。

---

## 4. 下次开赛前 30 分钟的检查表（可执行）

1. `bash scripts/selfcheck.sh --capabilities` 全绿；`scripts/container-pool.py` 能抢到容器（排队策略写死）。
2. 提交器版本确认：`kind=throttle` 必须与 `判错` 分离；`result != true` 不进排除集；限流重试队列有独立计数。
3. 附件到手第一枪 `bash scripts/triage-auto.sh <附件> <题号>`——**没有 triage 落盘，任何分析不算数**。
4. 每题开跑先在 `team/<题名>/README.md` 写三行：谁在跑、当前判据、下一步。
5. 赛后 30 分钟内跑 `python3 scripts/evidence-index.py` + `python3 scripts/wp-check.py`，别等打包才发现缺笔记。

---

## 5. 交付物

- `wp.md`（3 节：CMB 完整解法 / 问卷调查 / vaultlink 补分说明），`scripts/wp-check.py` 逐字节对账通过。
- `work/qwb2026-writeup-<时间>.zip`：内含 70+ 份会话 JSONL、`notes/`、`scripts/`、`evidence/`、`team/`、`wp.md`；md5 见 `wp.md` 首行。
- 证据：41 张 `team/<题名>/EVIDENCE.md` + `team/EVIDENCE-INDEX.md`（本文件是它们的方法论总结）。
