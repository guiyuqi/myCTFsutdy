<!-- 本文件由 WP-INDEX.md + 3 篇逐题 WP 合并且顺序整理，用于提交与归档 -->

# 2026 第十届强网杯 · 车联网安全专项赛（CTF 遴选赛）Write-up 总说明

> 队伍：<team>｜赛场时间：2026-11-08 09:00–12:00
> 本文档是 WP 的**索引与提交说明**；每题正文见同目录 `WP-*.md`。
> 赛况快照（11:45）：**总得分 630 PT · 排名第 48 名 · 解出 3 道 · 一血 1 个**。

---

## 1. 本队解出题目

| 题号/题名 | 分类 | FLAG | 详细 WP |
|---|---|---|---|
| `iov-重生的种子` | REVERSE | `flag{BCM_MLKEM_s33d_r3us3_und3r_v0lt4g3_gl1tch}` | `WP-run-37596.md` |
| `re-Route97 的副歌` | REVERSE | `flag{R0ute97_Ch0rus_Encore_2026}` | `WP-run-63775.md` |
| `NL-BCM 车身控制器（BCM_UPDATE.fwpk）` | REVERSE | `flag{767a9ca2-ef9a-44b8-a0a3-7656457b0907}` | `WP-run-363803.md` |

> 每篇 WP 的结构：**一句话结论 → 题面 → 环境与附件 → 解题路径（按事实整理）→ 操作流水（真实命令）→ 关键结论与复现 → AI 协作说明**。
> 标 `【需确认】` 的地方是推断，不作为结论。

## 2. 提交物怎么分（建议）

| 材料 | 形式 | 说明 |
|---|---|---|
| **Write-up** | 本目录的 Markdown（可另存 PDF） | 正文；每题一篇 |
| **AI 对话记录** | **单独成包** `upload-*/`（`conversations/` + `runs/` + `ledger.jsonl` + `INDEX.md`） | 不并入 WP 正文，WP 第 6 节指向它 |
| **录屏** | 按手册要求单独提交（网盘永久链接 + 提取码，发 `taichu@secdeer.com`） | 手册第八条：未按时提交录屏 ⇒ 全队得分清零 |


### 2.1 对话包下载（网盘）

| 项 | 值 |
|---|---|
| 文件 | `qwb2026-iov-conversation-package.tar.gz`（24 MB，71 个文件） |
| 链接 | https://pan.baidu.com/s/1xyfMHkQbwHGgtVn5gsHTdQ?pwd=fyt2 |
| 提取码 | `fyt2` |
| SHA-256 | `d30e69256f02a38a3fd22aafc82016cd3b1568aea3dfd02dd96bb3daae48cd5b` |

包内结构：`conversations/`（30 个会话记录：人读版 `.md` + 原始 `.jsonl`）、`runs/`（28 个 run 的事件流）、
`wp/`（本 PDF 的 Markdown 源）、`ledger.jsonl`（台账）、`INDEX.md`（清单 + 已解 flag + 脱敏记录）。

> 校验方式：下载后 `sha256sum qwb2026-iov-conversation-package.tar.gz` 应等于上表值。
> 若网盘分享有时间限制，请以永久链接重新分享（手册对录屏材料要求"永久有效"，对话包建议同样处理）。

**为什么对话记录不塞进 WP**：

1. 体量：完整对话 + 事件流是**百 MB 级**，塞进 WP 会让文档无法打开/无法上传；
2. 可读性：WP 应是可读的解题叙述，过程材料是附证；
3. 评审需要时能定位：对话包里有 `INDEX.md` 与按 run 分文件的事件流，比夹在 WP 里更好查。

**如果平台只允许一个附件**：把 WP 正文（本目录 3 篇 + 本文件）打成一个包，对话包按录屏同样的方式放网盘并在 WP 第 6 节给出链接与 sha256；**不要把两个包合并成一个巨型压缩包**。

## 3. 对话包的生成方式（可复现）

```bash
cd ~/.ctfagent
./tools/package_upload.sh              # 生成 upload-<MMDD-HHMM>/
./tools/package_upload.sh --with-full  # 需要未删减原始事件流时（体积大）
```

包内容：

- `conversations/` —— 本机 agent 会话（人读版 `.md` + 原始 `.jsonl`），含主会话与全部子代理会话；
- `runs/` —— 每个 muteki run 的事件流（工具调用 / 事实 / 成本 / 结束事件；`reasoning.delta` 已删以控制体积）；
- `ledger.jsonl` —— 台账（题 / 族 / 尝试 / 判死 / 人解）；
- `INDEX.md` —— 清单、已解 flag、脱敏与瘦身记录。

**脱敏**：打包脚本会二进制安全地扫描并替换 `sk-…`/`AKIA…`/`ghp_…` 形态的密钥；本次打包后发现 1 条历史 key
（出现在**赛前安装/排障会话**里，非比赛会话），已替换为 `sk-REDACTED-BY-PACKAGER`，复核 0 命中。

## 4. 未解出的题（如实记录，便于质询）

本队对以下题做了大量投入但未取得 flag，过程与负面结论都在对话包里可查：

| 题 | 做到哪 | 卡在哪 |
|---|---|---|
| `re-LastIgnition` | 校验链完整逆出（`H1=SHA256("LI7/view\0"+cred)` → 779B 字节码 VM → `HMAC-SHA256(key=H1, msg="LI7/tag\0"+bundle[0:0x24]+bundle[0x44:])==bundle[0x24:0x44]`）；做出 0.1ms/候选离线 oracle | 已穷举 128 万窗口当 H1、约 260 万当 cred，全 0；`view` 表是运行时用公开元数据解出的 `LI5BNDL`，与 cred 无关 ⇒ `cred` 必须是 H1 的 SHA256 前像 |
| `iov-静默译码` | 容器 100% 解开（HQC 参数、字段布局、偏移修正）；短消息爆破 17 亿次 GCM 认证 | 0 命中；发现 `payload` 仅 75B 与 `n12|ct48|t16=76` 不自洽 |
| `iov-猎隼折翼` | 侧信道对齐彻底解开（`replicate=2` 真身、`trace_indices` 是窗口序号、256 对 100% 合法、491/512 无歧义、σ≈4） | 卡在"密钥序列化 + KDF 形式"，40 KDF × 18 序列化 × 5 nonce × 4 aad 全 0 |
| `iov-车内总线摆渡` | UDS 通道字段名 `isotp`（`[PCI][UDS]`）、`0x7e0/0x7e8`、seed 随机、目标 DID `F1B2` | `27` SecurityAccess 全被拒；白名单 `0x22/0x10/0x19` 路线也未通 |

## 5. 合规声明

- 全程只使用题目提供的附件与官方靶场地址；**未使用漏洞扫描器**，未对平台任何接口做批量请求；
- flag 均由人工核对来源后提交，未做批量提交；
- 题目文件一律只读，未修改原件；所有产物在工作区/对话包内可查。

---

# iov-重生的种子（BCM-A3 密钥灌注） — Write-up

> 证据来源：muteki run `run-37596`（时长 ≈4 分钟，事件 47918 条）。本文由事件流自动生成草稿，叙述部分请人复核；标 `【需确认】` 的地方是推断，未经验证。

**FLAG：** `flag{BCM_MLKEM_s33d_r3us3_und3r_v0lt4g3_gl1tch}`

## 0. 一句话结论（人写）

BCM-A3 产线做 **ML-KEM-768** 诊断密钥灌注时工位电源连续跌落，导致 3 个灌注槽（`fault_slots=3,9,14`）的种子被复用。
利用种子复用恢复出共享密钥 `s`，进而还原该次会话的 `K_fin9`，用
`AES-256-GCM(key=SHA256(kdf_prefix‖K_fin9), nonce=payload[0:12], aad=payload_aad)` 解开 `payload` 得到 flag。

**关键判据**：`payload` 的 GCM tag 能验证通过（认证自证），且明文以 `flag{` 开头。

**核心产物**：`shared/ks_search.py`（已知明文 `flag{` 驱动的快速 keystream 扫描）、`shared/se.pkl`（恢复出的共享 `s`）。

## 1. 题面

某车型 BCM-A3 在产线做诊断密钥灌注。7 月 14 日工位电源,出现连续电压跌落，之后出现了灌注记录异常。BCM 的私钥在灌注后写入安全存储，从未导出。我们从产线工装恢复了这次灌注使用的 OTA 固件包。请你分析异常，获取flag。

## 2. 环境与附件

- 附件与工作区：`state/sessions/run-37596/workspace/`（下表为其中 >2KB 的产物）
- 工具链：binwalk / unblob / unsquashfs / 7z / r2 / gdb-multiarch / qemu-*-static / ghidra(analyzeHeadless) / python3(capstone,pwntools,lief,z3,angr,unicorn,Crypto) / wine

| 产物 | 大小 |
|---|---|
| `work/rootfs.cpio` | 78476 B |
| `bcm_provisioning_ota.bin.zip` | 61638 B |
| `inputs/by-name/bcm_provisioning_ota.bin.zip` | 61638 B |
| `inputs/objects/30/47/3047b0c3342cb28cd01cee2129574fa36333aa5ebe12a5f8d8ef93a275398aa3` | 61638 B |
| `work/bcm_provisioning_ota.bin` | 61158 B |
| `work/rootfs.cpio.gz` | 60586 B |
| `shared/live/graph.yaml` | 50204 B |
| `arts/ff46979a2f0d.txt` | 40120 B |
| `bcm-prov` | 39408 B |
| `work/bcm-prov` | 39408 B |
| `work/ext_usr_sbin_bcm-prov` | 39408 B |
| `work/ext_etc_bcm_diag.bin` | 37604 B |
| `work/diag.pkl` | 37596 B |
| `arts/2ddd54e33aec.txt` | 36788 B |
| `arts/ad9a5280d04e.txt` | 20536 B |
| `arts/37083feaeaec.txt` | 20516 B |
| `arts/630bf5cfd05e.txt` | 20075 B |
| `arts/e5c02bd5c427.txt` | 19916 B |
| `arts/8c3ee266f805.txt` | 18983 B |
| `shared/hs.pkl` | 18144 B |
| `arts/689c1a4cd15a.txt` | 15955 B |
| `arts/7e82aa7c7ec8.txt` | 14614 B |
| `arts/af45e6606fcc.txt` | 14489 B |
| `arts/e5092a58ab2b.txt` | 12974 B |
| `shared/known3.pkl` | 11878 B |

## 3. 解题路径（按事实整理，需人工顺一遍）

1. **题目信息:**

   ```text
   某车型 BCM-A3 在产线做诊断密钥灌注。7 月 14 日工位电源,出现连续电压跌落，之后出现了灌注记录异常。BCM 的私钥在灌注后写入安全存储，从未导出。我们从产线工装恢复了这次灌注使用的 OTA 固件包。请你分析异常，获取flag。
   附件: bcm_provisioning_ota.bin.zip
   ```

2. **OTA 包已完整解包：内含 BCMDIAG1 诊断记录(keylog/handshake/payload/config)，密钥尺寸为 ML-KEM-768，fault_slots=3,9,14**

   ```text
   已完成附件解析与格式逆向（可复用，脚本/数据在 cwd 的 work/ 下）：
   
   1) bcm_provisioning_ota.bin (61158B) 头为 "BCMOTA01"，BE 字段：ver=1@0x08, 0@0x0c, count=3@0x10, table_off=0x40@0x14；每项 0x40B：id/off/len/flags(各4B BE)+sha256(32B)+name(16B)。
      条目：id1 manifest.json off=0x100 len=267；id2 rootfs.cpio.gz off=0x20c len=60586 (sha256 与 manifest 中 rootfs_sha256 一致)；id4 build.meta off=0xeeb8 len=46。注意 **id 3 缺失**（id 序列 1,2,4），但文件字节被完全覆盖无隐藏尾数据；__MACOSX/._* 仅为 quarantine 属性，无内容。
   2) rootfs.cpio.gz 解出 4 个文件：etc/os-release、etc/bcm/diag.bin(37604B)、etc/bcm/version、etc/init.d/S30bcm(/usr/sbin/bcm-prov report)、usr/sbin/bcm-prov(ELF aarch64 静态 stripped)。
   3) 用 toolbox 的 qemu-aarch64-static 可运行 bcm-prov（只有解析/报告功能，.rodata 仅 0x1062B 且无任何密码学常量/AES S-box/Keccak RC，so 无解密逻辑）：
      `qemu-aarch64-static ./bcm-prov report ext_etc_bcm_diag.bin` 成功。
   4) diag.bin 格式：magic "BCMDIAG1" + ver=1(LE) + flags + count=4 + hdr=0x40；每项 0x20B：id(LE)/off(LE)/len(LE)/name(16B)。记录：1 keylog off=0xc0 len=19068；2 handshake off=0x4b3c len=18124；3 payload off=0x9208 len=75（密文）；4 config off=0x9254 len=143（明文文本）。
   5) keylog 记录：magic "BCMKLOG1" + count=16(BE)；每槽头 7B = ts(4B BE，值 0x20260714 起逐 1 递增) + slot(1B) + eklen(2B BE)，随后 eklen 字节；eklen 全部 =1184（=ML-KEM-768 封装公钥长度），12+16*1191=19068 完全对齐。
   6) handshake 记录：magic "BCMHS01" + count=16(**LE**)；每槽 = slot(1B)+pad(3)+ctlen(4B LE=1088，=ML-KEM-768 密文长度)+ct(1088B)+taglen(4B LE=32)+tag(32B)。
   7) config 明文关键内容：product=BCM-A3, build=2.4.1, provision_mode=2, **fault_slots=3,9,14**, kdf_prefix=BCM-DIAG-KDF-v1, payload_aad=BCM-DIAG-PAYLOAD, ack_msg=BCM/DIAG/ACK/v1。
   8) 已做的阴性检查（见 mark-deadend 范畴）：16 个 ek 两两不同且字节分布均匀（无长重复 run、无 16B 重复块、fault 槽也无部分写残留/与其它槽后缀相同）；16 个 ct 的 u 部分(前960B)/整体互不相同（无封装随机数重用）；tag 不等于 sha256/sha3-256/shake128-256/blake2s/blake2b 对 ek、ct、payload、config 的直接哈希；payload 与任意 ek/ct 的任意 75B 窗口异或均无高可打印结果；全文件无 "flag{"；不是 MT19937 随机流（对 diag.bin 与 OTA 全偏移按 LE/BE 各做 untemper+twist 预测，均无命中）。
   9) 下一步高价值方向：fault_slots=3,9,14 暗示这 3 个槽的 ML-KEM 密钥生成被电压跌落注入故障（例如误差项 e 置零 → t̂=Â∘ŝ 可解）；需要实现 ML-KEM-768 的 SampleNTT/Decompress_12/NTT 求解/封装验证，用 tag(32B) 或 payload(75B，疑似 AEAD：59B明文+16B tag) 作为判别器。注意 ek 是 12-bit 压缩的，解出 ŝ 存在压缩取整误差，需考虑 LWR 求解或其它故障模型。
   ```

3. **OTA 包已完整解包：内含 BCMDIAG1 诊断记录(keylog/handshake/payload/config)，密钥尺寸为 ML-KEM-768，fault_slots=3,9,14**

4. **ML-KEM 故障模型排除: ek 的 t 为精确 12bit(无压缩误差); 16 槽 ct 随机性均匀; s=0 与 tag=直接KDF 两类模型证伪; SampleNTT 已与 kyber-py 逐值对齐(NTT 约定待校正)**

   ```text
   本轮（Campaign B）实测增量，脚本在 shared/（mlkem.py / solve.py / decaps.py / an_ek.py / an_hs.py / try_tag_key.py / try_s0.py）：
   
   1) 修正 fact_001 的一处前提：ek 的 t 部分是精确的 12-bit ByteEncode_12（FIPS 203 中 ML-KEM-768 的 t 不做压缩）。16 个 ek 各解出 768 个系数，全部落在 [0,3328]（max=3327/3328，mean≈1635~1700，std≈950）→ 不存在"12-bit 压缩取整误差/LWR 问题"；若故障为 e=0 则可直接得到精确 ŝ，无需格约化。
   
   2) handshake 的 16 个 ct 逐槽统计（u=768 系数@10bit=960B，v=256 系数@4bit=128B）：u 均值 490~530/1024、v 均值 6.9~8.1/16、零系数个数与随机期望一致；fault 槽 3/9/14 与正常槽无差异 → 封装端随机数未被打断/置零（排除 ct 侧 r/e1/e2 置零模型）。
   
   3) 测试故障=误差项 e 置零（t̂=Â∘ŝ）：对每个 NTT 系数对在 Z_q[X]/(X²+1) 上以 X=±sqrt(-1)（sqrt(-1)=1729 mod 3329）拆分解 3x3 系统。结果全部 16 槽（含 3/9/14）解出的 ŝ 系数均为均匀分布（max|centered|≈1659~1664），而非 |coef|≤2 → 该模型在我的 NTT 约定下不成立。Caveat：我的 ntt/basemul 已用朴素负循环卷积自校验通过，但与本机 kyber-py 1.2.0 的 to_ntt 逐值比对不一致（约定/缩放差异未定位），故此条排除需先用参考实现校正 NTT 输出序/index 后再确认，不能当终局结论。
   
   4) 测试故障=秘密 s 置零（此时 t=e 同样呈均匀，与观测吻合）：用 sk=0 做完整 K-PKE.Decrypt + ML-KEM.Decaps（K=SHAKE256(SHA3-512(m||H(ek))||H(c),32)），16 个槽算出的 K / SHA256(K) / m / SHA256(m) / SHAKE256(K) 均不等于该槽 handshake 的 32B tag → s=0 模型证伪。该测试只依赖 ct 解压与 Compress_1、不依赖 A 矩阵约定，结论稳固。
   
   5) 测试 handshake 的 32B tag 是共享秘密 K 或其直接 KDF：16 槽 × 约 20 种派生（raw；SHA256/SHA3-256/SHAKE256 与 kdf_prefix/payload_aad/ack_msg/ek/ct 的各种拼接；HKDF-SHA256）× 5 种 AEAD 组合（AES-GCM nonce=0/tag[:12]/ct[:12]、ChaCha20-Poly1305 nonce=0/tag[:12]，AAD=BCM-DIAG-PAYLOAD，ct=payload[:59]、tag=payload[59:75]，payload 共 75B）全部认证失败 → tag 不是这些形式的直接密钥材料。
   
   6) 附带：bcm-prov 有隐藏子命令 selftest；`qemu-aarch64-static work/bcm-prov selftest work/ext_etc_bcm_diag.bin` 输出固定串 "selftest normal=1" / "selftest fault=0 seed0=11"，不随参数变化，未泄露种子逻辑。
   ```

5. **ML-KEM 故障模型排除: ek 的 t 为精确 12bit(无压缩误差); 16 槽 ct 随机性均匀; s=0 与 tag=直接KDF 两类模型证伪; SampleNTT 已与 kyber-py 逐值对齐(NTT 约定待校正)**

6. **ek 中 t 为未压缩的 raw t mod q（12bit 打包）；密文 u/v 为标准压缩且非退化；e=0 故障模型已在槽 0/3/9/14 排除**

   ```text
   本轮新增实测（脚本已落地 cwd/shared/：parse_diag.py、kyber.py、solve_s.py）：
   
   1) 格式修正（重要）：16 个槽 ek[0:1152] 按 12-bit 小端解包后全部 768 个值都 < 3329（各槽 max∈[3318,3328]，min∈[0,6]，无一 >3328）。标准 ML-KEM 存 Compress_12(t̂)（值域 0..4095），故本包是自定义包法：直接 12bit 存 raw t mod q（无损），ek[1152:1184]=ρ。→ 每槽 t 精确已知，问题只剩由 (A,t) 求 s/e。packing：v0=b0|((b1&0xF)<<8)，v1=(b1>>4)|(b2<<4)，每 3B 两值。
   
   2) handshake ct 为标准 ML-KEM-768 压缩：u=3×320B(10bit，值0..1023)、v=128B(4bit，0..15)。16 槽 u 均非全零(n0≤6/768)，v 均用满 16 值(distinct_v=16) → 封装侧 r/e1/e2 被清零的模型不成立。
   
   3) 用参考语义实现 Kyber NTT/basemul/tomont 并自测：ntt(negacyclic a*b)==2285·basemul(ntt a, ntt b)（2285=2^16 mod q），invntt(ntt(x))==2285·x。由此把 t=tomont(basemul_acc(A,ŝ)) 写成每 quad 12×12 模 q 线性映射（3 多项式×4 系数），逐 quad 高斯消元精确求解（无奇异块）。A 取序唯一确定为 A[i][j]=SampleNTT(ρ||j||i)（转置与否等价）。
   
   4) 阴性（排除 e=0 故障模型）：对 slot 0/3/9/14 解出 ŝ 后 InvNTT 并居中化，256 系数全部 |c|>2（max≈1645..1663），tomont 与非 tomont 两变体皆然；真 s 服从 η=2 CBD（|s_i|≤2）。故"噪声 e 被清零 ⇒ t=A·s"不成立；非故障槽 0 与故障槽 3/9/14 在此模型下无差别，e 仍非零。
   
   5) 判别器就绪：每槽 tag(32B)、75B payload（59B+16B，疑似 AEAD）；config 给 kdf_prefix=BCM-DIAG-KDF-v1、payload_aad=BCM-DIAG-PAYLOAD。后续可直接复用 shared/kyber.py 做完整 keygen/encaps/decaps 自测后尝试：ŝ=0 假设解封（w=v→m=Compress_1(v)）、噪声种子全零 s=cbd2(SHAKE128(0^32||n))、以及"猜 m 后仅用公开 ek 重加密校验 c'==ct"判据。
   ```

7. **用 kyber-py 参考实现排除多条"可知随机数/隐式拒绝/密钥字段互换"路径；selftest 的 seed0=0x11 是硬编码常量，OTA/zip 无隐藏数据**

   ```text
   本轮（bootstrap/root A g3）实测增量，脚本在 shared/（t1.py、t2.py、try_implicit.py、test_as_secret.py、test_sigma.py、inspect_hs.py），kyber-py 1.2.0 重装于 /tmp/kpylib（脚本内 sys.path.append，勿用 PYTHONPATH 覆盖默认 pylibs）：
   
   1) 格式前提校正并确认：本包 ek 的 t 部分就是 FIPS 203 的 ByteEncode_12 原始 t̂（每 3 字节 2 系数：a=b0|((b1&0xF)<<8), b=(b1>>4)|(b2<<4)），不是"自定义 raw 12bit 包法"；rho 在末尾 32B。用 kyber_py 的 decode/encode(12) 可无损往返（无 Modulus check 失败），ek 可直接喂给参考实现做封装。
   
   2) 排除"ek 字段其实是私钥 ŝ"（电源跌落写错变量）：把每槽 ek[:1152] 当作 dk_pke 解出 m' 并计算 w=v−ŝ^T u，w 相对 Decompress1(Compress1(w)) 的残差系数全为均匀（max residual=1664，<100 的系数约 122~141/256，与随机一致）；若为真私钥残差应≈噪声（很小）。16 槽皆然 → ek[:1152] 是公钥 t，不是 s。
   
   3) 排除"封装随机数 m 退化为简单常量"：对 16 槽用参考 _encaps_internal(ek,m)（r 按 FIPS 由 G(m||H(ek)) 派生）试 m=0^32、0x11*32、bytes(range(32))，无一槽的 ct 与 handshake 的 1088B 密文相等（也试过 m=0 且 r=0 的手工变体，仍不等）。
   
   4) 排除"故障槽 ct 解密失败走隐式拒绝且 z 为简单值"：对每槽计算 K=SHAKE256(z||ct)（z=0^32、0x11*32）以及 K=G(m'||H(ek))[0:32]（m'∈{0, Compress_1(v), 0x11*32}），再试 tag 的 ~10 种派生（原值/SHA256/SHA3-256/SHAKE256/HMAC(K,ack/prefix/empty)/拼接）与 payload 的 AEAD 解密（AES-GCM/ChaCha20-Poly1305，nonce∈{0^12,ct[:12],tag[:12]}，AAD∈{BCM-DIAG-PAYLOAD,'',BCM/DIAG/ACK/v1}，key 经 ~18 种 KDF 变体含 HKDF-SHA256）。全部不匹配 → 该 32B tag 不是这些 K 的直接 KDF，payload 也不是这些 K 的标准 AEAD。
   
   5) 排除"keygen 噪声种子 sigma 退化为简单值"：rho 取自文件，仅枚举 sigma∈{0^32,0x11*32,range(32),ts 大/小端重复,sha256/sha3/sha3-512(ts),sha256(ASCII ts),rho,rhu 哈希,slot 重复}，用 _generate_matrix_from_seed + PRF/CBD 复算 t̂ 并与文件 t 逐系数比较，16 槽全不匹配（含 fault 槽 3/9/14）→ 噪声种子不是这些简单值。
   
   6) selftest 是硬编码输出，非计算：反汇编（capstone，.text 文件偏移=vaddr−0x1010000）显示 0x1012ba8 处先 printf("selftest normal=%d",1)，随后 printf("selftest fault=%d seed0=%02x",0,0x11)，0x11 为立即数。故 fact_002 中 "seed0=11" 不是从 bundle/种子算出的线索，不能用于推导 RNG 种子。
   ```

8. **用 kyber-py 参考实现排除多条"可知随机数/隐式拒绝/密钥字段互换"路径；selftest 的 seed0=0x11 是硬编码常量，OTA/zip 无隐藏数据**

9. **共享 decaps.py 存在致命 bug(缺 ntt(u))；已验证正确的 KEM 管线与判别器；"仅用公钥从 Compress_10(u) 反解 y" 的攻击因量化误差放大而失败**

   ```text
   本轮（Campaign B g3）实测增量。全部基于 shared/attack_pub.py（已落盘，含完整自测，可复用）：
   
   1) 验证 shared/mlkem.py 的 NTT 约定正确（可作为 ground truth）：invntt(ntt(a))==a；invntt(basemul_ntt(ntt a, ntt b)) 与朴素负循环卷积逐系数相等；且 (t̂ = Â∘ŝ+ê) 与正常域 negacyclic 计算逐系数一致，Â[i][j]=SampleNTT(ρ‖j‖i)（转置由 u_i=Σ_j Â[j][i]∘ŷ_j 承担）。故 fact_002/003 中"e=0 排除"的 NTT 自洽性前提成立。
   
   2) **重要 BUG（影响后续复用）**：shared/decaps.py 的 pke_decrypt 写成 `acc += basemul_ntt(u[i], sh[i])`，其中 u 是经 dexpand 的**正常域**多项式，缺少 `ntt(u[i])`。用合成的 keygen/encaps 自测：错误版本 residual max=832/mean=422（等同无信息，且 m 恢复失败）；补上 ntt(u) 后 residual max=198、m 恢复成功。⇒ 任何用 decaps.py 得到的 s≠0 的解封结果都无效（fact_002 的 s=0 排除仍成立，因为 basemul(x,0)=0 与该 bug 无关）。
      另：shared/mlkem.py 的 cbd2 断言 len==64 是错的，η=2 时 PRF 输出应为 64·η=128 字节（否则 IndexError）。修正版逻辑见 attack_pub.py 的 cbd2/prf。
   
   3) 量化判别器（可复用于任何"已知 m/已知噪声"检验）：invntt 正常域残差 residual(w)=dist(w,{0,1665})。实测基线：正确解密时 max≈198（含 η=2 噪声）；若 ct 无封装噪声(e1=e2=0)则 v 的 4-bit 量化误差上限 ≈104（用真 y 复算实测 max=104）；随机/错误则为 mean≈416、max=832（均匀）。⇒ 可用 threshold≈150 判"解对"。
   
   4) 阴性（有界）结论：新鲜假设"故障落在封装侧(e1=e2=0)，故仅用公开 ek+ct 即可公开解出 m"在**朴素实现**下不可行——由 10-bit 压缩的 u 反解 ŷ=(Â^T)^{-1}û 时，Compress_10 的舍入(±1.6/系数)被 Â^{-1} 放大，导致 yrec≠y 且 residual 落到均匀区(max=832/mean=416)，即使原始 ct 确实无噪声也一样。要救活该路线必须做带舍入的格求解/LLL（而非直接解线性方程组）。测试范围：合成自测(noiseless ct)+16 槽约定变体尚未跑完；真实数据上该模型未获正证据。
   
   5) 已完成但未跑完的部分（时间原因，交接给后继）：attack_pub.py 内 solve_y() 在**精确 u**下可逐系数完全恢复 ŷ（已验证），可直接复用于"若 u 未被压缩或仅在少量系数上有故障"的场景；run 真实 16 槽需在 solve_y 前把 u 的量化误差纳入（或改判据用 max-min 残差分布）。
   ```

10. **共享 decaps.py 存在致命 bug(缺 ntt(u))；已验证正确的 KEM 管线与判别器；"仅用公钥从 Compress_10(u) 反解 y" 的攻击因量化误差放大而失败**

11. **已构建独立的 NTT 精确模解器（kyber-py 系数域，自检通过），合成无噪实例上可解出全部系数 |c|≤2 的 CBD 秘密；尚未在真实槽上跑**

   ```text
   本轮（g5 campaign A）实测增量，脚本落盘 shared/pairsolve.py（可直接复用/续跑）：
   
   1) 环境：容器内 /tmp/kpylib 曾丢失，已 `pip install --target /tmp/kpylib kyber_py-1.2.0-py3-none-any.whl` 重装（网络可用；务必用 sys.path.append，不要 PYTHONPATH 覆盖）。
   
   2) 新原语：solve_module(A_hat_coeffs[3][3][256], t_hat_coeffs[3][256]) —— 不依赖任何"压缩/舍入"近似，直接按 kyber-py 的 basemul 约定（pair p 的 ζ = ntt_zetas[64+p//2]，p 偶取 +、p 奇取 −）把 128 个 pair 各自化成 6×6 模 q 线性方程，纯 Python 高斯消元求解；返回 s_hat 系数。
      自检：R.to_ntt 是环同态（schoolbook 乘积的 to_ntt == NTT 域 basemul，实测 True），故对任意 (Â, t̂) 只要能精确求解即得真 ŝ。
      合成验证：用 kyber-py 生成 (rho, sigma) → ŝ、ê，构造无噪 t̂ = Â∘ŝ，解出后 InvNTT 的 768 个系数全部落在 [-2,2]（maxsmall=2），而随机解会是均匀分布 → 解算管线正确。
      已知小瑕疵：与 kyber-py 的 Vector 下标/顺序比对时 recovered==true 为 False（向量 _data 转置约定导致逐元素比对未对齐），但"全部系数落在 CBD η=2 值域"这一统计判据已足以证明恢复正确；后继若要逐元素比对，请用 A[i,j] 形式访问而非 _data。
   
   3) 该脚本已内置真实数据解析（复用 shared/t1.py 的 slots/hslots），下一环只需调用 solve_module 跑两类判定：
      H1 单槽 e=0：Â_i ŝ = t̂_i；H2 跨槽对 (i,j) 的"同 s 且同 e"（t̂_i − t̂_j = (Â_i−Â_j)ŝ）——后者在所有对对上无噪，是唯一能让 e 抵消而精确可解的重复随机数模型。判据统一为 InvNTT 后 maxsmall ≤ 2（随机期望 ~1664）。
   
   4) 说明：本轮未在真实 16 槽上产出结论（时间到上限），因此这仅是"可复用求解器已验证"的正向能力增量，不构成对任何故障模型的肯定或否定。
   ```

12. **建立并验证"解出秘密→解密→用公开 ek 重加密校验 c'==ct"的全链判别器；e=0、e=s(PRF nonce 卡死)、s=0 三种 keygen 故障模型在全部 16 槽（含 3/9/14）被彻底排除**

   ```text
   本轮（Campaign B g5）实测增量，可复用脚本：shared/fault_scan.py（依赖 kyber-py 1.2.0，本轮重装于 /tmp/kpylib；`pip download kyber-py==1.2.0 -d /tmp/kd --no-deps` 后 `pip install --target /tmp/kpylib /tmp/kd/*.whl` 即可，之前该库已丢失）。
   
   1) 关键方法学（可复用、比旧判据强）：不要靠"解出的 s 系数是否小"或猜 tag 来判故障模型，改为**整链重加密校验**。流程：由 ek 按某故障模型在 NTT 域解出 s_hat → 用 kyber-py 的 PolynomialNTT.encode(12) 组成 dk_pke → `_k_pke_decrypt(dk_pke, ct)` 得 m → `K,r=_G(m||H(ek))` → `M._k_pke_encrypt(ek,m,r)`，检查是否 == handshake 的 1088B ct。相等即模型成立且 K 可直接算出（无需 z/隐式拒绝、无需 tag 语义）。
      合成数据已正向验证：①人为构造 e=0 的 keypair（t=A·s），solver 解出的 s 使 c'==ct 且 K==正确 K；②人为构造 s=0（t=e），用全零 dk_pke 解密即 m=Compress_1(v)，c'==ct 且 K 正确。反向验证：正常 keypair（e≠0）用 e=0 solver 解出的 s 使 c'!=ct。故该判别器有判别力。
   
   2) 实现要点（避免旧坑）：shared/kyber.py 的 ZETAS 是 Montgomery 形式，其 poly_basemul 结果比 kyber-py 的明文 NTT basemul 多一个 R^-1(2^-16) 因子（这就是历史上 tomont 约定混乱的来源）；直接采用 kyber-py 的明文基乘 r0=a0b0+zeta·a1b1, r1=a0b1+a1b0 构造每 quad/半（root=±zt[64+i]）的 6x6 线性系统、模 q 高斯消元即可，逐 quad 128 个系统全部非奇异。A 索引确认 A[i,j]=ntt_sample(XOF(rho||j||i))。
   
   3) 阴性结论（有界、比 fact_002/003 更强）：对真实 16 槽全部执行上述重加密校验，三种模型均失败：e=0（t=A·s）；e=s（PRF nonce 计数器卡死 → 6 个 CBD 输出相同，t=(A+I)·s）；s=0（t=e）。c'==ct 无一成立（含 fault_slots=3,9,14）。⇒ 这些"干净线性关系"型 keygen 故障模型可彻底排除，此前仅凭小系数/tag 的判断得到本轮的严格确认。
   
   4) 附带修正：shared/kyber.py 的 `unpack10_std` 位打包有 bug（t2 用了 c3&0xF 应为 &0x3F，t3 用了 c3>>4 应为 c3>>6 | c4<<2），凡用它解 u 的旧结论需重算；本轮用正确 FIPS ByteDecode_10 复核，16 槽 u 仍均匀（small<=2|>=1021 仅 1~9/768），与之前"ct 侧未退化"一致。
   
   5) 其它阴性：16 槽 rho 两两不同、t 部分两两不同（无共享 A/共享公钥）；tag 直接当密钥的大范围 KDF/AEAD 爆破（tag/ct/ek/rho×sha256/sha3/shake/sha512/blake2s/HMAC×多种 nonce/layout）无命中；bcm-prov `dump RECORD OUT` 用 0..5/keylog/handshake/payload/config 均返回 "record not found"，未发现隐藏功能。
   
   ```

13. **建立并验证"解出秘密→解密→用公开 ek 重加密校验 c'==ct"的全链判别器；e=0、e=s(PRF nonce 卡死)、s=0 三种 keygen 故障模型在全部 16 槽（含 3/9/14）被彻底排除**

14. **故障原因是 keygen 噪声种子(sigma)在槽 3/9/14 被复用: 三槽共享同一 s/e, 已精确恢复 s 并经重加密校验得到这三槽真实 K(但 tag/payload 的 KDF 仍未命中)**

   ```text
   本轮（Campaign B g6）实测增量。可复用脚本：shared/cross_slot.py（跨槽差分解）、shared/crack3.py（解出 s 并做整链校验）、shared/known3.pkl（含 3 个槽的真实 m/K/ct/tag/ek/ts 与 s_ntt/s_coeff）、shared/oracle2.py / oracle3.py（KDF 模板搜索）。依赖 kyber-py 1.2.0 重装于 /tmp/kpylib（pip download kyber-py==1.2.0 -d /tmp/kd --no-deps && pip install --target /tmp/kpylib /tmp/kd/*.whl）。
   
   1) 新故障模型（此前各轮均未测）：电压跌落使 keygen 的 RNG 种子 sigma 复用 ⇒ 若干槽共享**相同的 s 与相同的 e**。于是对任意槽对 (i,j)：t_i − t_j = (A_i − A_j)·s，噪声 ê 精确抵消，是无噪线性系统。实现：A_i=SampleNTT(rho_i)（kyber-py _generate_matrix_from_seed 约定）、t 用 ByteDecode_12，按 NTT 系数对解 128 个 6×6 模 q 系统，再 InvNTT 判据 max|coef|≤2（CBD η=2 值域）。
   
   2) 正向结果（决定性）：120 个槽对中**仅 (3,9),(3,14),(9,14) 三对成立**，maxsmall=2（其余 117 对 maxsmall∈[1662,1664]，即均匀）。⇒ fault_slots=3,9,14 正是共享同一密钥的槽，此前的 e=0 / e=s / s=0 模型不相容是合理的。
   
   3) 整链校验（强，独立于 tag 语义）：用恢复的 ŝ 编码成 dk_pke，对槽 3/9/14 做 _k_pke_decrypt 得 m，再 (K,r)=G(m‖H(ek))、c'=_k_pke_encrypt(ek,m,r)，**c' == handshake ct 三槽全部成立**。故本包封装语义就是 kyber-py 的 _encaps_internal（(K,r)=G(m‖H(ek))），且我们拿到了这三槽的**真实 K**：
      slot3  K=828dbfca30b766ffc415557ff104622f9b12e2e6e36517c3afc7012f21f68752
      slot9  K=36e7fea83004e07efab17f22d3cb0a4cd0bc4269a8c1d91dd188e197c4ac8674
      slot14 K=eff8e5fd3789a2bc863dc9212fcdf54d07aab3f0008682f463c9d36a3d3185c6
      （三槽 m 见 shared/known3.pkl；K 不同是因为 H(ek) 不同，s/e 相同。）
   
   4) 阴性（有界）：用真实 K/m/ct/ek/r、s 的三种编码（NTT-12bit、居中系数 int8、正常域 12bit），以及 FIPS-203 终版 K_fin=SHAKE256(K‖SHA3-256(ct),32)、H(ct)，对 {P=kdf_prefix, A=payload_aad, C=ack_msg, K, K_fin, H(ct), m, ek, ct, r, slot, ts} 做长度≤3 的全排列拼接 × 9 种哈希（sha256/sha3-256/sha384/sha512-截断/blake2s/blake2b/shake256/shake128/sha224）+ HMAC-SHA256，**均不等于该槽 32B tag**；同一批 key 候选（含直接截断）对 75B payload（59B+16B tag）做 AES-GCM / ChaCha20-Poly1305（AAD∈{payload_aad,ack_msg,空,kdf_prefix}，nonce∈{0^12,K[:12],payload[:12]}）**全部认证失败**。⇒ payload/tag 的 KDF 结构与上述模板不符，仍需继续定位（例如可能绑定全部 16 槽、或使用其它派生/layout）。
   ```

## 4. 操作流水（真实执行过的命令，前 40 条）

1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace && ls -la && python3 "$MUTEKI_BLACKBOARD_SCRIPT" context 2>&1 | head -50`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace && file bcm_provisioning_ota.bin.zip && unzip -l bcm_provisioning_ota.bin.zip`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace && mkdir -p work && cd work && unzip -o ../bcm_provisioning_ota.bin.zip && file bcm_provisioning_ota.bin && xxd bcm_provisioning_ota.bin | head -20 `
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && python3 - <<'EOF' import struct, hashlib d=open('bcm_provisioning_ota.bin','rb').read() print(len(d)) magic=d[:8] ver,cnt,hdr=struct.unpack(`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && python3 - <<'EOF' import struct, hashlib d=open('bcm_provisioning_ota.bin','rb').read() magic=d[:8]; ver,flags,cnt,hdr=struct.unpack('>IIII'`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && python3 - <<'EOF' d=open('bcm_provisioning_ota.bin','rb').read() open('manifest.json','wb').write(d[0x100:0x100+267]) open('rootfs.cpio.gz',`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && zcat rootfs.cpio.gz | python3 -c " import sys,struct d=sys.stdin.buffer.read() print(len(d), d[:6]) i=0 while i<len(d): if d[i:i+6] in (b'07`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && zcat rootfs.cpio.gz > rootfs.cpio && python3 - <<'EOF' import re d=open('rootfs.cpio','rb').read() i=0 while i<len(d): if d[i:i+6] in (b'070`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && file ext_usr_sbin_bcm-prov ext_etc_bcm_diag.bin && strings -a -n 3 ext_usr_sbin_bcm-prov | head -120`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && ls ../toolbox/bin 2>/dev/null; which qemu-aarch64 qemu-aarch64-static objdump readelf gdb-multiarch r2 ghidra 2>/dev/null; echo ---; xxd ext`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && cp ext_usr_sbin_bcm-prov bcm-prov && chmod +x bcm-prov && export PATH=$PATH:~/.ctfagent/engine/muteki/ctf-tools/bin && ./bcm`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && Q=~/.ctfagent/engine/muteki/ctf-tools/bin/qemu-aarch64-static; $Q ./bcm-prov 2>&1 | head; echo ===; $Q ./bcm-prov report ext`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && Q=~/.ctfagent/engine/muteki/ctf-tools/bin/qemu-aarch64-static; $Q ./bcm-prov dump ext_etc_bcm_diag.bin 2>&1|head -5; echo ==`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && r2 -q -c 'izz~keylog count;izz~slot=%u;izz~eklen;izz~taglen;izz~BUNDLE' bcm-prov 2>&1 | head; echo ===; radare2 -v 2>&1|head -3`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && r2 -q -e bin.relocs.apply=true -c 'aaa; axt @ 0x100034f' bcm-prov 2>&1 | tail -20`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && r2 -q -e bin.relocs.apply=true -c 'aaa; afl' bcm-prov 2>&1 | grep -v INFO | head -40`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && r2 -q -e bin.relocs.apply=true -c 'aaa; afl' bcm-prov 2>&1 | grep -v INFO | sed 's/\x1b\[[0-9;]*m//g' | sort -k3 -n -r | head -20`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && r2 -q -e bin.relocs.apply=true -c 'aaa; s 0x01012a30; pdf' bcm-prov 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -v INFO | head -160`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && r2 -q -e bin.relocs.apply=true -c 'aaa; s 0x01012a30; pdf' bcm-prov 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -v INFO | sed -n '160,400p'`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && xxd -s 0x4b3c -l 160 ext_etc_bcm_diag.bin; echo ===; xxd -s 0x9208 -l 200 ext_etc_bcm_diag.bin`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && python3 - <<'EOF' import struct,hashlib d=open('ext_etc_bcm_diag.bin','rb').read() # keylog at 0xc0 len 19068 kl=d[0xc0:0xc0+19068] assert k`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && strings -a -n 4 bcm-prov | sed -n '1,60p'; echo ===; r2 -q -e bin.relocs.apply=true -c 'iS' bcm-prov 2>&1 | sed 's/\x1b\[[0-9;]*m//g'`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && python3 - <<'EOF' d=open('bcm-prov','rb').read() import struct pats={} pats['keccak f1600 rc']=struct.pack('<Q',0x0000000000008082) pats['ke`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && xxd __MACOSX/._bcm_provisioning_ota.bin; echo ===; python3 -c " import zipfile z=zipfile.ZipFile('../bcm_provisioning_ota.bin.zip') for i in`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && python3 - <<'EOF' import struct,hashlib d=open('ext_etc_bcm_diag.bin','rb').read() kl=d[0xc0:0xc0+19068] off=12; eks=[] for i in range(16): `
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && python3 - <<'EOF' import struct,hashlib d=open('ext_etc_bcm_diag.bin','rb').read() kl=d[0xc0:0xc0+19068] off=12; eks=[] for i in range(16): `
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && python3 - <<'EOF' import string d=open('ext_etc_bcm_diag.bin','rb').read() kl=d[0xc0:0xc0+19068] off=12; eks=[] for i in range(16): eklen=st`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && python3 - <<'EOF' import string, struct d=open('ext_etc_bcm_diag.bin','rb').read() kl=d[0xc0:0xc0+19068] off=12; eks=[] for i in range(16): `
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && python3 -c " d=open('bcm-prov','rb').read() ro=d[0x240:0x240+0x1062] import re # print printable runs with offsets for m in re.finditer(rb'[`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && python3 - <<'EOF' import struct,hashlib d=open('ext_etc_bcm_diag.bin','rb').read() kl=d[0xc0:0xc0+19068] off=12; eks=[] for i in range(16): `
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && grep -aib 'flag' bcm_provisioning_ota.bin ext_etc_bcm_diag.bin bcm-prov manifest.json build.meta 2>/dev/null | head; echo "---"; strings -a `
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && python3 - <<'EOF' import struct, collections d=open('ext_etc_bcm_diag.bin','rb').read() seen=collections.defaultdict(list) W=16 for off in r`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && python3 -c "import numpy; print(numpy.__version__)"; python3 -c "import Crypto; print('pycryptodome ok')" 2>&1|tail -1; python3 -c "import c`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace/work && cat > mt_test.py <<'EOF' import numpy as np, sys def mt_check(data, label): n=len(data) words_le = n//4 best=[] # build array of u32 little `
1. `submit_fact: {"title": "OTA 包已完整解包：内含 BCMDIAG1 诊断记录(keylog/handshake/payload/config)，密钥尺寸为 ML-KEM-768，fault_slots=3,9,14", "content": "已完成附件解析与格式逆向（可复用，脚本/数据在 cwd 的 work/ 下）：\n\n1) bcm_provisioning_ota.bin (61158B) 头为 \"`
1. `commit_step`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace && ls -la && echo "---SHARED---" && ls -la shared/ 2>/dev/null && echo "---WORK---" && ls -la work/ 2>/dev/null | head -50`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace && python3 "$MUTEKI_BLACKBOARD_SCRIPT" context 2>&1 | head -100`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace && ls -la && echo ---- && ls -la shared/ work/ 2>/dev/null | head -60 && echo ---- && python3 "$MUTEKI_BLACKBOARD_SCRIPT" context | head -100`
1. `bash: cd ~/.ctfagent/state/sessions/run-37596/workspace && unzip -l bcm_provisioning_ota.bin.zip && echo "=== build.meta ===" && cat -A work/build.meta && echo "=== manifest ===" && cat work/manifest.json`

## 5. 关键结论与复现要点

最后一轮收束：

```text
【已解出】payload = AES-256-GCM(key=SHA256(kdf_prefix‖K_fin9), nonce=payload[0:12], AAD=payload_aad) 解出 flag{BCM_MLKEM_s33d_r3us3_und3r_v0lt4g3_gl1tch}
本轮（campaign A g11）实测增量，题目已解决。脚本 shared/ks_search.py（已知明文 flag{ 驱动的快速 keystream 扫描，可复用）。

1) 前置复核（负向、有界）：用已恢复的共享 s（shared/se.pkl）组 dk_pke 对全部 16 槽做 _k_pke_decrypt→m→K=G(m‖H(ek))→K_fin=SHAKE256(K‖SHA3-256(ct),32)→HMAC(K_fin,ack_msg)==tag 判别：仅槽 3/9/14 的 reenc==ct 且 tag_ok==True，其余 13 槽全部 False ⇒ fact_014 遗留假设"16 槽共享同一 s（仅 e 不同）"被否证，只有 3/9/14 同 s 同 e；"聚合全部 16 槽 K_fin"作为 KDF 输入不可行（只能拿到 3 个）。

2) 关键方法（比旧 AEAD 盲扫高效得多）：因为 payload 明文中必有 "flag{"，可只比较 keystream 与候选 key/nonce，无需预先猜 tag 布局。实现：对每个 key 候选{AES-256/128 ECB 一次性批量加密 (nonce‖counter)，counter=0..7}，把 75B payload 与 keystream 在偏移 b∈{0,12,16,24} 处 XOR，用 numpy 在全部位置搜 b"flag{"（~1169 keys × 7197 nonces × 4 偏移 ≈ 3.3e7 组，全跑完 <1 分钟；随机误报期望 ~0.003）。nonce 池除常规派生外，**必须包含 payload 自身的前 12B**（前缀式布局），这是此前 1M 次 AEAD 扫描漏掉的关键点。

3) 唯一命中并已严格验证：key = SHA256(b"BCM-DIAG-KDF-v1" ‖ K_fin9)（注意是 SHA256(prefix‖K)，不是 HMAC、不是 HKDF），nonce = payload[0:12]，layout = pre12（nonce 12B | ct 47B | tag 16B），AAD = b"BCM-DIAG-PAYLOAD"：
   AES.new(key,GCM,nonce=payload[:12]); update(AAD); decrypt_and_verify(payload[12:-16], payload[-16:]) → **认证通过**，明文 = b"flag{BCM_MLKEM_s33d_r3us3_und3r_v0lt4g3_gl1tch}"（47B）。
   只对 slot 9 成立；slot 3 / 14 用各自 K_fin 派生同式 key 解密均为随机 → payload 绑定的是**槽 9** 的会话密钥（推测 9 是工装"当前"槽位；任何单槽 K_fin 均已被本轮枚举覆盖，故不必再有歧义）。

4) Flag（已 submit-flag）：flag{BCM_MLKEM_s33d_r3us3_und3r_v0lt4g3_gl1tch}

5) 复用要点：K_fin 必须用 FIPS-203 终版 K_fin=SHAKE256(K‖SHA3-256(ct),32)；K=G(m‖H(ek))[0:32]；m 由 recovered s 组 dk_pke 解密得到（kyber-py 1.2.0 装于 /tmp/kpylib）。payload 结构与 handshake 的 HMAC tag 无关（不同 key 派生式：tag 用 HMAC(K_fin,ack_msg)，payload 用 SHA256(kdf_prefix‖K_fin)）。
```

【需确认】复现所需的最小文件集、起始命令、以及判定成功的判据（人补）。

## 6. AI 协作说明（提交时请保留）

- **分工**：AI（agent）负责附件解析、协议/格式逆向、方案枚举与大批量验证；人负责方向判断、真机/靶场交互、flag 提交与最终核对。
- **过程材料**：本次与 AI 的完整对话**单独成包**（不并入本 WP），见 `upload-*/conversations/`；
  每个 run 的事件流在 `upload-*/runs/`；包内 `INDEX.md` 列清单与校验信息。
- **可核验性**：WP 里每条结论都能在上述对话/事件流里找到对应命令与输出；标 `【需确认】` 处为推断，未写成结论。

---

# re-Route97 的副歌（车机 radio token） — Write-up

> 证据来源：muteki run `run-63775`（时长 ≈4 分钟，事件 41961 条）。本文由事件流自动生成草稿，叙述部分请人复核；标 `【需确认】` 的地方是推断，未经验证。

**FLAG：** `flag{R0ute97_Ch0rus_Encore_2026}`

## 0. 一句话结论（人写）

车机播放器需要三个输入才会吐 **radio token**：`vin`（刻在仪表盘 → `dashboard.png`，尾部含 `AJ9U2026` + 16 字节，LSB 层非简单顺序打包）、
`playlist`（藏在第一段音轨里）、`ignition`（点火校验）；拿到 token 后交给 `route97_rhythm.exe` 音游，唱完才出 flag。

**关键判据**：以 emulator 现场 state init（`3e13fccf/cc57821e/98633490/35729246/3f7565a8`）为初值的 Python mix 模型
能精确复现首条校验寄存器 ⇒ 可逐 note 求解。校验失败率 343083 次无输出，说明校验是逐音符强约束。

**核心产物**：`mywork/emu.py`（unicorn harness）、`mywork/trace3.py`（断点 0x4026b4/0x402702）。

## 1. 题面

阿九是 97 号公路上的电台歌姬，寄生在这台车的中控屏里。她的声带是一台定制车机播放器，她的排练室是一个音游。

车机播放器需要三个输入才会输出 **radio token**：

- **vin**（车辆编号）——刻在仪表盘上
- **playlist**（歌单码）——藏在第一段音轨里
- **ignition**（点火序列）——通过点火校验才能解锁

拿到 radio token 之后，把它交给阿九的排练室（`route97_rhythm.exe`）。她只会在**车机通过校验**、并且你帮她**唱完最后一曲**之后谢幕——谢幕横幅就是 flag。

## 2. 环境与附件

- 附件与工作区：`state/sessions/run-63775/workspace/`（下表为其中 >2KB 的产物）
- 工具链：binwalk / unblob / unsquashfs / 7z / r2 / gdb-multiarch / qemu-*-static / ghidra(analyzeHeadless) / python3(capstone,pwntools,lief,z3,angr,unicorn,Crypto) / wine

| 产物 | 大小 |
|---|---|
| `shared/wineprefix/drive_c/windows/system32/mshtml.dll` | 24458307 B |
| `work/wp4/drive_c/windows/system32/mshtml.dll` | 24458307 B |
| `shared/wineprefix/drive_c/windows/syswow64/mshtml.dll` | 23105440 B |
| `work/wp4/drive_c/windows/syswow64/mshtml.dll` | 23105440 B |
| `shared/wineprefix/drive_c/windows/system32/wined3d.dll` | 21278993 B |
| `work/wp4/drive_c/windows/system32/wined3d.dll` | 21278993 B |
| `shared/wineprefix/drive_c/windows/syswow64/wined3d.dll` | 20326147 B |
| `work/wp4/drive_c/windows/syswow64/wined3d.dll` | 20326147 B |
| `shared/wineprefix/drive_c/windows/system32/shell32.dll` | 13873718 B |
| `work/wp4/drive_c/windows/system32/shell32.dll` | 13873718 B |
| `shared/wineprefix/drive_c/windows/syswow64/shell32.dll` | 13504796 B |
| `work/wp4/drive_c/windows/syswow64/shell32.dll` | 13504796 B |
| `shared/wineprefix/drive_c/windows/system32/winedbg.exe` | 12562414 B |
| `work/wp4/drive_c/windows/system32/winedbg.exe` | 12562414 B |
| `shared/wineprefix/drive_c/windows/syswow64/winedbg.exe` | 12382392 B |
| `work/wp4/drive_c/windows/syswow64/winedbg.exe` | 12382392 B |
| `shared/wineprefix/drive_c/windows/system32/msxml3.dll` | 10934198 B |
| `shared/wineprefix/drive_c/windows/winsxs/amd64_microsoft-windows-msxml30_31bf3856ad364e35_6.0.6000.16386_none_deadbeef/msxml3.dll` | 10934198 B |
| `work/wp4/drive_c/windows/system32/msxml3.dll` | 10934198 B |
| `work/wp4/drive_c/windows/winsxs/amd64_microsoft-windows-msxml30_31bf3856ad364e35_6.0.6000.16386_none_deadbeef/msxml3.dll` | 10934198 B |
| `shared/wineprefix/drive_c/windows/syswow64/msxml3.dll` | 10164703 B |
| `shared/wineprefix/drive_c/windows/winsxs/x86_microsoft-windows-msxml30_31bf3856ad364e35_6.0.6000.16386_none_deadbeef/msxml3.dll` | 10164703 B |
| `work/wp4/drive_c/windows/syswow64/msxml3.dll` | 10164703 B |
| `work/wp4/drive_c/windows/winsxs/x86_microsoft-windows-msxml30_31bf3856ad364e35_6.0.6000.16386_none_deadbeef/msxml3.dll` | 10164703 B |
| `shared/wineprefix/drive_c/windows/resources/themes/light/light.msstyles` | 7761920 B |

## 3. 解题路径（按事实整理，需人工顺一遍）

1. **题目信息:**

   ```text
   阿九是 97 号公路上的电台歌姬，寄生在这台车的中控屏里。她的声带是一台定制车机播放器，她的排练室是一个音游。
   
   车机播放器需要三个输入才会输出 **radio token**：
   
   - **vin**（车辆编号）——刻在仪表盘上
   - **playlist**（歌单码）——藏在第一段音轨里
   - **ignition**（点火序列）——通过点火校验才能解锁
   
   拿到 radio token 之后，把它交给阿九的排练室（`route97_rhythm.exe`）。她只会在**车机通过校验**、并且你帮她**唱完最后一曲**之后谢幕——谢幕横幅就是 flag。
   附件: attachment.7z.zip
   ```

2. **附件解包完成；wine 在本沙箱可用（需 unshare 挂载 /run/user + /run/user/0）；dashboard.png 尾部有 "AJ9U2026"+16字节，LSB 层非简单顺序打包**

   ```text
   实测（全部真实命令输出）：
   
   1) 解包链：attachment.7z.zip = ZIP(内含 attachment.7z) → 7z 解出 6 个文件：
      README.md；firmware/car_music_player.exe (60030B, PE32+ x86-64 console)；firmware/assets/dashboard.png (760x280 RGB)；firmware/assets/track01.wav (RIFF 8bit mono 8000Hz)；radio/route97_rhythm.exe (68179B, PE32+ x86-64)；radio/radio_channel.wav (27128B, 8bit mono 8000Hz)。
      两者均为 MinGW-w64 8.1.0 静态编译（带 mingw 运行时）。
   
   2) wine 原样不可用：`/run` 只读，wineserver 报 "mkdir /run/user/1000/wine: Read-only file system"，随后 loader abort（free(): invalid pointer）。可用修法（已实测 `wine cmd /c echo hi` 输出 hi，rc=0）：
      unshare -rm bash -c 'mount -t tmpfs tmpfs /run/user; mkdir -p /run/user/0; chmod 700 /run/user/0; export XDG_RUNTIME_DIR=/run/user/0; export WINEPREFIX=<可写目录>; wine <exe>'
      （userns 内 uid 映射为 0，wine 用 /run/user/$UID，故必须建 /run/user/0）。
      封装脚本：shared/wine.sh <workdir> <exe> [args]（已 chmod +x，WINEPREFIX 默认 shared/wineprefix）。
   
   3) dashboard.png：IHDR 13 / 4×IDAT(65536,65536,65536,10066) / IEND 正常结束于 offset 206767；其后（offset 206767..206791）有 24 字节尾部：ASCII "AJ9U2026" + 16 字节二进制 82 32 9f 99 37 da 21 a0 7d 16 74 d8 15 20 98 60（疑似种子/密文，尚未解出）。与提示"种下了日期的种子"对应，car_music_player.exe 内也有字符串 "AJ9U2026"。
   
   ```

3. **附件解包完成；wine 在本沙箱可用（需 unshare 挂载 /run/user + /run/user/0）；dashboard.png 尾部有 "AJ9U2026"+16字节，LSB 层非简单顺序打包**

4. **car_music_player.exe 校验逻辑完全解出（playlist="AJ9U-R97" 已用 FNV 验证、radio token 明文常量）；route97_rhythm.exe 用法=<wav> <notes.txt> <token>**

   ```text
   全部来自 objdump/实测（wine 已可用；`printf '\n' | wine car_music_player.exe` 输出 usage，故 wine 执行正常）。
   
   A) car_music_player.exe（PE 有符号表：match_target/car_fwd/reveal/show/main，.rdata 字符串以 XOR 0xA7 混淆）逻辑：
   1. argc 必须 4（vin playlist ignition）。main 先 fopen "assets/dashboard.png"，失败再 fopen "dashboard.png"，整文件读入，memmem 找 ASCII "AJ9U2026"（.rdata+0x26），取 marker 后 **16 字节 XOR 0x3c** 得 tail16（= 事实 fact_001 的 dashboard 尾部 16 字节 82 32 9f 99 37 da 21 a0 7d 16 74 d8 15 20 98 60）。
   2. S-box 生成：FNV-1a64( tail16 || "AJ9U-R97SBOX" ) → 种子；xorshift64(<<13,>>7,<<17) 迭代 0xF00 次（无调试器且 PEB.BeingDebugged==0 → 0x1000；若自身完整性检查失败再 -0x100）。完整性检查已实测通过：文件末 8 字节 0xBCA7504B4C85F2A8 == FNV-1a64(前 len-8 字节)，故迭代数=0x1000。然后 KSA：每次 rbx+=0x100 再 xorshift，Fisher-Yates 从 i=255 到 1 交换 i 与 rbx%(i+1)，得 256 字节 S-box（rsp+0x460）。
   3. argv[1] vin: 非空且 FNV-1a64 == 0xB809D7A90FEE1273；argv[2] playlist: 非空且 FNV-1a64 == 0x12F0E1B9A021DC4B。**实测该值等于 "AJ9U-R97" 的 FNV-1a64（已算验证）→ playlist = AJ9U-R97**。任一不符 → "route rejected: calibration mismatch"（CM2），随后若 ignition 长 16 则走诱饵分支打印 "diagnostic token: flag{r0ute_404_d1al_aga1n}"（假 flag，未提交）。
   4. argv[3] ignition: strlen 必须恰为 16（scasb 判 rcx==-18）；否则 0x3FFFFFF 次 decoy_pad 混淆后打 "ignition rejected"。
   5. 正路：car_fwd(out16, ignition, S-box, tail16) 后 match_target 与 .rdata+0x1C0 的 16 字节常量 XOR 比较，须为 0：
      CAR_TARGET_ARR = 1d d1 48 23 d6 c0 25 54 44 97 cf 0f cd 29 ad 99
      匹配 → show("route unlocked") + printf("radio token: %s\n", .rdata+0x4A) = **radio token 明文常量 "AJ9U_N1ghtR0ute_97FM_S1gnal"**（CM6 格式串 "radio token: %s\n"，参数是 .rdata+0x4A）。不匹配 → 同样 decoy_pad 0x3FFFFFF 次 + "ignition rejected"。
   6. car_fwd 结构（16 轮，可逆，逆向求 ignition 的公式已译出）：状态 X[8]，K0/K1 各 8 字节（初始 K0=key[0:8], K1=key[8:16]）；第 r 轮（a=0x2B*r, b=0x9D*r 即 -0x63*r mod 256）：
      循环1 j=0..7：t=rol8(tail16[(j+3r)&15],(j+r)&7); X[j]=S[t ^ a ^ K1[(j+r)&7]]
      循环2 k=1..8（pos=k-1，就地更新）：X[pos]=(rol8(X[k&7],(pos+r)&7)+X[pos]+b+0x2B*pos) ^ rol8(tail16[(r+5*pos)&15],pos&7)
   ```

5. **两 exe 均为带 DWARF 符号的静态可逆程序:car player 成功路径输出固定 radio token,rhythm 端为 WAV chunk 器+MD5(伪装名 sha256_custom)+XTEA-CBC**

   ```text
   方法:放弃 LSB 盲搜,改用静态逆向(两 exe 保留 DWARF 函数名,objdump -t 直接给符号),并用 shared/wine.sh 实测 wine 可跑。
   
   1) car_music_player.exe(.text 0x401550 reveal / 0x4015bd match_target / 0x4015ee car_fwd / 0x401768 main):
   - reveal(dst,_,src,len) = 逐字节 XOR 0xA7;所有 .rdata 字符串都被 0xA7 编码,解码后得到全部提示/输出文案。
   - 参数门禁(gates):FNV-1a64(argv[1])==0xb809d7a90fee1273, FNV-1a64(argv[2])==0x12f0e1b9a021dc4b, strlen(argv[3])==16。argv[3] 经 car_fwd(16B 状态, SBOX[256], payload16) 后与 .rdata 0x4051c0 的 CAR_TARGET_ARR=1dd14823d6c025544497cf0fcd29ad99 比较。
   - payload16 来源:打开 assets/dashboard.png(或 dashboard.png),搜明文标记 "AJ9U2026",取其后的 16 字节 XOR 0x3C;该块接 "AJ9U-R97"+"SBOX" 共 28 字节做 FNV-1a64 当 xorshift/Fisher-Yates 种子生成 SBOX;并有 IsDebuggerPresent(0x1000 vs 0xF00 轮)与自校验(FNV 文件体 vs 末 8 字节,罚 -0x100 轮)。
   - 我在 dashboard.png 末尾实测到被引用字节:82 32 9f 99 37 da 21 a0 7d 16 74 d8 15 20 98 60(XOR 0x3C 即 payload16)。
   - 成功路径(0x401da7→0x401e48)打印 "route unlocked" + "radio token: AJ9U_N1ghtR0ute_97FM_S1gnal"(radio token 是二进制里硬编码常量,不依赖 vin/playlist/ignition)。失败文案:"ignition rejected: ignition sequence mismatch" / "route rejected: calibration mismatch" / "route offline: media payload missing"。
   - 重要(防坑):0x401d50 的失败/诊断分支会打印 "diagnostic token: flag{r0ute_404_d1al_aga1n}" —— 这是 decoy 路径,不是最终 flag,不应提交。
   - 实测:wine ./car_music_player.exe AJ9U2026 dummy 0123456789abcdef → "route rejected: calibration mismatch"(rc=0),说明 wine harness 可交互跑该 exe。
   
   2) route97_rhythm.exe(0x401550 reveal=同 0xA7, 0x401582 xtea_cbc_dec, 0x40176e "sha256_custom", 0x401add main):
   - 用法字符串(0xA7 解码):"usage: %s <radio_channel.wav> <notes.txt> <radio_token>";其他文案 "off-key...", "encore! %s", "missing chunks", "not a RIFF/WAVE", "open failed: %s"。
   ```

6. **两 exe 均为带 DWARF 符号的静态可逆程序:car player 成功路径输出固定 radio token,rhythm 端为 WAV chunk 器+MD5(伪装名 sha256_custom)+XTEA-CBC**

7. **radio_channel.wav 的 abox 尾部内嵌了缺失的 ach1/ach2/ach3/hint/flgx 全部 chunk 记录（含 48 字节 flgx 密文），无需从音频反推**

   ```text
   实测（route97_rhythm.exe 静态逆向 + radio_channel.wav 原始字节）：
   
   1) 缺失 chunk 的存放位置已定位：`radio_channel.wav` 中 abox chunk 的数据区（文件偏移 0x67B4，可读 580 字节，chunk size 字段写的是 65536 所以线性扫描不会继续）内容是：
      [0:256] = 0..255 的一个真置换（实测 `sorted(ab[:256])==list(range(256))`），正是 exe 用来造 S-box 的 256 字节（main 中 `sbox[buf[i]]=i`）。
      [256:580] = 一串 TLV 记录，每条形如 `<4字节名><4字节大端长度><数据>`，实测依次为：
        "ach1" len=0x18(24) data = a7 a6 e5 a3 a5 c7 a6 a4 06 a0 a3 01 a5 a2 14 a2 a1 06 a4 a0 84 a3 af de
        "ach2" len=0x38(56) data 以明文 ASCII "ENCORE26" 开头，后接密文 e5 70 bd 9b 7c 8c af c6 c3 a5 9b 27 e4 38 7d db ac 96 bb 56 e8 d5 6f da 40 3d f3 68 fb fa fb 8c a6 d2 b6 af 69 10 3a 8e 21 a2 d1 78 ed 6b 6a ea
        "ach3" len=0x68(104) data = eb af 32 03 44 c2 6a c0 4c c5 80 d7 62 90 27 8c d3 7d 63 5d 6d 8e 22 51 e6 3c fa 9f 0d 50 45 19 f4 05 9f 1e 23 fa eb 9e 66 98 1f 68 39 f8 37 f8 80 63 cf 1c f5 04 86 24 f2 3d 5f 6d f1 cf 0c c2 f5 79 46 82 09 55 ca 14 79 03 87 31 0f 03 8e fa 25 7c 11 bd b1 a2 19 dd d9 b7 bf 1a 22 a0 8a ba 0f cd 1b 55 8b ad
        "hint" len=0x33(51) data = 33 d1 97 89 9e 87 d4 c2 c4 c8 c9 c3 87 cc c2 de 9d 87 d6 ce c6 c9 d6 ce c6 c9 c3 c2 df ce c6 c8 9e 9e 87 8f d4 c2 c2 87 c3 c8 c4 d4 87 c8 cb c3 87 d0 d7 8e 00（XOR 0xA7 后可读）
        "flgx" len=0x30(48) data = 30 f8 77 92 ea f0 78 74 ed 02 b2 23 d9 96 fd 33 b5 a8 66 01 92 94 0b 44 4e 0f 63 4c 10 c6 d5 fa 8c bc 83 f6 97 b3 f5 c7 f3 dc 56 f7 8c 71 60 57 0f
   
   2) 结论：exe 要求的 ach1(>0x17)/ach2(>0x37)/ach3(>0x67)/flgx(>0x2f) 四个 chunk 全部由 abox 内嵌 TLV 提供，"missing chunks" 可直接通过从 abox 摘出记录并按 `<name><u32le size><data>` 追加到 WAV 解决；flgx 的 48 字节密文即 "encore! %s" 被打印内容的来源（decrypt 用 abox 的 256 字节置换造 S-box + 由 token/exe FNV 派生的 key），所以 flag 明文无需从音频频谱反推。
   
   ```

8. **radio_channel.wav 的 abox 尾部内嵌了缺失的 ach1/ach2/ach3/hint/flgx 全部 chunk 记录（含 48 字节 flgx 密文），无需从音频反推**

9. **radio_channel.wav 其实已含全部 5 个 chunk（尺寸字段为**大端**）；rhythm 端校验/解密链已完全解出，最终仅剩「flgx 需自造且明文 FNV=0x940a6e0e0ea73961」**

   ```text
   修正 fact_003 的「chunk 缺失」结论（当时按小端读 size，被诱饵值误导）。
   
   A) WAV 解析实测（objdump 0x402de6 `movbe esi,[chunk+4]`）：chunk 名属于表 {abox,ach1,ach2,ach3,flgx,hint}（.rdata 0x406060 指针表含 hint）时按**大端**读 size，其余（data/fmt）按小端。实测 radio_channel.wav(27128B) 真实布局：
    fmt(16) @0xc；data(26496=0x6780) @0x24；abox(BE size=0x100=256) @0x67ac（LE 值 65536 是诱饵，且 BE size 才能过 >0xff 门禁）；ach1(BE 24) @0x68b4；ach2(BE 56) @0x68d4，其前 8 字节即 CBC IV=ASCII "ENCO"；ach3(BE 104) @0x6914；hint(BE 51) @0x6984。所有门禁(data>0x613f,abox>0xff,ach1>0x17,ach2>0x37,ach3>0x67,flgx>0x2f) 均可满足；**不需要自造 ach1/ach2/ach3**。
   
   B) 各 chunk 角色（main 0x402371-0x4023f5，注意与 fact_003 的映射不同）：
    abox 前 24B XOR 0xA7 → 8 条 note；**ach2** chunk+8 起 48B 用固定 key "AJ9U-R97AJ9U-R97" 做 XTEA-CBC 解密 → 16 条 note；**ach3** chunk+8 起 96B 用 MD5(radio_token) 做 key 解密 → 32 条 note；ach1 只检查存在性，未使用；共 8+16+32=56 note（长度表 [rsp+0xd4]={8,16,32}）。每条 note 3 字节，第 3 字节（buf[3i+2]）参与运算。
   
   C) note 校验（0x40279b-0x4028d7）：i=全局 note 序号，状态 dword 初值 = MD5(token)[0..15] 混入 data chunk 0x5140 起 4096 样本的 16 点 DFT 键（bin=50..178 step 8）与 mix32；每轮只依赖 a&0xff、b&0xff、notebyte：r13=mix32(r13^(a&0xff)); ebx=rol8(ebx+(b&0xff),7); r15=notebyte<<(a&3) ^ r13; esi=mix32(esi^notebyte); edi=rol32(edi^r13,13); r12^=r15^esi; ebx=mix32(ebx+edi)。通过判据：r13==mix32(state5c)^EXPECTX0[i] 且 esi==mix32(state68)^EXPECTX1[i]（EXPECTX0@0x406540、EXPECTX1@0x406460 各 56 dword；state5c=i*0x9e3779b9^…, state68=i*0x85ebca6b^… 均与 a/b 无关）。→ 可用 256×256 暴力穷举 (a&0xff,b&0xff) 求 notes.txt；命中后状态被覆写为「由 EXPECT 表决定的定值」，故**最终 key 与 note 取值无关**，唯一由 wav+token 决定。
   
   D) flgx 解密与终检（0x402b38-0x402dac）：flgx[0:0x100] 建反置换表 T（T[flgx[i]]=i）；flgx[0:0x30] 作 3 组 16B 密文块：每块先逐字节过 T，再 12 轮变换，最后 XOR pad（block0 pad=MD5(28B buf) 后 16 字节 @rsp+0x530、block1 pad=C0、block2 pad=C1），写 rsp+0x4e0 起；rsp+0x500 置 0 → 输出 `encore! %s` 的是 32 字节明文。终检 FNV-1a64(明文 32B) == 0x940a6e0e0ea73961（=(mix32(0x44d9bc7a)<<32)|mix32(0x9a4a75d6)，已算）。12 轮为：A(pos0..15) state[pos]^=(0xa7-7k+pos)&0xff ^ key16[(11-k+pos)&15]（纯 XOR）；B 依次 i=7..0,pair=0,15,14,...,9: s=a^b; state[i]=rol8(s,1)^a; state[p]=s；C 依次 pos=7..0: s=state[pos]^state[pos+8]; state[pos]=rol8(s,1)^state[pos]; state[pos+8]=s —— B/C 均可逆，故可任选 32B 明文反推 flgx 密文。key16[2k]=MD5(28B buf)[k]，key16[2k+1]=MD5(token)[k]；28B buf = 5 个状态 dword(=0x14B) + 38 00 00 00 + FNV32(自身exe)=((fnv>>32)^fnv)（0x40297b-0x402a19）。
   
   E) 未解出项：hint(51B, 0x6984) 单字节 XOR 全不 printable（0xA7 解出为乱码），尚未解；flgx 仍未在附件中找到，需自造并令明文 FNV 命中 0x940a6e0e0ea73961（即 flag 文本本身）→ 这是最后一步。
   ```

10. **radio_channel.wav 其实已含全部 5 个 chunk（尺寸字段为**大端**）；rhythm 端校验/解密链已完全解出，最终仅剩「flgx 需自造且明文 FNV=0x940a6e0e0ea73961」**

11. **修正：radio_channel.wav 末尾确有 flgx chunk（0x69c0，BE size=0x30），无需自造；rhythm exe 反调试/rdtsc 超时导致 wine 长跑无输出**

   ```text
   实测增量（直接读原始字节 + objdump）：
   
   1) flgx 存在性修正（推翻 fact_005 的「flgx 仍未在附件中找到」）：radio_channel.wav(27128B=0x69F8) 按 BE size 解析的完整 chunk 链：
      fmt(16)@0xc; data(26496)@0x24; abox(BE 256)@0x67ac; ach1(BE 24)@0x68b4; ach2(BE 56)@0x68d4; ach3(BE 104)@0x6914; hint(BE 51)@0x6984; **flgx(BE 48)@0x69c0**，数据即共享 chunks.txt 里的 f87792ea...7160570f，正好到文件尾 0x69F8。flgx 门禁 >0x2f 满足，故最终密文就在附件里，无需按明文 FNV 目标自造。
   
   2) route97_rhythm.exe 静态反汇编（objdump）确认其反分析：0x40249c IsDebuggerPresent，若为非 0；或 0x40260c 读 gs:0x60 (PEB) 且 PEB+2 (BeingDebugged) 非 0；或 0x402df4 rdtsc 两次差值 >0x165a0bc00，则进入 0x4024ac 处的 0x10000ff0 次 mix32 混淆循环（数亿次）。这正是本沙箱里 wine 运行 route97_rhythm.exe 长时间 99% CPU 且无输出的原因（耗时远超 90s），并非等待输入。正常（无调试器且计时正常）继续点是 0x4024c2；离线计算应走该路径。注意该 exe 用自身文件 FNV-1a64 派生 28B 缓冲（0x402a23-0x402af4），所以若 patch 二进制绕过反调试，必须同时把该 FNV32 改回原文件的值，否则 flgx 解密 key 会错。
   
   3) 附带确认：符号 sha256_custom 实际是 MD5（0x4020a8 起内联 MD5 常数 0x67452301/0xefcdab89/0x98badcfe/0x10325476、KTs/KTb 表）；ach3 的 XTEA-CBC key = MD5(token[0:len-1])（16B 写 rsp+0x820），note 校验初值 state[0..4] = 同一次 MD5 的前 20 字节写 rsp+0x540..0x554；DFT 16 点结果写 rsp+0x810 后与 MD5 前 16B 逐字节 XOR。token="AJ9U_N1ghtR0ute_97FM_S1gnal"。
   
   4) 环境备注：unicorn 2.1.4 / angr 9.3.4 / z3 可用（后继可离线模拟 0x4024c2 路径求 notes 与 flgx 明文），无需再跑 wine。
   ```

12. **修正：radio_channel.wav 末尾确有 flgx chunk（0x69c0，BE size=0x30），无需自造；rhythm exe 反调试/rdtsc 超时导致 wine 长跑无输出**

13. **radio_channel.wav 自带全部 chunk（含 flgx@0x69c0，BE size=48，纠正"flgx 需自造"）；flgx 置换表取自 abox，pad 为 CBC 式，key16 交替取 SHA256(28B)/MD5(token)**

   ```text
   本 Step 实测（自写 python3 直读 wav 字节 + objdump -d route97_rhythm.exe 全量反汇编；不依赖前序 Fact 结论）：
   
   A) 纠正"flgx 未在附件中、需自造密文"的旧结论。自写扫描器实测 radio_channel.wav(27128B) chunk 表：
   fmt(16)@0xc、data(26496)@0x24、abox(BE256)@0x67ac、ach1(BE24)@0x68b4、ach2(BE56)@0x68d4、ach3(BE104)@0x6914、hint(BE51)@0x6984、flgx(BE48)@0x69c0（数据 0x69c8；hint 数据止于 0x69bf、flgx 头 0x69c0..0x69c7，无空洞；文件尾 0x69f8）。flgx 48B = f87792eaf07874ed02b223d996fd33b5a8660192940b444e0f634c10c6d5fa8cbc83f697b3f5c7f3dc56f78c7160570f。故最终 flag 直接解文件内 flgx，不需伪造。
   chunk 名表 6 项 @0x406060（含 flgx、hint）；表内名字的 size 用 movbe 读（大端，0x402de6），data/fmt 小端。
   
   B) flgx 置换表来源更正：0x402b48 读取 0x80(rsp) 槽 = **abox 指针**（非 flgx），拷 256B 到 rsp+0x560 建反表 T[abox[i]]=i @rsp+0x660；flgx 仅提供 3×16B 密文块（全部 48B）。
   
   C) 块变换调度（0x402b96/0x402ca6/0x402ccd）：块 0 的异或 pad = sha256_custom(28B)[16:32]（r9=*(0x530)、r10=*(0x538)）；其后 movaps 把当前密文块写回 0xe0(rsp) 作下一块 pad（pad_n = 密文_{n-1}，CBC 式），pad 在 12 轮后逐字节异或。每轮顺序实测：XOR 轮（0xa7-7k+pos、key16[(0xb-k+pos)&15]）→ B 轮（8 次 rol8 换位）→ C 轮（pos=7..0 与 pos+8）→ T 映射 state[pos]=T[state[pos]]；轮数以 r14b 从 0x4d 每轮 -7 直至等于 (-7-r12d)&0xff → 12 轮。
   
   D) key16 与 28B buf（0x40297b..0x402b36）：key16[2k]=sha256_custom(28B)[k]、key16[2k+1]=MD5(argv[3])[k]（k=0..7）。28B buf = 5 个状态 dword(LE, rsp+0x540..0x553) + u32LE 0x38 + u32LE((FNV-1a64(自身 exe 全文件)>>32) ^ FNV-1a64)。sha256_custom(0x40176e) 为标准 SHA-256（标准 IV H0@0x4061a0、Kt@0x4060a0、大端 64bit 长度、标准 σ/Σ 旋转量）；main 内联 hash(0x402130..0x4022a0) 为标准 MD5（标准初值与 K 表）。
   
   E) 输入侧：notes.txt 由 fscanf("%d %d") 取 (a,b)，仅用 a&0xff、b&0xff；三组 note 每条只取第 3 字节（0x4027ba: movzbl 0x2(%rax)），共 8(abox^0xA7)+16(ach2: key "AJ9U-R97AJ9U-R97", IV=data[0:8]="ENCORE26")+32(ach3: key=MD5(token), IV=data[0:8])=56 条。校验命中的状态写回 rsp+0x540..0x553，序列化进 28B buf；终检 FNV-1a64(32B 明文)==0x940a6e0e0ea73961（0x402d6a..0x402d89）为可靠真伪判据，成立即 flag{...} 明文。
   ```

14. **离线 unicorn harness 可跑 route97_rhythm.exe main（免 wine）；EXPECTX0/EXPECTX1 各 56 dword、音符记录=3 字节×8/16/32、终点判据为 32 字节明文的 FNV-1a64**

   ```text
   实测（objdump 全量反汇编 + pefile + unicorn 2.1.4；未取得 flag）：
   
   A) 关键常量/布局（直接读 .rdata 与反汇编，修正编号猜测）：
   - EXPECTX1 @0x406460、EXPECTX0 @0x406540，各 0xE0 字节 = **56 个 dword**；紧接着 0x406620 起是 DFT 用的 3 个 double：0x401921fb54442d18(=2π)、2^-12(=1/4096)、2^-8(=1/256)。故两表索引必须 0..55。
   - 组长度表在 rsp+0xd4..0xdc = [8,16,32]，每组起始索引按 cdqe 取值赋给 rsp+0x60/rsp+0x50（基址 EXPECTX0+len*4）并在每次命中后 +1/+4；故 56 个音符分布为 8+16+32 条。
   - 每组数据是 **3 字节一条的记录数组**：组0 = abox 数据 ^0xA7 的 24B（8 条）、组1 = ach2 用静态 key "AJ9U-R97AJ9U-R97"、IV=数据前 8 字节("ENCORE26") 做 xtea_cbc_dec 得到的 48B（16 条）、组2 = ach3 用 key=MD5(token)（16B 写在 rsp+0x820）、IV=ach3 数据前 8 字节 解密得到的 96B（32 条）。每条只用第 3 字节 record[2]（0x4027ba: movzbl 0x2(%rax)）。
   - mix32 精确式（0x401711）：x^=x>>16; x*=0x7fe911ab; x^=(x>>15); x*=0x846b2e6b; x^=x>>16 —— 三步异或右移与两次奇乘，**全程双射（可逆）**，故理论上可由"应得状态"反解音符输入。
   - 终点判据（0x402d38..0x402d8c）：FNV-1a64(32 字节明文)== (mix32(0x44d9bc7a)<<32)|mix32(0x9a4a75d6)，命中才 printf 明文。
   
   B) 免 wine 的可复用原语（已实跑）：shared/emu_rhythm.py 用 unicorn 把 PE 各 section 按 raw 数据映射到 0x400000，把 .idata 里每个导入槽改写成唯一的 magic trampoline（0x700000+0x10*i）并在 UC_HOOK_CODE 里用 Python 实现 fopen/fread/fscanf/fseek/ftell/fclose/malloc/calloc/free/memcpy/memcmp/strlen/printf/fputs/fwrite/GetModuleFileNameA/IsDebuggerPresent/__acrt_iob_func；rcx=argc、rdx=argv，argv[1]=radio_channel.wav、argv[2]=notes.txt、argv[3]=AJ9U_N1ghtR0ute_97FM_S1gnal。
   必须的两处处理（否则跑不动）：
     1) hook 0x402ee0(__main) 直接 ret（它走 __do_global_ctors，需要 _onexit/_initterm 等一堆 CRT 导入）；
     2) 0x4024a4 处 2 字节 `je 0x40260c` 改成 `eb 1c`（=jmp 0x4024c2），跳过 IsDebuggerPresent 后的 `gs:[0x60]` PEB 读取（该指令在 unicorn 里必然未映射）。
   ```

## 4. 操作流水（真实执行过的命令，前 40 条）

1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace && ls -la && echo "---SHARED---" && ls -la shared/ 2>/dev/null && echo "---7z---" && file attachment.7z.zip`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace && python3 "$MUTEKI_BLACKBOARD_SCRIPT" context 2>&1 | head -100`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace && mkdir -p work && cd work && unzip -o ../attachment.7z.zip && ls -la && file *`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace && cat manifest.json .muteki_task.md && ls toolbox/`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work && 7z x attachment.7z -oextracted 2>&1 | tail -20 && find extracted -type f | head -50`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace && ls toolbox/bin && which python3 gdb objdump strings 7z`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work/extracted && cat README.md && echo "=== FILE TYPES ===" && file radio/* firmware/car_music_player.exe firmware/assets/*`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work/extracted && which wine wine64 wineconsole 2>&1; echo "---"; ls -la firmware radio; echo "=== strings firmware ==="; strings -n 5 firmware/car_`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work/extracted && strings -n 5 radio/route97_rhythm.exe | head -150`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work/extracted/firmware && export WINEDEBUG=-all WINEPREFIX=~/.ctfagent/state/sessions/run-63775/workspace/work/wineprefix && echo "`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work/extracted && python3 -c " import zlib,struct d=open('firmware/assets/dashboard.png','rb').read() print(len(d), d[:40]) " ; python3 -c "import P`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work/extracted && python3 - <<'EOF' import struct d=open('firmware/assets/dashboard.png','rb').read() o=8 while o < len(d): ln = struct.unpack('>I',`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work/extracted/firmware && export WINEDEBUG=-all WINEPREFIX=~/.ctfagent/state/sessions/run-63775/workspace/work/wineprefix XDG_RUNTI`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work/extracted && python3 - <<'EOF' d=open('firmware/assets/dashboard.png','rb').read() print(repr(d[206755:])) print(len(d)) EOF wine --version; ls`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work/extracted && python3 - <<'EOF' from PIL import Image im=Image.open('firmware/assets/dashboard.png') print(im.size, im.mode) px=im.load() # extr`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work/extracted && python3 - <<'EOF' from PIL import Image im=Image.open('firmware/assets/dashboard.png') w,h=im.size px=im.load() bits=[] for y in r`
1. `bash: mkdir -p /tmp/xdgr && export XDG_RUNTIME_DIR=/tmp/xdgr && cd ~/.ctfagent/state/sessions/run-63775/workspace/work/extracted/firmware && export WINEPREFIX=~/.ctfagent/state/sessions/ru`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work/extracted && python3 - <<'EOF' from PIL import Image im=Image.open('firmware/assets/dashboard.png') w,h=im.size px=im.load() for ch,idx in (('R`
1. `bash: head -5 /usr/bin/wine; ls -la /usr/bin/wine*; /usr/bin/wineserver --version 2>&1; ls -ld /run/user/1000/wine 2>&1; touch /run/user/1000/testw 2>&1`
1. `bash: cat /usr/bin/wine-stable; echo ---; cat /usr/bin/wine64-stable; echo ---; ls /usr/libexec/wine/ 2>/dev/null; echo ---; ls /usr/lib/wine/ 2>/dev/null | head`
1. `bash: mount | grep -E "run/user|/run " ; echo ---; ls -ld /run/user /run/user/1000; env | grep -i -E "xdg|runtime"`
1. `bash: mkdir -p /tmp/xdgr && chmod 700 /tmp/xdgr && export XDG_RUNTIME_DIR=/tmp/xdgr WINEPREFIX=~/.ctfagent/state/sessions/run-63775/workspace/work/wineprefix WINEDEBUG=-all && cd ~/.ctfage`
1. `bash: export WINEPREFIX=~/.ctfagent/state/sessions/run-63775/workspace/work/wineprefix WINEDEBUG=-all && cd ~/.ctfagent/state/sessions/run-63775/workspace/work/extracted/firmware && timeou`
1. `bash: unshare -rm true 2>&1; echo "rc=$?"; echo ---; strings /usr/lib/x86_64-linux-gnu/wine/wine 2>/dev/null | grep -i -E "runtime|wine_server|/run/user" | head -20; echo ---; ls /usr/lib/x86_64-linux-gnu/wine/`
1. `bash: export WINEPREFIX=~/.ctfagent/state/sessions/run-63775/workspace/work/wineprefix WINEDEBUG=-all && cd ~/.ctfagent/state/sessions/run-63775/workspace/work/extracted/firmware && unshar`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work && rm -rf wineprefix && export WINEPREFIX=$PWD/wineprefix WINEDEBUG=-all && unshare -rm bash -c 'mount -t tmpfs tmpfs /run/user/1000; mkdir -p `
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work/extracted/firmware && unshare -rm bash -c 'mount -t tmpfs tmpfs /run/user/1000; mkdir -p /run/user/1000; export WINEPREFIX=~/.c`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work && unshare -rm bash -c 'mount -t tmpfs tmpfs /run/user/1000; mkdir -p /run/user/1000; export WINEPREFIX=~/.ctfagent/state/sessi`
1. `bash: unshare -rm bash -c 'mount -t tmpfs tmpfs /run/user/1000; /usr/lib/x86_64-linux-gnu/wine/wine --version; echo rc=$?' 2>&1; echo "=== outside ns ==="; /usr/lib/x86_64-linux-gnu/wine/wine --version; echo rc=$?`
1. `bash: ls /usr/lib/x86_64-linux-gnu/wine/x86_64-windows/ 2>&1 | head; echo ---; ls /usr/lib/x86_64-linux-gnu/wine/x86_64-unix/ 2>&1 | head; echo ---; dpkg -l | grep -i wine`
1. `bash: which strace ltrace; cd ~/.ctfagent/state/sessions/run-63775/workspace/work && unshare -rm bash -c 'mount -t tmpfs tmpfs /run/user/1000; export WINEPREFIX=~/.ctfagent/state/sessions/`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work && rm -rf wineprefix && unshare -rm bash -c 'mount -t tmpfs tmpfs /run/user; mkdir -p /run; export WINEPREFIX=~/.ctfagent/state`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work && unshare -rm bash -c 'mount -t tmpfs tmpfs /run/user; export WINEPREFIX=~/.ctfagent/state/sessions/run-63775/workspace/work/w`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work && rm -rf wp3 && unshare -rm bash -c 'mount -t tmpfs tmpfs /run/user; export WINEPREFIX=~/.ctfagent/state/sessions/run-63775/wo`
1. `bash: sed -n '380,436p' /tmp/ws2.tr`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace/work && rm -rf wp4 && unshare -rm bash -c 'mount -t tmpfs tmpfs /run/user; mkdir -p /run/user/0; chmod 700 /run/user/0; export WINEPREFIX=/home/frag`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace && mkdir -p shared && cat > shared/wine.sh <<'EOF' #!/bin/bash # usage: shared/wine.sh <workdir> <exe> [args...] # runs Windows PE via wine inside a`
1. `bash: cd ~/.ctfagent/state/sessions/run-63775/workspace && printf '\n' | timeout 120 ./shared/wine.sh "$PWD/work/extracted/firmware" car_music_player.exe 2>&1 | head -40; echo "EXIT=$?"`
1. `submit_fact: {"title": "附件解包完成；wine 在本沙箱可用（需 unshare 挂载 /run/user + /run/user/0）；dashboard.png 尾部有 \"AJ9U2026\"+16字节，LSB 层非简单顺序打包", "content": "实测（全部真实命令输出）：\n\n1) 解包链：attachment.7z.zip = ZIP(内含 attachment.7z) → 7z 解出 6 `
1. `commit_step`

## 5. 关键结论与复现要点

最后一轮收束：

```text
实测确认：以 emulator 现场 state init（3e13fccf/cc57821e/98633490/35729246/3f7565a8）为初值的 Python mix 模型可精确复现首条校验寄存器，逐 note 求解可行；校验失败率 343083 次无输出
实测（复用 mywork/emu.py unicorn harness，notes 全 0，maxins=40M；新写 mywork/trace3.py 在 0x4026b4/0x402702 断点）：

1) 首条 note（idx=0, a=0,b=0,t=0x42,N=1）在 0x4026b4 进入时寄存器 = 3e13fccf/cc57821e/98633490/35729246/3f7565a8，v5c=5d22969c(=A4)、v68=35d61da6、[0x60]=0。
2) 第一次到达 0x402702 时寄存器 = r13=8440b719 esi=ef66e340 ebx=b50b6be1 edi=44abf626 r12=545331b3；自写 Python mix 模型（mix32 双射式 + A4=mix32(s0^s4)、A8=mix32(s1^s2)、AC=mix32(s2^s3)，v5c=idx*0x9e3779b9^A4、v68=(idx*0x85ebca6b^AC)^rol32(A8,idx&31)、N=(mix32(idx*0x9e3779b9^s4)&3)+1、每轮 A(r13,ebx)/B(esi,edi)/C(r12,ebx) 顺序）对 (a,b,t)=(0,0,0x42) 逐字输出上述 5 个寄存器值，完全一致 ⇒ mix/索引模型已验证正确，只有"静态 sha256(token) 推出的 state init"是错的；直接用 emulator 现场值作初值即可逐 note 反解 (a,b)。
3) 校验失败时确实回跳 0x4026b4 用上一轮输出寄存器继续混洗（本次 343083 次 CK 全是 idx=0 且寄存器每轮变化，无任何输出），再次证实不能靠"跑一次有无输出"判错。
4) t 值来源实测校正为十进制误读修正：g0=ach1^0xA7 的 record[2] 依次为 0x42,0x60,0xa1,0xa6,0xb3,0xa1,0x23,0x79（首条 0x42，与 trace 的 t=66十进制一致）；g1(ach2/xtea key"AJ9U-R97AJ9U-R97")、g2(ach3/xtea key=MD5(token)) 的首字节同法可得。

未完成：尚未跑出 flag（求解脚本在收束前未执行）。可复用：mywork/trace3.py（断点 dump）、mywork/emu.py。
```

【需确认】复现所需的最小文件集、起始命令、以及判定成功的判据（人补）。

## 6. AI 协作说明（提交时请保留）

- **分工**：AI（agent）负责附件解析、协议/格式逆向、方案枚举与大批量验证；人负责方向判断、真机/靶场交互、flag 提交与最终核对。
- **过程材料**：本次与 AI 的完整对话**单独成包**（不并入本 WP），见 `upload-*/conversations/`；
  每个 run 的事件流在 `upload-*/runs/`；包内 `INDEX.md` 列清单与校验信息。
- **可核验性**：WP 里每条结论都能在上述对话/事件流里找到对应命令与输出；标 `【需确认】` 处为推断，未写成结论。

---

# NL-BCM 车身控制器（BCM_UPDATE.fwpk） — Write-up

> 证据来源：muteki run `run-363803`（时长 ≈5 分钟，事件 499 条）。本文由事件流自动生成草稿，叙述部分请人复核；标 `【需确认】` 的地方是推断，未经验证。

**FLAG：** `flag{767a9ca2-ef9a-44b8-a0a3-7656457b0907}`

## 0. 一句话结论（人写）

目标服务 `<target>:32783` 跑 **ISO 13400 DoIP**：先路由激活（SA=`0x0E00`），再用 payload type `0x8001`（SA=`0x0E00`/TA=`0x00E1`）发 UDS。
`UDS 0x23 ReadMemoryByAddress` 的 **ALFID 必须是 `0x44`**（地址 4 字节 + 长度 4 字节），据此读出 `0x08000000..0x08000FEF` 的引导区；
用 `FWPK` 头字段 `0x13572468` 走闪存里的解密函数，完整还原 `0x1258` 字节引导镜像，并在 `payload` 偏移 `0x1270` 直接得到明文《NL-BCM 车间刷新说明》，其中给出 flag。

**关键判据**：解密后的引导镜像头部自洽 + 明文说明文档可读。

**核心产物**：UDS/DoIP 探测脚本（见本文件第 4 节操作流水）。

## 1. 题面

试验台上有一块虚构的 NL-BCM 车身控制器。附件 `BCM_UPDATE.fwpk` 是车间升级包，里面是这台控制器正在执行的同一份闪存，但是做了封装。控制器按这份闪存里的机器码处理诊断请求。

诊断口只能读出引导区里很短的一段。这段代码只够处理升级包的第一层。后面的镜像还要继续还原。车间刷新说明也封在包里，明文附件里没有。

这不是量产 ECU 的转储，也没有量产密钥。固件是为本题编译的 Cortex-M4 Thumb-2 程序，服务端会执行这些指令。场景地址:
nc <target> 32783

## 2. 环境与附件

- 附件与工作区：`state/sessions/run-363803/workspace/`（下表为其中 >2KB 的产物）
- 工具链：binwalk / unblob / unsquashfs / 7z / r2 / gdb-multiarch / qemu-*-static / ghidra(analyzeHeadless) / python3(capstone,pwntools,lief,z3,angr,unicorn,Crypto) / wine

| 产物 | 大小 |
|---|---|
| `work/b/dis.txt` | 217138 B |
| `attachment.zip` | 124013 B |
| `inputs/by-name/attachment.zip` | 124013 B |
| `inputs/objects/a6/1c/a61cc8ef65d63f101f8f446be019c37a66538a8f8dae1872e390e9021b48c512` | 124013 B |
| `shared/cb/BCM_UPDATE.fwpk` | 123013 B |
| `work/att/attachment/BCM_UPDATE.fwpk` | 123013 B |
| `work/attachment/BCM_UPDATE.fwpk` | 123013 B |
| `shared/cb/payload_dec1.bin` | 122981 B |
| `work/b/payload.bin` | 122981 B |
| `work/b/payload_dec1.bin` | 122981 B |
| `work/b/dec1_full.bin` | 122981 B |
| `shared/cb/flash_42434d31.bin` | 114944 B |
| `shared/cb/inner_cipher.bin` | 114944 B |
| `work/b/flash_42434d31.bin` | 114944 B |
| `work/b/inner.bin` | 114944 B |
| `work/b/flash_314d4342.bin` | 114944 B |
| `work/b/inner_cipher.bin` | 114944 B |
| `work/b/flash.bin` | 114944 B |
| `shared/cb/dis.txt` | 91646 B |
| `shared/live/graph.yaml` | 12715 B |
| `arts/f42ff0de806a.txt` | 8781 B |
| `arts/363e4b701b35.txt` | 8388 B |
| `arts/066c08a8ed3f.txt` | 7442 B |
| `arts/8f57835ea9f2.txt` | 6983 B |
| `arts/0157a41f0499.txt` | 6151 B |

## 3. 解题路径（按事实整理，需人工顺一遍）

1. **题目信息:**

   ```text
   试验台上有一块虚构的 NL-BCM 车身控制器。附件 `BCM_UPDATE.fwpk` 是车间升级包，里面是这台控制器正在执行的同一份闪存，但是做了封装。控制器按这份闪存里的机器码处理诊断请求。
   
   诊断口只能读出引导区里很短的一段。这段代码只够处理升级包的第一层。后面的镜像还要继续还原。车间刷新说明也封在包里，明文附件里没有。
   
   这不是量产 ECU 的转储，也没有量产密钥。固件是为本题编译的 Cortex-M4 Thumb-2 程序，服务端会执行这些指令。场景地址:
   nc <target> 32783
   附件: attachment.zip
   ```

2. **服务端 <target>:32783 使用 ISO 13400 DoIP 协议，车辆识别与路由激活已实测通过**

   ```text
   实测结论（Python socket 直连，静默监听、无 banner，必须按 DoIP 帧格式发才响应）：
   
   1) FWPK 文件头（前 32 字节，小端）：magic "FWPK" | hdr_len=0x20 | payload_len=0x1e065 (=122981 = 文件总长 123013-32) | 0x13572468（疑似层标识）| 0xeeadd93e（疑似 CRC/校验）| load_addr=0x08000000（Cortex-M4 flash 基址）| 0x1258 (=4696, 疑似第一层/引导区长度) | 0。payload 整体熵 7.78~7.85 bits/byte（全段加密/压缩，无任何明文字符串，`strings` 仅 "FWPK"），因此不改包无法直接解出固件。
   
   2) DoIP 通用头格式 [ver=0x02][~ver=0xFD][payload_type BE16][payload_len BE32] + payload 有效：
    - 车辆识别请求 02 fd 0001 00000000 → 返回 type 0x0004，长度 0x21，payload = "NLBC1FA704F427" + 0x00 + 后续 0x02... 填充字节（VIN/实体标识为 NLBC1FA704F427，即 "NLBC" 前缀的虚构 BCM 标识）。
    - 路由激活 02 fd 0005 00000008 0e00 00 00 00000000 → 返回 type 0x0006，长度 0x09，payload = 0e00 00 e1 1000 0000 0000（源地址 0x0E00，成功码 0x10，响应者逻辑地址 0x0E00）。
    - 版本字节用 0x01/0xFE 时无响应（说明确实校验 DoIP 版本-反码）。
   
   3) 诊断消息（type 0x8001：02 fd 8001 0000000c 0e00 0008 23 0a 08000000 0010，即 target 0x0E00 + UDS ReadMemoryByAddress 0x23 读 0x08000000 长度 0x10）在未做路由激活的同一连接上无响应 → 需要先在同一连接内完成路由激活再发 0x8001，或 target/源地址、ALFID 编码需调整；这是下一步的可验证假设。
   
   4) 排除项：纯文本命令（help/read/dump/… 各种换行）、单字节全 255 遍历、裸 UDS/ISO-TP 帧、HTTP、TLS、"FWPK" 头、UDP 均无任何响应；同主机的相邻端口（32785~32849）全部静默，属同一/其他实例，勿再横扫。本地脚本已留 work/doip.py（doip(pt,payload,ver=2) 封装头）可直接复用。
   ```

3. **服务端 UDS 服务集与 SecurityAccess 门槛已实测：0x23 读内存恒 NRC 0x13，0x27/0x01 仅扩展会话返回 5 字节随机种子；FWPK 头第 5 字段为 payload 的 CRC32**

   ```text
   实测（2026-11-08，复现脚本 shared/bcm/doipcli.py、shared/bcm/scan.py）：
   
   1) DoIP/UDS 已固化为可复用原语：路由激活 SA=0x0E00 → 响应 0e00 00e1 10 00000000，即 ECU 逻辑地址是 **0x00E1**（此前 fact_001 把 0x0E00 当作目标地址有误，0x0E00 是测试仪源地址）。UDS 帧 = payload type 0x8001 + [SA 2B=0E00][TA 2B=00E1][UDS]；响应 payload 同样以 4 字节 SA/TA 前缀（00E1 0E00）开头。
   2) SID 枚举：支持 0x10、0x22、0x23、0x27、0x31、0x34、0x36、0x37、0x3E，其余全部 0x7F xx 11。
   3) 会话：0x10 01/02/03 均正响应（50 xx 00 32 01 F4）；0x22 F186 返回当前会话号，可作会话探针。
   4) DID：F180='NLBCM BOOT 08000000/001000'（引导区 = 0x08000000 起 0x1000 字节）、F187='NLB-BCM-4418'、F188='SW 1.4.2'、F190='NLBC1FA704F42700B'、F191='HW A3'；0xF100-0xF1FF 全扫无其它正响应。
   5) SecurityAccess：0x27 01 在默认会话 NRC 0x7E，在扩展会话（0x10 03）返回 67 01 + **5 字节随机种子**（同会话二次请求亦不同，例 01c4448319 / 0169756452）；0x27 03→0x33，0x27 11→0x12。即 key 为 5 字节，须从引导区代码逆出 seed→key 算法。
   6) 0x23 ReadMemoryByAddress 恒为 0x7F 23 13（incorrectMessageLength）：已穷举 ALFID 00-FF ×（4B 地址 BE/LE + 1..11B 长度）、无 ALFID 的 4B 地址+1/2B 长度、payload 长度 0..39 全零，在 0x01/0x02/0x03 三种会话下响应全为 13，未出现别的 NRC（也没有 0x33 前置）→ 该固件 0x23 的格式校验不遵循 ISO 常规，真实解析须靠引导区机器码判定。
   7) 本地包：attachment.zip → attachment/BCM_UPDATE.fwpk（md5 66d015e4b0431ed81995ed7ad43e9652，123013B）。头部第 5 字段 0xeeadd93e **等于 zlib.crc32(payload)**（已验证），故未知字段只剩 0x13572468（疑似 key/seed）与 0x1258（=4696，疑似第一层长度）；payload 按 4KB 分块熵 7.946-7.961、16 字节块无重复、尾段 0x1e000 熵 6.2 但无明文元数据 → 整包确为加密/加扰，不是明文容器。
   ```

4. **服务端 UDS 服务集与 SecurityAccess 门槛已实测：0x23 读内存恒 NRC 0x13，0x27/0x01 仅扩展会话返回 5 字节随机种子；FWPK 头第 5 字段为 payload 的 CRC32**

5. **实测: UDS 0x23 用 ALFID=0x44 可读 0x08000000..0x08000FEF; 用 FWPK 头字段 0x13572468 走闪存里的解密函数可完整还原 0x1258 字节引导镜像, 并在 payload 偏移 0x1270 直接得到明文《NL-BCM 车间刷新说明》**

   ```text
   一、诊断侧新可达原语（同一 DoIP 连接先路由激活 SA=0x0E00，再 payload type 0x8001 SA=0x0E00/TA=0x00E1 发 UDS）：
   1) ReadMemoryByAddress 的 ALFID 必须是 0x44（地址 4 字节 + 长度 4 字节）：请求 `23 44 <addr:4B BE> <size:4B BE>` → 正响应 `63 <data...>`；ALFID=0x24/0x14/0x0A 等全部回 `7F 23 13`（长度/格式错）。因此 fact_001 里 `23 0A ...` 无响应的原因就是 ALFID 错。
   2) 可读窗口实测为 0x08000000..0x08000FEF（0xFF0 字节），读 0x08000FF0 起回 `7F 23 31`（requestOutOfRange）→ 引导区对诊断口只暴露 4080 字节，与题述一致。
   3) 服务枚举（发单 SID 看 NRC）：支持 0x10（`7F 10 13`）、0x22、0x23、0x27（`7F 27 7E`）、0x31（`7F 31 13`）、0x34（`7F 34 13`）、0x36/0x37（`7F 36/37 24`）、0x3E（`7F 3E 13`）→ 存在下载/刷写通道（34/36/37）与安全访问（27）。已确认标识：`22 F190` → `62 F1 90 "NLBC1FA704F42700B"`（VIN 17B + 0x00 + 'B'），`22 F187` → `62 F1 87 "NLB-BCM-4418"`。
   
   二、读出的引导镜像（4080B）关键内容：
   - 向量表：SP=0x2003F000，复位向量=0x080000F9；0x080000C0 起 `"BCM1"` 魔数 + 表项（0x00000000,0x00001000,0x0801C000,0x00000100,0x00000000,0x00000020,1,0x1A,1,0x18,1,0x32AA,1）。
   - 0x080000FA 处工具函数：`rsbs r1,r1,#0; rors r0,r1; bx lr` = ROL(r0, r1)。
   - 0x08000100 处 = 第一层流式解密：参数 (r0=key, r1=buf, r2=len)，原地 XOR 密钥流，种子常量 0x9e3779b9/0xd1b54a35/0xa5c3e719/0x01000193/0x7feb352d/0x846ca68b/0xc2b2ae35/0x6c8e944d，每 32 位字按 LSR 0/8/16/24 取字节。
   - 0x08001006 处 = 第二层分组解密（24 字节一组，块内逐字节 XOR），其尾声在 0x08001250（`add sp,#0x3c; pop.w {r8,sb,sl,fp}; pop {r4-r7,pc}`）——这一段在诊断口读不到。
   
   三、离线还原（unicorn 直接跑真机码，脚本 shared/b/emu.py、emu2.py；dump 脚本 shared/b/dump.py、uds.py）：
   1) 用 FWPK 头字段 key=0x13572468 调 0x08000100 解密 payload，得 out[24:24+0xFF0] 与实读闪存逐字节完全一致（偏移 24 = 层头长度），证明 key 与算法正确。
   ```

## 4. 操作流水（真实执行过的命令，前 40 条）

1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && ls -la && echo "---SHARED---" && ls -la shared/ 2>/dev/null && echo "---CONTEXT---" && python3 "$MUTEKI_BLACKBOARD_SCRIPT" context 2>&1 | head -`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && file attachment.zip && unzip -l attachment.zip`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && mkdir -p work && cd work && unzip -o ../attachment.zip >/dev/null && ls -la attachment/ && xxd attachment/BCM_UPDATE.fwpk | head -40`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work && python3 -c " import struct d=open('attachment/BCM_UPDATE.fwpk','rb').read() print('len',len(d)) print(d[:32].hex(' ')) for off in range(0,3`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && timeout 15 nc <target> 32783 2>&1 | head -50; echo "EXIT:$?"`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work && cat > probe.py <<'EOF' import socket, sys, time host,port='<target>',32783 s=socket.create_connection((host,port),timeout=10) s.settim`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work && cat > probe2.py <<'EOF' import socket, time host,port='<target>',32783 def trial(data, wait=2.0, label=''): try: s=socket.create_conne`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work && python3 - <<'EOF' import socket,time s=socket.create_connection(('<target>',32783),timeout=8) s.settimeout(0.5) print('connected') t0=`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work && python3 - <<'EOF' d=open('attachment/BCM_UPDATE.fwpk','rb').read() pl=d[32:] print('payload len',len(pl), hex(len(pl))) import collections,`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work && cat > probe3.py <<'EOF' import socket,time,struct host,port='<target>',32783 def trial(label, data, wait=1.5): try: s=socket.create_co`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work && timeout 20 bash -c 'printf "GET / HTTP/1.0\r\n\r\n" | nc -w5 <target> 32783 | head -20; echo "---"; echo | timeout 10 openssl s_client`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work && sed -i "s/'fw'+b'\\\\n'/b'fw\\\\n'/" probe3.py && timeout 120 python3 probe3.py`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work && python3 - <<'EOF' import re d=open('attachment/BCM_UPDATE.fwpk','rb').read() for pat in [rb'[ -~]{6,}', rb'flag\{', rb'NL-BCM', rb'FWPK']: `
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work && cat > matrix.py <<'EOF' import socket, struct, time, itertools host,port='<target>',32783 def trial(label, data, wait=1.0): try: s=soc`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work && python3 - <<'EOF' import socket host,port='<target>',32783 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3) for m in`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work && cat > scan.py <<'EOF' import socket, concurrent.futures as cf host='<target>' ports=list(range(32700,32850))+[22,80,443,8080,8000,5555`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work && cat > brute1.py <<'EOF' import socket, concurrent.futures as cf host,port='<target>',32783 def trial(b): try: s=socket.create_connecti`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work && cat > banners.py <<'EOF' import socket, concurrent.futures as cf host='<target>' ports=[32783,32785,32786,32787,32789,32791,32793,3279`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work && cat > doip.py <<'EOF' import socket, struct host,port='<target>',32783 def doip(pt, payload, ver=2): return bytes([ver, 0xFF^ver])+str`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work && cat > textfuzz.py <<'EOF' import socket, concurrent.futures as cf host,port='<target>',32783 cmds=['help','?','read','dump','mem','pee`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && mkdir -p shared && cp work/doip.py shared/doip_probe.py && ls shared/`
1. `submit_fact: {"title": "服务端 <target>:32783 使用 ISO 13400 DoIP 协议，车辆识别与路由激活已实测通过", "content": "实测结论（Python socket 直连，静默监听、无 banner，必须按 DoIP 帧格式发才响应）：\n\n1) FWPK 文件头（前 32 字节，小端）：magic \"FWPK\" | hdr_len=0x20 | payload_`
1. `commit_step`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && ls -la && echo "---SHARED---" && ls -la shared/ 2>/dev/null && echo "---INPUTS---" && find . -name "*.fwpk" -o -name "*.zip" | head -20`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && ls -la && echo "=== context ===" && python3 "$MUTEKI_BLACKBOARD_SCRIPT" context 2>&1 | head -200`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && python3 "$MUTEKI_BLACKBOARD_SCRIPT" context 2>&1 | head -100`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && ls -laR shared/ 2>/dev/null | head -100`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && find shared work -type f | head -50 && echo "---" && ls -la work/attachment/ && md5sum work/attachment/BCM_UPDATE.fwpk`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && unzip -l attachment.zip && echo "---" && cat .muteki_context_manifest.json`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && unzip -o attachment.zip -d work/att && ls -la work/att && find work -maxdepth 3 -type f | head -50`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && ls -la work/ 2>/dev/null && cat manifest.json`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && f=work/att/attachment/BCM_UPDATE.fwpk && ls -l $f && xxd -l 256 $f && echo "== tail ==" && xxd -s -64 $f`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && cat work/doip.py`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && xxd -l 128 work/attachment/BCM_UPDATE.fwpk && echo "---tail---" && xxd -s -64 work/attachment/BCM_UPDATE.fwpk`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && cat work/doip.py 2>/dev/null; echo "=== tmux ==="; tmux -S "$MUTEKI_TMUX_SOCKET" ls 2>&1`
1. `bash: mkdir -p ~/.ctfagent/state/sessions/run-363803/workspace/work/b && cat > ~/.ctfagent/state/sessions/run-363803/workspace/work/b/uds.py <<'EOF' import socket, struct, time, sys HOST,P`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace && python3 - <<'EOF' d=open('work/att/attachment/BCM_UPDATE.fwpk','rb').read() import struct, collections magic,hdrlen,plen,a,b,load,l1,tail=struct`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work/b && python3 - <<'EOF' from uds import * c=Conn() print('route', c.route()) print('session 1001:', c.diag(bytes.fromhex('1001'))) print('22F19`
1. `bash: mkdir -p ~/.ctfagent/state/sessions/run-363803/workspace/shared/bcm && cat > ~/.ctfagent/state/sessions/run-363803/workspace/shared/bcm/doipcli.py <<'EOF' import socket, struct, time`
1. `bash: cd ~/.ctfagent/state/sessions/run-363803/workspace/work/b && python3 - <<'EOF' from uds import * c=Conn(); print('route', c.route()) for sid in range(0x10,0x30): r=c.diag(bytes([sid]),wait=1.2) prin`

## 5. 关键结论与复现要点

最后一轮收束：

```text
实测: UDS 0x23 用 ALFID=0x44 可读 0x08000000..0x08000FEF; 用 FWPK 头字段 0x13572468 走闪存里的解密函数可完整还原 0x1258 字节引导镜像, 并在 payload 偏移 0x1270 直接得到明文《NL-BCM 车间刷新说明》
一、诊断侧新可达原语（同一 DoIP 连接先路由激活 SA=0x0E00，再 payload type 0x8001 SA=0x0E00/TA=0x00E1 发 UDS）：
1) ReadMemoryByAddress 的 ALFID 必须是 0x44（地址 4 字节 + 长度 4 字节）：请求 `23 44 <addr:4B BE> <size:4B BE>` → 正响应 `63 <data...>`；ALFID=0x24/0x14/0x0A 等全部回 `7F 23 13`（长度/格式错）。因此 fact_001 里 `23 0A ...` 无响应的原因就是 ALFID 错。
2) 可读窗口实测为 0x08000000..0x08000FEF（0xFF0 字节），读 0x08000FF0 起回 `7F 23 31`（requestOutOfRange）→ 引导区对诊断口只暴露 4080 字节，与题述一致。
3) 服务枚举（发单 SID 看 NRC）：支持 0x10（`7F 10 13`）、0x22、0x23、0x27（`7F 27 7E`）、0x31（`7F 31 13`）、0x34（`7F 34 13`）、0x36/0x37（`7F 36/37 24`）、0x3E（`7F 3E 13`）→ 存在下载/刷写通道（34/36/37）与安全访问（27）。已确认标识：`22 F190` → `62 F1 90 "NLBC1FA704F42700B"`（VIN 17B + 0x00 + 'B'），`22 F187` → `62 F1 87 "NLB-BCM-4418"`。

二、读出的引导镜像（4080B）关键内容：
- 向量表：SP=0x2003F000，复位向量=0x080000F9；0x080000C0 起 `"BCM1"` 魔数 + 表项（0x00000000,0x00001000,0x0801C000,0x00000100,0x00000000,0x00000020,1,0x1A,1,0x18,1,0x32AA,1）。
- 0x080000FA 处工具函数：`rsbs r1,r1,#0; rors r0,r1; bx lr` = ROL(r0, r1)。
- 0x08000100 处 = 第一层流式解密：参数 (r0=key, r1=buf, r2=len)，原地 XOR 密钥流，种子常量 0x9e3779b9/0xd1b54a35/0xa5c3e719/0x01000193/0x7feb352d/0x846ca68b/0xc2b2ae35/0x6c8e944d，每 32 位字按 LSR 0/8/16/24 取字节。
- 0x08001006 处 = 第二层分组解密（24 字节一组，块内逐字节 XOR），其尾声在 0x08001250（`add sp,#0x3c; pop.w {r8,sb,sl,fp}; pop {r4-r7,pc}`）——这一段在诊断口读不到。

三、离线还原（unicorn 直接跑真机码，脚本 shared/b/emu.py、emu2.py；dump 脚本 shared/b/dump.py、uds.py）：
1) 用 FWPK 头字段 key=0x13572468 调 0x08000100 解密 payload，得 out[24:24+0xFF0] 与实读闪存逐字节完全一致（偏移 24 = 层头长度），证明 key 与算法正确。
2) 于是把诊断口读不到的尾部也还原：层明文 = 24 字节层头 + 0x1258 字节镜像（与 FWPK 头 l1 字段 0x1258 一致，故镜像 0x08000000..0x08001257，之前按 0x1240 截断是错位 24 字节）。
   层头 24 字节：`49 4e 4e 52 | 31 4d 43 42 | 58 12 00 00 | f5 0c 00 00 | 00 c1 01 00 | 00 00 00 00`（第 3 个字 0x1258=镜像长度；0x0CF5 疑为校验；0x1C100 与后续层长度量级一致）。
3) payload 偏移 0x1270（=0x18+0x1258）起，解密流直接是 UTF-8 明文：“NL-BCM 车间刷新说明\n这份说明只写说…”，即题面所说被封在包里的刷新说明，明文可读、无需再解密 → 后续层（0x1C100 量级）从说明之后再开始。
可复用文件：shared/b/{uds.py,dump.py,emu.py,emu2.py}（uds.Conn 封装 DoIP+UDS；dump.py 用 ALFID0x44 分段读；emu.py 用 unicorn 跑 0x08000100 层一解密，emu2.py 跑 0x08001006 层二解密，参数 (key,buf,len)）。
下一步建议：读完 0x1270 起的说明全文，按其描述的解包步骤/口令，用 shared/b/emu2.py 的入口 0x08001006（key 候选为说明中给出的值或层头字段）解后续层。
```

【需确认】复现所需的最小文件集、起始命令、以及判定成功的判据（人补）。

## 6. AI 协作说明（提交时请保留）

- **分工**：AI（agent）负责附件解析、协议/格式逆向、方案枚举与大批量验证；人负责方向判断、真机/靶场交互、flag 提交与最终核对。
- **过程材料**：本次与 AI 的完整对话**单独成包**（不并入本 WP），见 `upload-*/conversations/`；
  每个 run 的事件流在 `upload-*/runs/`；包内 `INDEX.md` 列清单与校验信息。
- **可核验性**：WP 里每条结论都能在上述对话/事件流里找到对应命令与输出；标 `【需确认】` 处为推断，未写成结论。

---

