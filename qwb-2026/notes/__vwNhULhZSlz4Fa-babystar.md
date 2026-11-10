# babystar（强网杯 2026 线上赛 · PWN · 1000 分 / 0 队解出）

目标：`nc <target> 36885`。无附件。容器下发后**立即可连**（不需要等 2 分钟）。
角色：子代理只做侦察与协议逆向，**未提交 flag**。

## 1. 线上帧格式（全部实测验证）

```
frame := uint8 type | uint32 BE length | payload[length]
type  : 'T' 遥测  'E' ASCII 错误文本  'C' CCSDS 命令包  'F' CFDP PDU
```
验证方法：把抓到的字节流按该规则切分，3328 字节的初始流能被完整消费、每帧 length 与后续 type 字节自洽。
例：`54 00000012 0883c004000b000f463f402800000000000000`（'T'，18 字节 TM 包）。

## 2. T 帧 = CCSDS TM 包（6 字节主头）

| 偏移 | 字段 | 实测 |
|---|---|---|
| 0-1 | `ver(3)=0,type(1)=1,sechdr(1)=0,apid(11)` | apid = `((p[0]&7)<<8)|p[1]` |
| 2-3 | seq: `flags(2)=11b` + 计数器 14bit | 每个 APID 独立递增（同 APID seq 连续） |
| 4-5 | 包长度-1（BE） | 与长度字段一致，`payload_len == 6+len16+1` |
| 6-9 | cFS 风格时间 u32 秒（BE） | 观测 0x000F463F ≈ 1001023 s，随时间单调 +
| 10-11 | 子秒 u16（BE） | 0x4028/0x40AC 递增 |
| 12.. | 应用 HK 数据 | 见下 |

观测到的 APID：`0x000 0x001 0x003 0x004 0x005 0x080 0x083 0x084 0x085 0x08a 0x090 0x09b 0x0a4 0x0a7 0x0aa 0x0ad 0x0b0 0x0b8 0x0fb`（约 1–2 Hz 轮询，无请求也主动推）。
★ 泄字段：`apid=0x0b8` 的 body 内含字符串 `/cf/ds_filter_tbl.tbl`；`apid=0x004` body 内含 `SBN.SBN_RemapTbl`
⇒ 卫星端是 **cFS 风格**文件系统（`/cf/`），CF 应用 → CFDP 是真实攻击面。

## 3. E 帧 = 免费 oracle（已全部落盘）

| 输入 | 响应 |
|---|---|
| C 帧 payload < 8 字节 | `short CCSDS packet` |
| C 帧 `18000000 00000000`（8B，APID 0x000） | `command not permitted` ← **命令白名单** |
| F 帧 0 字节 | `bad CFDP PDU length` |
| F 帧 4~6 字节 | `bad CFDP PDU` |
| F 帧 7 字节（只有头） | `bad CFDP directive` |
| F 帧 type=FileData、无事务 | `file data without metadata` |
| F 帧 type=Directive, dc≠0x07 且 data 足够长 | **静默丢弃** |
| F 帧 dc 非 0x07 且 data 只有 1 字节 | `bad CFDP directive`（长度不足伪装成指令错误） |
| F 帧 dc=0x07 Metadata（任何名字） | `unsafe CFDP destination filename` ← **当前卡点** |

## 4. F 帧 = CFDP PDU（布局实测与 CCSDS 727 一致）

```
byte0 = ver<<5 | pdu_type<<4 | dir<<3 | txmode<<2 | crc<<1 | large
        0x24 = ver1 / directive / dir0 / unack / 无CRC
byte1-2 = PDU data field length (BE)
byte3   = seg_ctrl<<7 | (src_eid_len-1)<<4 | segmd<<3 | (tsn_len-1)
        0x00 → eid 1B + tsn 1B → 头 = 4+2*1+1 = 7 字节
byte4 = src_eid, byte5 = tsn, byte6 = dst_eid, byte7 = 指令码
总长必须 == 7 + data_field_len，否则静默丢弃 / bad CFDP PDU
```
Metadata(0x07) 参数域按 CCSDS 727 打包后被**正确解析**（否则会报 bad directive）：
`[dc=07][closure<<6|checksum_type][file_size u32][src 名 LV][dst 名 LV]`。
用 `spacepackets`(work/venv) 生成的**规范 PDU** 与我手搓的字节完全一致，行为也一样 → 布局已确认。

指令码扫描 0x00–0x1F（data 41 字节）→ **只有 0x07 被实现**，其余静默丢弃
⇒ CFDP 攻击面只有 Metadata（+后续 File Data），Proxy Put / Filestore Request **未实现**。

## 5. 卡点（下一步抓手）

`unsafe CFDP destination filename` 对**所有**输入恒定：空名 / 相对名 `a` `b` `d` / 带扩展名 `b.bin` `b.dat` `b.tbl` `b.txt` `b.raw` `b.out` / `recv.bin` / `.` `..` `/` `./b` / 200×`A` /
绝对路径 `/cf/ds/x` `/cf/rx/x` `/cf/dest/x` `/cf/in/x` `/cf/dl/x` `/cf/downlink/x` `/cf/recv/x` `/cf/uplink/x` `/cf/tmp/x` `/cf/ground/x` `/cf/gs/x` `/cf/data/x` `/cf/store/x` `/cf/out/x` `/cf/host/x` `/tmp/x` `/cf/x` `/cf/ds_filter_tbl.tbl`，
以及 1/2/4 字节 LV 宽度、截断 LV、NUL 注入、空 LV —— 全部同样报错。
**而 source 名写 `/cf/host/flag` 从不被拒**（不对称！）。
⇒ 结论：该检查的输入**不是我发的 LV**（很可能解析出来的名字恒为空，或校验读的是别的偏移 / 依赖 entity id 或某个 C 命令预设的会话）。下一步应：
1. 用差分法在 Metadata 参数域里逐字节扫"哪个字节影响 unsafe/静默"，定位它真正的名字读取偏移（每步只改 1 字节，串行 400ms）；
2. 打通 C 帧白名单（`command not permitted` 后的第一层），看是否有"设置接收目录/下发权限"的命令——那可能就是 dest 校验的前置条件。

## 6. 证据与复现

- harness：`scripts/__vwNhULhZSlz4Fa-solve.py`（串行单连接、帧切分、请求/响应逐字节落盘）
- 证据（请求+响应原始字节）：`evidence/__vwNhULhZSlz4Fa-t1-garbage.bin` … `t16-edges.bin`
- `work/venv` 里装了 `spacepackets`（系统 pip 是 PEP668 外部管理，必须用 venv）

## 7. ★ C 帧命令白名单已被打开（第二轮）

19 个 APID 各发一条 **NOOP（fc=0，总长 8 字节，length 字段=1）**，逐条归因（`evidence/__vwNhULhZSlz4Fa-t17-noop-apid.bin`）：
- **被接受（静默、无 E）**：0x004 0x080 0x083 0x084 0x085 0x090 0x09b 0x0a4 0x0aa
- `command not permitted`：0x000 0x001 0x003 0x005 0x08a 0x0a7 0x0ad 0x0b0 0x0b8 0x0fb
⇒ 白名单是**按 APID**的，校验和不校验（ck=0x00 也放行）。

fc 1..8 扫这 9 个 APID（`t18`）后定位到 **0x004 = cFS Table Services（TBL）**：

| fc | 语义 | 实测 |
|---|---|---|
| 0 | NOOP | 静默接受 |
| 1 | reset registry | 静默接受 |
| 2 | **TBL LOAD** | payload **必须正好 64 字节**（表路径，NUL 填充） |
| 3,6,8 | dump / load-from-file 等 | `command not permitted` |
| 4 | **TBL VALIDATE** | payload 必须正好 **42** 字节 |
| 5 | **TBL ACTIVATE** | payload 必须正好 **40** 字节（表名） |

TBL LOAD（fc=2）行为细节：
- data < 64 → E `short TBL LOAD payload`；data > 64 → TM 事件 `Invalid msg length -- ID = 0x1804, CC = 2, Len = 88, Expected = 72`
- **路径白名单只有一个**：`/cf/ds_filter_tbl.tbl` → 接受，TM 事件（apid 0x008）打印
  `...CFE_TBL...LoadFile,file=/cf/ds_filter_tbl.tbl,tbl=DS.FILTER_TBL:Successful`
- 其它一律 E `TBL LOAD path not permitted`：`/cf/host/flag`、`/cf/`、`x`、`../flag`、`/cf/ds/x`、`/cf/tbl/x.tbl`、`/cf/../host/flag`、`/cf/ds/../../host/flag`、以及 `白名单名 + "/../../host/flag"`
- **半通**：`/cf/ds_filter_tbl.tbl\x00/cf/host/flag` 能过路径检查（事件里出现 LoadFile），说明校验取 **NUL 前的字符串做全等比较**，open 也用同一前缀 ⇒ 这条不构成穿越。
- 只有加载过该文件后表才进入 `Load already in progress` 状态。
- fc=5 activate `DS.FILTER_TBL`（40 字节名）→ `Activate,tbl=DS.FILTER_TBL:Cannot activate table, Inactive image not Validated`
- fc=4 validate `name(40)+\x00\x00`（42B）→ **完全静默**，但表仍 `not Validated`（42 字节内容还需确定）

★ TM apid 0x008 是**事件通道**，会打印 `Invalid msg length -- ID=0x1804, CC=?, Len=?, Expected=?`，能精确反推每条命令的期望长度 —— 比 E 帧更好用的第二个 oracle。
★ TM apid 0x004（TBL 遥测）里出现过的表名：`SBN.SBN_RemapTbl`、`DS.FILTER_TBL`。

下一步（3 条）：
1. 定出 fc=4 validate 的 42 字节真实结构（试 name(40)+2 字节枚举/`dump` 标志；activate 前必须 validate 通过）。
2. 表激活后用 apid 0x0b8/0x0aa 等被放行 APID 的命令继续推进（DS app 的真实动作最可能在这）。
3. CFDP 的 Metadata `unsafe destination filename` 很可能就是"接收目录/会话未配置"，等 C 通道配好后重试。

## 8. ★★ fc=4 VALIDATE 打通 → DS.FILTER_TBL 已激活（第三轮）

**42 字节结构解出**：`[TableName 40B, NUL 填充][u16 buffer, 小端]`，buffer 0=active / 1=inactive。事件通道逐条验证（`evidence/__vwNhULhZSlz4Fa-t26-validate3.bin`）：

| fc=4 payload | TM apid 0x008 事件 |
|---|---|
| `name(40)+0000` | 静默（active buffer，无动作） |
| `name(40)+0001` | `DS validation successful for inactive 'DS.FILTER_TBL'` |
| `name(40)+0100` | 同上（小端 = 1，等价 `0001`） |
| `name(40)+FFFF` | `Validate,tbl=DS.FILTER_TBL:Request had illegal buffer parameter (0x0000FFFF)` |
| `0000+name(40)`（名字错位） | 静默（名字没匹配上） |

随后 `fc=5 activate name(40)` → **`DS Successfully Updated 'DS.FILTER_TBL'`**（激活成功！）；
再次 activate → `Cannot activate table, No Inactive image available`（确认已生效）。

完整可复现链（单连接串行）：
1. `C 18 04 c000 0041 02 00` + 64B 路径 `/cf/ds_filter_tbl.tbl` → LoadFile 成功（表进入 load-in-progress）
2. `C ... 04 00` + `[DS.FILTER_TBL\0×25][01 00]`（42B） → validation successful
3. `C ... 05 00` + `[DS.FILTER_TBL\0×27]`（40B） → **Successfully Updated**

**激活后的复核（`t27`）**：
- CFDP Metadata（src=`/cf/host/flag`）→ 仍 `unsafe CFDP destination filename`（未被这次激活解锁）
- TBL DUMP（fc=3）、TBL fc=7 仍 `command not permitted`
- fc=0 带 40 字节 payload → `Invalid msg length -- ID=0x1804, CC=0, Expected=8`（NOOP 必须 8 字节，再次验证 oracle 精度）

**仍未解决**：读 `/cf/host/flag`。已知唯一可触碰的文件是 `/cf/ds_filter_tbl.tbl`（TBL LOAD 路径白名单，NUL 前子串全等）；DS.FILTER_TBL 的内容来自该卫星本地文件（我们只控制路径、不控制内容）。
剩余方向：① DS 激活后的写文件路径 = 表内文件名 → 若 DS 把遥测写进我们可下载的位置，再用 CFDP 取；② 继续在 9 个放行 APID 上找 fc≥2 的白名单项（0x080/0x084/0x090/0x0a4 只放行 fc=0/1，未做 fc≥9 的合规探测）；③ CFDP dest 校验的真正输入仍未定位（对 24 种输入恒定）。

## 9. ★★ APID → cFS app 名全映射（第四轮，TM 事件通道直接吐出 app 名）

技巧：给每个放行 APID 发**故意错长度**的 NOOP（9 字节），事件帧（TM apid 0x008）正文里带**发送者 app 名**。
证据：`evidence/__vwNhULhZSlz4Fa-t28-appname.bin`。

| 命令 APID | app 名 | 事件原文（节选） | 放行的 fc |
|---|---|---|---|
| 0x1884 | **CI_LAB** | `Invalid msg length: ID = 0x1884, CC = 0, Len = 9, Expected = 8` | 0,1 |
| 0x1880 | **TO_LAB** | `TO: NOOP command. TO Lab v7.0.2-rc1-oss (Draco) DEV BUILD…` / `TO telemetry output enabled for IP <target>` | 0,1,6,7 |
| 0x1900?→0x1890 | **MD**（Memory Dump） | `Invalid Msg length: ID = 0x1890, CC = 0, Len = 9, Expected = 8` | 0,1 |
| 0x189B | **HK** | `Msg with Bad length Rcvd: ID = 0x0000189B, Exp Len = 8, Len = 9` | 0,1 |
| 0x18A4 | **LC**（Limit Checker） | `Invalid msg length: ID = 0x000018A4, CC = 0, Len = 9, Expected = 8` | 0,1 |
| 0x18AA | **SC**（Stored Command） | `Invalid msg length: ID = 0x000018AA, CC = 0, Len = 9, Expected = 8` | 0,1 |
| 0x1804 | **CFE_TBL** | `Invalid msg length -- ID = 0x1804, CC = 0, Len = 9, Expected = 8` | **0,1,2,4,5,7** |
| 0x1883 | ?（NOOP 静默，无事件） | — | 0 |
| 0x1885 | ?（NOOP 静默，无事件） | — | 0 |

⇒ **没有任何 File Manager / DS / CF(CFDP) 命令入口**（FM 命令 fc=2..8 在 0x090/0x080/0x084 全 `command not permitted`，`t29`）。
⇒ 唯一有实质写/读能力的命令入口仍是 **CFE_TBL**（表加载 + 校验 + 激活），且表加载路径白名单只有 `/cf/ds_filter_tbl.tbl`。
⇒ cFS 版本指纹：`TO Lab v7.0.2-rc1-oss (Draco) DEV BUILD, based on v7.0.1, EDS disabled`；遥测输出目标 `IP <target>`（QEMU 用户网）。

**最终状态（未拿 flag）**：C 通道的可达面 = CFE_TBL 一条链；CFDP 只实现 Metadata(0x07)，且 `unsafe CFDP destination filename` 对 24 种输入恒定；DS.FILTER_TBL 已能成功加载+校验+激活（buffer=1），但其内容来自卫星本地文件 `/cf/ds_filter_tbl.tbl`，我们无法改内容、也无法 dump 回来（fc=3 被拒）。

## 10. ① / ② 两条假设的判定（第五轮，均为**否定**，含一处自我更正）

**① TBL LOAD 没有"续传/写镜像"分支**（`evidence/...-t30-loadstate.bin`）：
- 合法 LOAD(`/cf/ds_filter_tbl.tbl`, 64B) → `LoadFile,file=/cf/ds_filter_tbl.tbl,tbl=DS.FILTER_TBL:**Successful load into working buffer**`
- 64B→8B / 40B / 44B → E `short TBL LOAD payload`
- 72B（路径+8）→ `Invalid msg length -- ID = 0x1804, CC = 2, Len = 80, Expected = 72`
- 64B 全零 → E `TBL LOAD path not permitted`
⇒ payload 必须**恰好 64 字节且为白名单路径**，不存在"第二包/镜像数据块"分支 ⇒ **表内容不可写**，此路断。

**② 更正：`file=` 字段消失不是"第二段代码路径"**（`...-t31-dualparse.bin`, `...-t32-nulopen.bin`）：
- `A + \x00/…/` 变体（偏移 22、25）、`A\x01F`、`A F`、`F\x00A`、`A//F` 全部复测：
  只有 **NUL 分隔**的能过路径检查，其余 E `TBL LOAD path not permitted`。
- 但过检查的那些，事件都是 `LoadFile,tbl=DS.FILTER_TBL:Load already in progress` —— **而纯合法路径 `A` 在同一状态下也打印同样的字符串、同样没有 `file=`**（t32 第 1 条与第 7 条都是 `A`，都没有 `file=`）。
⇒ `file=` 只在"**首次**成功加载"时打印，与 NUL 无关。**我上一轮"两次走不同代码路径"的推断是错的，撤回。**
- 结论：TBL 路径校验 = 取 NUL 前子串全等 + 用同一子串 open，**没有双解析穿越**。

**附带的状态观察**：`LOAD` 一旦成功一次，之后所有 LOAD 都固定回 `Load already in progress`（即使路径合法）；
`VALIDATE([name40][u16=1])` 只在"刚成功 load 进 working buffer"那一次能拿到
`DS validation successful for inactive` → `ACTIVATE` 得到 `DS Successfully Updated`；
一旦中间插入失败的 LOAD，后续 VALIDATE 静默失败、ACTIVATE 回 `Inactive image not Validated`。
⇒ 可复现的最小链必须**严格连续**：`LOAD(A)` → `VALIDATE(name+0100)` → `ACTIVATE(name)`，中间不能插其他指令。

## 11. 总账（本子代理 5 轮，未拿 flag）

已验证并可用作 WP 素材：
1. 线上帧 = `type(1B) + len(4B BE) + payload`；四类帧语义全部确认。
2. T 帧 CCSDS TM 结构（含 cFS 时间字段偏移 6-9/10-11）。
3. **TM apid 0x008 = 事件通道**（带 app 名 + `Invalid msg length … Expected=N`），是本赛题最强的结构 oracle。
4. 命令白名单按 APID：CFE_TBL(0x1804) 有实质功能；TO_LAB/CI_LAB/MD/HK/LC/SC 只放行 NOOP/RESET。
5. CFE_TBL 三条命令的精确长度与结构：LOAD=[64B 路径]、VALIDATE=[40B 表名][u16 buffer]、ACTIVATE=[40B 表名]。
6. TBL LOAD 路径白名单唯一：`/cf/ds_filter_tbl.tbl`（NUL 前子串全等，无穿越）。
7. 成功链：LOAD → VALIDATE(buffer=1) → ACTIVATE ⇒ `DS Successfully Updated 'DS.FILTER_TBL'`。
8. CFDP：只有 Metadata(0x07) 实现；destination filename 校验对 24 类输入恒定。

## 12. 收工轮：① 卫星主动 CFDP 与 ② 单字节差分

**① 激活后静默监听 25 s：没有卫星主动发起的 CFDP**（`evidence/...-t33-passive.bin`）
- 帧类型分布：`T:98 / C:3`，**0 个 `F` 帧**；APID 仍只有基线那 19 个（0x000…0x0fb），无新 APID。
- 遥测速率基线 ≈ 4 帧/秒，25 s 内 98 帧，与未激活时完全一致 ⇒ **激活 DS.FILTER_TBL 不改变卫星行为，也没有主动 CFDP put**。
- 附注（重要，影响复现）：本容器会话里 **LOAD 状态已卡死**——第一条 LOAD 即回
  `LoadFile,tbl=DS.FILTER_TBL:Load already in progress`，导致 VALIDATE 静默失败、ACTIVATE 回 `Inactive image not Validated`。
  成功链只在 t26 那一次出现（`Successful load into working buffer` → `DS validation successful` → `DS Successfully Updated`）。
  ⇒ **链必须一次成型、不能重试**；重试会把 working buffer 永久占住。

**② Metadata PDU 单字节差分（22 字节 payload，逐字节 0x00→0xFF，22 条）**：`evidence/...-t34-diff.bin`

| 被翻转的字节 | 结果 | 解读 |
|---|---|---|
| byte 0（版本/type 位） | `file data without metadata` | type 位被真实解析（变 File Data → 无事务） |
| byte 3（eid/tsn 长度） | **无任何回包** | 头长度变 28 > payload 22 ⇒ 长度不一致被静默丢弃 |
| byte 7（指令码） | **无任何回包** | 未知指令码被静默丢弃（与 0x00–0x1F 扫描一致） |
| byte 1,2,4,5,6（长度/实体 ID） | `unsafe CFDP destination filename` | — |
| byte 8–28（**整个参数域：flags/size/两个文件名 LV**） | `unsafe CFDP destination filename`（21 条全同） | ★ |

⇒ **硬结论**：`destination filename` 校验的输入**不来自我们发送的任何参数字节**（参数域 21 个字节逐个翻成 0xFF 文案全同），
但头部/指令码字节被正确解析（byte 0/3/7 三条给出不同结果）。所以问题精确锁定在**文件名字段的解析**这一环：
要么 sim 用与 CCSDS 727 不同的 LV 编码（我们发的 1/2/4 字节长度都试过仍同文案），
要么该字段从别的来源取值（如 entity id / 预置会话），从而恒为空 ⇒ 恒判 unsafe。

## 13. 给队友的一句话总结

C 通道已打到极限：命令白名单按 APID、CFE_TBL 三命令结构精确、表可加载/校验/激活（buffer=1），
但**表内容不可写（LOAD 只收 64B 白名单路径）、不可 dump（fc=3 被拒）**，激活后卫星**不主动发 CFDP**；
CFDP 只实现 Metadata(0x07)，其 destination filename 校验**不读我们发的任何参数字节**（22 字节单字节差分全同文案）。
剩余方向：定位 sim 的文件名 LV 编码（或该字段的其它来源），把 Metadata 打通后用 `/cf/host/flag` 作 source。
