# 2026 极氪全球汽车网络安全挑战赛（线上赛）Writeup

> **赛事**：2026 极氪全球汽车网络安全挑战赛（线上赛）
> **时间**：2026-09-19（约 08:19–11:23）
> **平台**：—
> **题目**：共 11 题，全部解出（100%）
> **flag 前缀**：`GEELY{...}`

---

## 1. 赛事概览

| 项 | 内容 |
|---|---|
| 赛事全称 | 2026 极氪全球汽车网络安全挑战赛（线上赛） |
| 主办 / 平台 | 极氪（官方线上赛；归档未记录平台名称） |
| 比赛时间 | 2026-09-19（归档记录约 08:19–11:23） |
| 参赛形式 | 线上解题赛（CTF） |
| 题目总数 | 11 |
| 解出题数 | 11 |
| 题目分类 | 汽车协议 / CAN 逆向、固件逆向、密码学、图像取证、协议 / 规范逆向（车联网） |
| flag 格式 | `GEELY{...}` |

本场没有一道"标准固件解包"题：11 道题全部围绕**自定义数据面**展开 —— CAN 帧与滚动令牌、
FSK 磁带音频、ECU 固件里的校准块、自定义 VM 微码、加密差分容器、伪名证书、
PnC/TSP 报文与未保护头、相机/雷达坐标变换、点阵碎片卡。

因此本场最大的特点与瓶颈都不在"工具"上，而在**两件事**：

1. **把被抹掉的常数/格式从附件里恢复出来**（照片色卡、旋钮指针角度、替换环颜色图例、
校准块 CRC、由 `tbs_sha256` 当预言机爆破出的 TBS 文本格式）；
2. **确定 flag 的字节级构造方式** —— 原始字节还是 hex 文本、大小写、摘要是否被
`ASCII(...)` 包装、HMAC 还是纯拼接。至少 5 道题的最终答案由这一层决定。

---

## 2. 成绩统计

### 2.1 分类统计

| 分类 | 解出 / 总数 | 备注 |
|---|---|---|
| 汽车协议 / CAN 逆向 | 2 / 2 | CAN Noir、Pressure Gate |
| 固件逆向 | 3 / 3 | UDS Zero、Delta Forge、Microcode Atrium |
| 密码学 | 1 / 1 | V2X Shadow Certificate（ECDSA nonce 复用） |
| 图像取证 | 2 / 2 | Chromatic Custody、Ghost Fleet |
| 协议 / 规范逆向（车联网） | 3 / 3 | Plug & Charge Rollback、TSP Shadow Rebinding、ADAS Fusion Spoof |
| 合计 | 11 / 11 | 全部解出 |

> 本场**没有官方分类口径**，上表分组是本文自行归纳的结果（按题目的主要考点归并）。

### 2.2 题目索引

| # | 题目 | 分类 | 分值 | 解出 | 状态 | flag |
|---|---|---|---|---|---|---|
| 1 | CAN Noir | 汽车协议 / CAN 逆向 | — | — | ✅ | `GEELY{CAN_8a663785962c9a67_8c45eed5b4fd503c}` |
| 2 | UDS Zero | 固件逆向 | — | — | ✅ | `GEELY{UDS_6B2F51A7_904E96FC_MICROCODE_COLD_START}` |
| 3 | Chromatic Custody | 图像取证 | — | — | ✅ | `GEELY{80e4bf16c0cd763f6c9bf3220af0fe6b37729e7ff7042b54f131ba41f747f69b}` |
| 4 | Pressure Gate | 汽车协议 / CAN 逆向 | — | — | ✅ | `GEELY{SENTINEL_0aeaa5b8100366fe_3bbe8c612a7d9d6f}` |
| 5 | Delta Forge | 固件逆向 | — | — | ✅ | `GEELY{DELTA_801198DDD1CF0B93_D390327DAF554E2C}` |
| 6 | Microcode Atrium | 固件逆向 | — | — | ✅ | `GEELY{ATRIUM_007C1B66052D3321_86B3F3C6DBDD9B5C}` |
| 7 | V2X Shadow Certificate | 密码学 | — | — | ✅ | `GEELY{V2X_898cafad25db5e3fc74a1364_c7df2614b26ca968f35eba0b}` |
| 8 | Plug & Charge Rollback | 协议 / 规范逆向 | — | — | ✅ | `GEELY{PNC_3784e057d579d4f778055b8c_294421b6eb8d1959d6c70d69}` |
| 9 | TSP Shadow Rebinding | 协议 / 规范逆向 | — | — | ✅ | `GEELY{TSP_1cf690e892221045c43b34aa_77b8e1efe308ad6a69775527}` |
| 10 | ADAS Fusion Spoof | 协议 / 规范逆向 | — | — | ✅ | `GEELY{ADAS_480aface33774137b2a67cb7_a42cb64dabf2e476c38ce26e}` |
| 11 | Ghost Fleet | 图像取证 | — | — | ✅ | `GEELY{d40a971673369ea262ca89bfea2da80f3ae02cd4738505fdde5a4f12f921a425}` |

> 状态：`✅` 已解出 ｜ `⚠️` 部分解出 ｜ `❌` 未解出 ｜ `—` 不适用
> 本场归档中**没有分值信息**，也没有各题解出人数，这两列统一记 `—`。

---

## 3. 逐题 Writeup

> 每题统一结构：**元信息 → 思路 → 关键步骤 → 关键代码 → 踩坑 → 产出**。
> 元信息四行固定：`分类` / `状态` / `flag` / `附件`。
> 本场无分值数据，`状态` 行只记 `✅ 已解出`。

### 3.1 · CAN Noir

* **分类**：汽车协议 / CAN 逆向（CAN 总线、汽车电子、逆向还原、状态预测、照片色卡解码）
* **状态**：✅ 已解出
* **flag**：`GEELY{CAN_8a663785962c9a67_8c45eed5b4fd503c}`
* **附件**：`attachments12.zip`（`can_signal_notes.txt`、`can_unlock_trace.log`、`field_service_extract.txt`、`maintenance_photos/decode_card.png`、`maintenance_photos/keyless_pcb.png`）

**思路**

给定 8 帧无钥匙进入 CAN 报文，滚动令牌算法的**所有数值常数都被抹掉**，只能从返修照片与厂商色卡上读回来；读对之后回验 8 帧证明取值唯一，再预测第 9 帧并对其完整数据取哈希出 flag。

**关键步骤**

1. 摸清数据面（`can_signal_notes.txt`）：CAN ID `18FF50A5`、DLC 8 —— `[0:2]` 大端 16 位计数器、`[2]` 固定相位 `0x7D`、`[3:7]` 大端滚动令牌、`[7]` 前 7 字节 XOR。8 帧计数器 `0x0040–0x0047`，XOR 校验全过 ⇒ 下一帧计数器 `0x0048`。
2. 摸清算法结构（`field_service_extract.txt`）：链路为 `X = K ^ (N*S)` → `X = rotl(X,R)` → `X ^= M` → `T = X ^ (X>>13)`，但所有数值常数被抹掉，必须从照片读。
3. 照片取值：

   * `decode_card.png` 提供颜色→nibble 精确调色板（RGB 逐字节匹配，无近似判色）。
   * `keyless_pcb.png` 的 R1..R4 两色块按"左为高 nibble"拼出 `K = 0x49AF32C7`；R5..R8 拼出 `M = 0x5A17C0DE`。
   * U1 丝印两行 `9E37` / `79B1` **不是两个 16 位数**，而是一个 32 位常数 `S = 0x9E3779B1`（黄金比例常数）。
   * `ROTATION STAGE` 画了 7 个三角形 ⇒ `R = 7`。
4. 回验定参：用上述常数重算 8 帧令牌，**8/8 逐位一致**，证明取值唯一（也反向确认了色块解码与 nibble 顺序）。
5. 预测第 9 帧：`N = 0x0048` ⇒ 令牌 `T = 0x409043D7` ⇒ 数据场 `00 48 7D 40 90 43 D7 71`（末尾 XOR = `0x71`），完整数据 `00487D409043D771`。
6. 出 flag：按题面取下一帧完整数据的 `SHA-256` 前 16 / 后 16 位。题面未写死哈希输入的编码，按二进制工件取原始字节为首选：`SHA-256(00487D409043D771) = 8a663785962c9a67…8c45eed5b4fd503c`。

**关键代码**

```python
K, S, M, R, PHASE, MASK = 0x49AF32C7, 0x9E3779B1, 0x5A17C0DE, 7, 0x7D, 0xFFFFFFFF

def rol(x, r):
    return ((x << r) | (x >> (32 - r))) & MASK

def token(n):
    x = K ^ ((n * S) & MASK)          # X = K xor (N * S)
    x = rol(x, R)                     # X = rotate_left(X, R)
    x ^= M                            # X = X xor M
    return (x ^ (x >> 13)) & MASK     # T = X xor (X >> 13)

def frame(n):
    body = bytes([(n >> 8) & 0xFF, n & 0xFF, PHASE]) + token(n).to_bytes(4, "big")
    return body + bytes([functools.reduce(lambda a, b: a ^ b, body)])   # byte7 = XOR

h = hashlib.sha256(frame(0x0048)).hexdigest()      # 对下一帧完整数据取哈希
print(f"FLAG = GEELY{{CAN_{h[:16]}_{h[-16:]}}}")
```

**踩坑**

* 色卡读数易错：**peru A ≠ 橙 3**、**橄榄 E ≠ 黄 4** —— 按颜色名的直觉取 nibble 会把 K/M 读错。
* U1 丝印若按两个 16 位数（`0x9E37`、`0x79B1`）去读，**任何一帧都对不上**；这是本题唯一的设计陷阱。
* 题面没有写死哈希输入的编码，编码选择直接决定 flag。

> 备选（同一帧数据、不同哈希输入编码）：hex 小写 `GEELY{CAN_c99276b6468e2122_41060ddd01210ae2}`、hex 大写 `GEELY{CAN_c5007c61406904bf_f65dc5131e39daea}`、仅 4 字节令牌 `GEELY{CAN_964372d2f1397c89_39de91c494296ca6}`；首选为原始字节 `GEELY{CAN_8a663785962c9a67_8c45eed5b4fd503c}`。

**产出**：`scripts/can12_solve.py`、`notes/09-GEELY-CAN-无钥匙进入滚动令牌.md`

---

### 3.2 · UDS Zero

* **分类**：固件逆向（UDS、CRC32、密钥派生、循环异或）
* **状态**：✅ 已解出
* **flag**：`GEELY{UDS_6B2F51A7_904E96FC_MICROCODE_COLD_START}`
* **附件**：`attachments11.zip`（`firmware/ecu_diag_fw.bin` 32 KiB、`firmware/rescue_card.png`、`maintenance_photos/diagnostic_bulletin.png`、`maintenance_photos/maintenance_tool_screen.png`）

**思路**

32 KiB ECU 固件切片 + 3 张维护资料 PNG：从 PNG 里 OCR 出校准块布局与 32 位密钥派生算法，按 CRC32 自校验在固件里定位校准块取出常数，再对最终 SEED 派生密钥、用大端密钥字节循环异或解开 DID 记录得到 flag。

**关键步骤**

1. `attachments11.zip` 内为 32 KiB 原始 ECU 固件切片（`ecu_diag_fw.bin`）和 3 张维护资料 PNG。
2. OCR 三张图：

   * `rescue_card.png`：扫描固件中的 `0xC3`，要求 `CRC32(前 0x16 字节) == 后 4 字节大端`，并给出头部字段布局。
   * `diagnostic_bulletin.png`：给出 32 位密钥派生算法。
   * `maintenance_tool_screen.png`：给出多组 `SEED -> KEY` 和最终 `SEED = 6B2F51A7`。
3. 在固件中扫描并通过 CRC32 校验，命中偏移 **`0x5A17`**：

```
   c3 0d a51f3e27 9e3779b1 27d4eb2f 85ebca6b 00007b21 a4e853a1
   ```

   解析得到：`rotation = 0x0D`、`K0 = 0xA51F3E27`、`K1 = 0x9E3779B1`、`K2 = 0x27D4EB2F`、`K3 = 0x85EBCA6B`、`DID record offset = 0x7B21`（块内 `+0x16` 起的 4 字节为 CRC32）。

4. 用截图里的 5 组已知 SEED/KEY 对验证派生算法，全部匹配：`11223344→43619418`、`2468ACE0→375AF638`、`5A17B3C2→4D8A7C2C`、`7F3E19D6→3895619F`、`8C0A44E2→DC270A4C`。
5. 对最终种子 `0x6B2F51A7` 求密钥：`KEY = 0x904E96FC`。
6. 从 `0x7B21` 读取 `0x40` 字节 DID 记录，使用**大端密钥字节 `90 4E 96 FC` 循环异或**解密，去除尾部 `00` 填充，得到 flag。

**关键代码**

```python
data = open('ecu_diag_fw.bin', 'rb').read()

# 1) 扫描并校验 C3 校准块：CRC32(前 0x16 字节) == 后 4 字节大端
off = next(i for i in range(len(data) - 0x1A + 1)
           if data[i] == 0xC3
           and (zlib.crc32(data[i:i + 0x16]) & 0xFFFFFFFF)
               == int.from_bytes(data[i + 0x16:i + 0x1A], 'big'))

rotation = data[off + 1]
K0, K1, K2, K3, did_off = struct.unpack('>IIIII', data[off + 2:off + 0x16])

# 2) 32 位密钥派生
def derive_key(seed):
    x = (seed ^ K0) & 0xFFFFFFFF
    x = (x * K1 + K3) & 0xFFFFFFFF
    x ^= x >> 15
    x = ((x << rotation) | (x >> (32 - rotation))) & 0xFFFFFFFF
    return x ^ K2

key = derive_key(0x6B2F51A7)               # 0x904E96FC
kb  = key.to_bytes(4, 'big')               # 90 4E 96 FC

# 3) DID 记录：大端密钥字节循环异或
enc = data[did_off:did_off + 0x40]
dec = bytes(c ^ kb[i % 4] for i, c in enumerate(enc))
flag = dec.rstrip(b'\x00').decode()
```

**产出**：—（源只给出代码、未记脚本名；归档 `scripts/` 与 `notes/` 中无 UDS Zero 对应产物）

---

### 3.3 · Chromatic Custody

* **分类**：图像取证（Misc、颜色 XOR、HMAC-SHA256）
* **状态**：✅ 已解出
* **flag**：`GEELY{80e4bf16c0cd763f6c9bf3220af0fe6b37729e7ff7042b54f131ba41f747f69b}`
* **附件**：`attachments7.zip`（`cards/evidence_envelope.png`、`cards/registration_jig.png`、`plates/front_plate.png`、`plates/rear_plate.png`、`plates/front_blank.png`、`plates/rear_blank.png`）

**思路**

两块印刷板各印了 128 个颜色标记，`red XOR cyan` 逐格得到 16 字节密钥；两板不在同一坐标系，必须先用 3 个 fiducial 解出相似变换再对格取位，最后按封套字段拼出 custody record 做 HMAC-SHA256。

**关键步骤**

1. OCR 证据封套得到关键信息：`operator: overlay-custody`、`vehicle: LGXFE4SB8N2077653`、`epoch: 1790412800`、`plate rule: red xor cyan`、`secret width: 16 bytes`、`authentication: HMAC-SHA256`。
2. OCR 配准卡得到：`REGISTRATION JIG: THREE FIDUCIALS`、`Place cyan marks over matching red marks`；两张板上各有 3 个黑色圆环定位点（fiducial）。
3. 求 **front → rear** 的相似变换：以 3 个 fiducial 中心为控制点，最小二乘解出 `a = 0.99709947`、`b = 0.07626172`、`tx = 57.91414594`、`ty = -31.84669792`（即约旋转 4.37°，尺度约 1.000）。
4. 两张板上各有 128 个数据圆环，排成 **16 行 × 8 列，间距 54 px**；front 网格起点约为 `(630, 240)`。
5. 按颜色规则取位：front 暗红环 = 1、灰环 = 0；rear 暗青环 = 1、灰环 = 0；同一格两板异或，即 `red XOR cyan`。字节顺序按题卡约定：`row0 = byte0`、左列 = bit7、右列 = bit0。
6. 还原出 16 字节密钥：`2b9811754604d2c8c40268e21e903777`。
7. custody record 按封套字段顺序用 `|` 拼接：`overlay-custody|LGXFE4SB8N2077653|1790412800`。
8. 计算 `HMAC-SHA256(key, record) = 80e4bf16c0cd763f6c9bf3220af0fe6b37729e7ff7042b54f131ba41f747f69b`，平台返回"恭喜，提交的 Flag 正确!"。

**关键代码**

```python
X0, Y0, STEP = 630, 240, 54                                  # front 数据网格 16x8，间距 54 px
A, B, TX, TY = 0.99709947, 0.07626172, 57.91414594, -31.84669792   # front -> rear

FRONT_COLORS = [(140, 10, 10), (175, 160, 145)]   # 1 = dark red,  0 = gray
REAR_COLORS  = [(8, 90, 125),  (150, 185, 205)]   # 1 = dark cyan, 0 = gray

key = bytearray()
for r in range(16):
    b = 0
    for c in range(8):
        x, y = X0 + c * STEP, Y0 + r * STEP
        xr = int(round(A * x - B * y + TX))       # rear 的对应格必须投影后取
        yr = int(round(B * x + A * y + TY))
        b = (b << 1) | (bit_at(front, x, y, FRONT_COLORS)
                        ^ bit_at(rear, xr, yr, REAR_COLORS))
    key.append(b)                                  # row0 = byte0, 左列 = bit7
key = bytes(key)                                   # 2b9811754604d2c8c40268e21e903777

record = b'overlay-custody|LGXFE4SB8N2077653|1790412800'
digest = hmac.new(key, record, hashlib.sha256).hexdigest()
print('FLAG = GEELY{%s}' % digest)
```

**踩坑**

* 两板不是同一坐标系：配准卡明确要求 "Place cyan marks over matching red marks"，rear 的读点必须先用 3 个 fiducial 拟合出的相似变换逐点投影，**在相同像素坐标上直接读会错位**。
* 判色用精确 RGB 调色板逐字节匹配（`(140,10,10)` 记 1、`(175,160,145)` 记 0），考的就是"无近似判色"；用颜色阈值近似判断容易翻位。

**产出**：`scripts/att7_solve.py`、`notes/11-GEELY-CHROMATIC-CUSTODY.md`

---

### 3.4 · Pressure Gate

* **分类**：汽车协议 / CAN 逆向（Misc 逆向：FSK 音频解码、CAN 状态机、旋转开关与替换环识读）
* **状态**：✅ 已解出
* **flag**：`GEELY{SENTINEL_0aeaa5b8100366fe_3bbe8c612a7d9d6f}`
* **附件**：`attachments10.zip`（`evidence/tape_reader.wav`、`evidence/tape_reader_card.png`、`evidence/update_rule.png`、`evidence/segment_trace.log`、`photos/gauge_panel.png`、`photos/sbox_ring.png`）

**思路**

参数被拆到三种介质里：FSK 磁带音频给出 ROT/MASK，旋钮板照片给出乘数，替换环照片给出 S-BOX；拼齐后过滤有效 CAN 帧、用全部 72 帧验证状态转移，再预测下一帧并按其哈希输入出 flag。

**关键步骤**

1. 磁带卡（`tape_reader_card.png`）规定：FSK `bit 1 = 1800 Hz`、`bit 0 = 900 Hz`；bit 周期 45 ms，MSB first；帧结构 `sync16 = A5 C3`、`rot8`、`mask32`、`crc16`；CRC 为 **CRC-16/CCITT-FALSE**（poly `0x1021`、init `0xFFFF`、final XOR `0xFFFF`）。
2. 解码 48 kHz WAV：每个 bit 取 `round(48000 × 0.045) = 2160` 个采样点，忽略尾部静音后得到 9 字节 `A5 C3 0B 3D 6F 8A 15 3A 44`；前 7 字节 CRC 正好 `3A44` ⇒ `ROT = 0x0B`、`MASK = 0x3D6F8A15`。
3. 读状态推进规则（`update_rule.png`）：有效帧 `status = 0x5A`；最后一字节 = 前 7 字节异或；payload 布局 `counter(2 BE) + state(4 BE) + status(1) + xor(1)`；推进公式：

```
   X = PREVIOUS xor COUNTER
   X = X * MULT
   X = rotate_left(X, ROT)
   X = X xor MASK
   STATE = substitute_nibbles(X, SBOX)
   ```

   **注意：当前帧的 COUNTER 是作用于上一帧 PREVIOUS 得到当前帧 STATE 的。**

4. 日志共 96 帧，过滤后**有效帧 72 个**，计数器 `0x1000..0x1047`。
5. 旋转开关板 `gauge_panel.png`：8 个旋钮指针位置按 16 档量化，读数 `G0..G7 = 7 4 F A 1 2 C 9` 排列为

```
   G0 G1 G2 G3 G4 G5 G6 G7
    7  F  4  A  1  2  C  9
   ```

   从左到右为高到低 nibble ⇒ `MULT = 0x7F4A12C9`。图中每档下方的 `15` 是干扰信息，真值由指针角度决定（归档笔记另记：按 16 档位反射映射 `digit = (4 - slot) mod 16` 读角度）。

6. 替换环 `sbox_ring.png`：环上的黑色数字是输入、底部同色图例对应输出；结合 CAN 状态序列可完全确定 `SBOX[0..F] = C 5 6 B 9 0 A D 3 E F 8 4 7 1 2`。用全部 72 个有效帧验证状态转移，全部一致。
7. 预测下一帧：最后一帧 `counter = 0x1047`、`state = 0x110F8EB8` ⇒ 下一帧 `counter = 0x1048`、`next_state = 0x83B4CE18` ⇒ `payload = 10 48 83 B4 CE 18 5A E3`，完整数据 `104883B4CE185AE3`。
8. 生成 FLAG：本题**实际接受的哈希输入是大写十六进制字符串**：`SHA-256("104883B4CE185AE3") = 0aeaa5b8100366fef201429711bdf033ae39ceef310153573bbe8c612a7d9d6f`，取前 16 / 后 16 位。

**关键代码**

```python
ROT, MASK, MULT = 0x0B, 0x3D6F8A15, 0x7F4A12C9
SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
        0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]

def substitute_nibbles(x):
    y = 0
    for sh in (28, 24, 20, 16, 12, 8, 4, 0):
        y = (y << 4) | SBOX[(x >> sh) & 0xF]
    return y

def advance(prev_state, counter):                  # counter 是"当前帧"的计数器
    x = (prev_state ^ counter) & 0xFFFFFFFF
    x = (x * MULT) & 0xFFFFFFFF
    x = rotl32(x, ROT)
    x ^= MASK
    return substitute_nibbles(x)

# 有效帧：status == byte6 == 0x5A 且 XOR(bytes0..6) == byte7
next_state = advance(0x110F8EB8, 0x1048)            # 0x83B4CE18
frame_hex  = "104883B4CE185AE3"                     # 大写十六进制文本才是被接受的哈希输入
digest = hashlib.sha256(frame_hex.encode()).hexdigest()
flag = f"GEELY{{SENTINEL_{digest[:16]}_{digest[-16:]}}}"
```

**踩坑**

* 每 bit 必须按 `round(sr × 0.045)` 取整切分（48 kHz 下为 2160 点），并去掉尾部静音产生的 `0x00`，否则磁带数据会多出尾巴、CRC 对不上。
* COUNTER 的语义是"当前帧的计数器作用于上一帧 STATE"；把它当成"生成下一帧的参数"会让整条链错位。
* MULT 真值由指针角度（16 档量化）决定，每档下方的 `15` 是干扰信息。
* 哈希输入编码：原始 8 字节、小写 hex、大写 hex 三种都"看起来合理"，本题实际接受的是**大写十六进制字符串**。

> 备选（同一份归档记录里的其余编码）：`SHA-256(原始 8 字节)` → `GEELY{SENTINEL_3e270fb18704391f_0c6837f7d8e2ded9}`；小写 hex → `GEELY{SENTINEL_377ee4c752bb87b6_faa9b7929ce7b467}`；首选为大写 hex → `GEELY{SENTINEL_0aeaa5b8100366fe_3bbe8c612a7d9d6f}`。

**产出**：`notes/10-GEELY-SENTINEL-压力网关.md`（赛时解题脚本 `solve_att10.py` 属草稿区，归档时已清理，`scripts/` 内无对应脚本）

---

### 3.5 · Delta Forge

* **分类**：固件逆向（固件差分、协议逆向、密码分析）
* **状态**：✅ 已解出
* **flag**：`GEELY{DELTA_801198DDD1CF0B93_D390327DAF554E2C}`
* **附件**：`attachments5.zip`（`firmware/base_image.bin` 0x2000、`firmware/ecu_delta_container.bin` 301 字节、`protocol/calibration_stamp.txt`、`protocol/forge_protocol.txt`）

**思路**

301 字节的加密差分容器里混着 20 条记录、其中 8 条是诱饵：只有按"密钥随父摘要链式变化 + 字节和校验 + 链提示摘要"三条判据顺序推进，才能从 12 个序列各筛出唯一一条真补丁；打完补丁后用基线镜像与序列号派生的 MANIFEST 密钥解开 manifest 得 flag。

**关键步骤**

1. 附件：`base_image.bin` 基线镜像（大小 `0x2000`）、`ecu_delta_container.bin` 加密差分容器（301 字节）、`calibration_stamp.txt`、`forge_protocol.txt`。
2. 关键常量：`FAMILY = GEELY-DELTA-FORGE-7`、`ROOT_ID = C64A8C1BB751D6CC`、补丁序列 1..12、`MANIFEST_OFFSET = 0x1F00`、`MANIFEST_LENGTH = 0x60`。
3. 容器按 `uint16 BE length + payload` 解析，共 **20 条记录**。
4. 对序列 S 解密：

```
   key       = SHA256(FAMILY || parent_id || uint16be(S))
   plaintext = ciphertext XOR repeating(key)
   ```

5. 补丁格式：

```
   +00        EC 4F                 magic
   +02        offset uint16 BE
   +04        op uint8
   +05        length uint8
   +06        data[length]
   +06+len    chain_hint uint16 BE
   +08+len    checksum uint8
   ```

   整条记录长度 = `9 + length`。操作：`A0` 覆盖、`A1` 异或、`A2` 加、`A3` 左旋。

6. 校验字段题面写作 xor checksum，但**实测为字节和**：`sum(plaintext[:8 + length]) & 0xff == checksum`。链提示计算：`digest = SHA256(FAMILY || image_after_patch || uint16be(S))`，要求 `chain_hint == digest[:2]`，且 `next_parent_id = digest[:8]`。
7. 恢复出的真实补丁链：

| S | 记录 idx | offset | op | data | chain_hint | next_parent |
|---|---|---|---|---|---|---|
| 1 | 0 | 0x1951 | A3 左旋 | `03` | `31a7` | `31a7b79c3b12c950` |
| 2 | 3 | 0x1EE0 | A2 加 | `21ef4c407475` | `854d` | `854d739150f5466e` |
| 3 | 4 | 0x0EC0 | A0 覆盖 | `aa298e534b` | `70e8` | `70e83a568e1af411` |
| 4 | 6 | 0x060E | A3 左旋 | `01` | `7fe8` | `7fe8b04e02aaa420` |
| 5 | 8 | 0x0B28 | A1 异或 | `50bd2f613c` | `8244` | `8244c71eee37ec34` |
| 6 | 9 | 0x0E68 | A2 加 | `31835b621d9fb1` | `f316` | `f3162c08946bcc91` |
| 7 | 10 | 0x053A | A2 加 | `d507` | `73b6` | `73b6179fb8a44c47` |
| 8 | 11 | 0x0E44 | A3 左旋 | `04` | `d8a3` | `d8a34442a812c3f0` |
| 9 | 12 | 0x0202 | A3 左旋 | `03` | `87d1` | `87d1a0d78db481e1` |
| 10 | 14 | 0x00F0 | A2 加 | `cb14ca` | `a59a` | `a59a2ee5f8a73169` |
| 11 | 16 | 0x1099 | A3 左旋 | `03` | `ee98` | `ee98c6afb6b5c238` |
| 12 | 17 | 0x1B33 | A0 覆盖 | `26d3d77ddd54` | `9ba3` | `9ba30527b4377df4` |

8. 诱饵记录为：`1, 2, 5, 7, 13, 15, 18, 19`（即真实使用 `0, 3, 4, 6, 8, 9, 10, 11, 12, 14, 16, 17`）。
9. 最终镜像 `SHA-256 = 771cc12691d6e5b922e788f3e161e291cc753c7ac473a442c2bcc5f01c5d43db`（chain 打到 seq 12 后再无后续补丁）。
10. Manifest 解密：

&#x20;   ```
    MANIFEST_KEY = SHA256(FAMILY || base_image[0x0000:0x1F00] || uint16be(12) || b"MANIFEST")
    ```

    密钥 `888210bfaa24a284e4149f23cf9aab79a7bb6387967baee0e06c0776454f57a4`；对 `0x1F00` 开始的 `0x60` 字节重复 XOR，去除尾部 `0xA5` padding，得到

&#x20;   ```
    DELTA|12|GEELY{DELTA_801198DDD1CF0B93_D390327DAF554E2C}|
    ```

**关键代码**

```python
FAMILY  = b"GEELY-DELTA-FORGE-7"
ROOT_ID = bytes.fromhex("C64A8C1BB751D6CC")

image, parent_id = base, ROOT_ID
for seq in range(1, 13):
    key = hashlib.sha256(FAMILY + parent_id + struct.pack(">H", seq)).digest()
    for idx, cipher in enumerate(records):
        pt = xor_repeat(cipher, key)
        if len(pt) < 9 or pt[:2] != b"\xEC\x4F":
            continue
        offset = struct.unpack(">H", pt[2:4])[0]
        op, length = pt[4], pt[5]
        if len(pt) != 9 + length:                     # 整条长度 = 9 + len（不是 8 + len）
            continue
        data     = pt[6:6 + length]
        hint     = pt[6 + length:8 + length]
        checksum = pt[8 + length]
        if (sum(pt[:8 + length]) & 0xFF) != checksum:  # 实测是 SUM，不是题面写的 XOR
            continue
        new_image = apply_patch(image, offset, op, data)
        digest = hashlib.sha256(FAMILY + new_image + struct.pack(">H", seq)).digest()
        if hint != digest[:2]:
            continue
        image, parent_id = new_image, digest[:8]
        break

manifest_key = hashlib.sha256(
    FAMILY + base[:0x1F00] + struct.pack(">H", 12) + b"MANIFEST").digest()
manifest = xor_repeat(image[0x1F00:0x1F00 + 0x60], manifest_key).rstrip(b"\xA5")
print("FLAG =", manifest.split(b"|")[2].decode("ascii"))
```

**踩坑**

* 校验字段题面写作 `xor checksum`，**实测是 8 位字节和**：rec0 明文 `ec4f1951a3010331a724` 的 `XOR = 0xdc` 对不上，`SUM = 0x24` 才等于字段值。
* 整条记录长度是 `9 + length`；按文档暗示的 `8 + length` 解析会把 20 条记录**全部判废**。
* 容器里 8 条诱饵记录（idx `1, 2, 5, 7, 13, 15, 18, 19`）；只有同时满足 magic、长度、SUM 校验与链提示四项，才能让每个 seq 收敛到唯一候选。

**产出**：`scripts/forge_verify.py`（另有 `scripts/forge_offline.py`）、`notes/31-GEELY-DELTA-FORGE.md`

---

### 3.6 · Microcode Atrium

* **分类**：固件逆向（自定义 VM 微码、数据校验与解密）
* **状态**：✅ 已解出
* **flag**：`GEELY{ATRIUM_007C1B66052D3321_86B3F3C6DBDD9B5C}`
* **附件**：`attachments.zip`（`atrium_boot.bin` 8 KB / 0x2000、`atrium_protocol.txt`、`opcode_plate.txt`、`hardware_stamp.txt`）

**思路**

8 KB 镜像里有 16 条 lane，只有 6 条通过四项校验；掩码链表还是自定义 VM 的字节码 —— 按 CRC32 升序拼成 0xC0 字节程序丢进 VM 跑出 32 字节 KEY，再 XOR 解 manifest。**核心陷阱是 CRC32 必须对 mask 之后的 chunk 计算**。

**关键步骤**

1. 附件结构：8 KB 镜像 `atrium_boot.bin`（`0x2000`）+ 3 份说明 `atrium_protocol.txt`（lane 布局与校验规则）、`opcode_plate.txt`（VM 指令集）、`hardware_stamp.txt`（关键偏移）。镜像分两块：`0x1000` 是 16 条 lane 表（stride `0x100`），`0x1C00` 是 `0x60` 字节的 manifest（重复 KEY 做 XOR）。
2. lane 布局与解掩码：`+000` masked chunk(0x20)、`+020` lane_id(u16be)、`+022` status、`+023` reserved、`+024` seed(u32be)、`+028` crc32(u32be)、`+02C` `"ATRM"`。
`LANE_MASK = SHA256("ATRIUM-MICROCODE-8" || u16be(lane_id) || u32be(seed) || "ATRIUM-LANE")`，`unmasked = masked XOR LANE_MASK`。
3. 16 条里只有 **6 条**通过四项校验（对上 protocol 的 `VALID LANES 6`）：

   * lane #0–#5 全过 → 真；
   * lane #6/#7 的 marker 与 crc 都对，但 status/reserved 错 → 专门骗"只看 crc"的伪造项；
   * lane #8–#15 marker 都不是 `ATRM` → 废数据；
   * **关键：CRC32 必须对 mask 之后的 chunk 计算，这是唯一硬判据。**
4. 拼装程序：6 条真 lane 按 `CRC32(unmasked)` **升序**拼接，`6 × 0x20 = 0xC0` 字节，正好等于 opcode plate 声明的程序长度（自校验信号）。
5. 跑 VM 取 KEY：`R0..R5` 初值 = 有效 lane 的 `lane_id`，其余为 0；指令 `byte0 = [opcode(4) | dst(4)]`、`byte1 = [src(4) | imm(4)]`。执行 192 字节后 OUT 恰好吐 32 字节 KEY：

```
   007c1b66052d332186b3f3c6dbdd9b5c5ceb50b4eadce3efd1faa763eceb87eb
   ```

6. 解 manifest：`0x1C00` 起 `0x60` 字节与 KEY 循环 XOR，剥掉 `0xA5` padding ⇒ `ATRIUM|GEELY{ATRIUM_007C1B66052D3321_86B3F3C6DBDD9B5C}|`。

一句话链路：四项校验筛出 6 条真 lane → 按 crc 升序拼成 0xC0 字节 VM 程序 → 跑 VM 得 32 字节 KEY → XOR 解 manifest → flag。

**关键代码**

```python
FAMILY, TAG = b"ATRIUM-MICROCODE-8", b"ATRIUM-LANE"
LANE_TABLE, LANE_STRIDE, LANE_CHUNK = 0x1000, 0x100, 0x20
MANIFEST_OFF, MANIFEST_LEN = 0x1C00, 0x60

def lane_mask(lane_id, seed):
    return hashlib.sha256(FAMILY + struct.pack(">H", lane_id)
                          + struct.pack(">I", seed) + TAG).digest()

unmasked = bytes(a ^ b for a, b in
                 zip(img[base:base + LANE_CHUNK], lane_mask(lane_id, seed)))
ok = (status == 0x6D and reserved == 0xC3 and marker == b"ATRM"
      and crc == (zlib.crc32(unmasked) & 0xFFFFFFFF))   # CRC 必须对 unmasked 算

valid = sorted((L for L in parse_lanes(img) if L["ok"]), key=lambda L: L["crc"])
prog  = b"".join(L["chunk"] for L in valid)             # 6 x 0x20 = 0xC0
key   = run_vm(prog, [L["lane_id"] for L in valid])[:32]

plain = bytes(c ^ key[i % 32]
              for i, c in enumerate(img[MANIFEST_OFF:MANIFEST_OFF + MANIFEST_LEN]))
print(plain.rstrip(b"\xA5").decode())
```

**踩坑**

* lane 过滤是本题核心陷阱：**CRC32 必须对 mask 之后的 chunk 计算**；对 masked 数据算 CRC 会把 6 条真 lane 全部判废。
* lane #6/#7 的 marker 与 crc 都正确，只有 status/reserved 错 —— 这是专门为"只看 crc"的过滤逻辑准备的伪造项；四项校验缺一不可。
* 真 lane 必须按 `CRC32(unmasked)` 升序拼接；`0xC0` 恰好等于 opcode plate 声明的长度，是顺序正确的自校验信号。

**产出**：`scripts/atrium_solve.py`、`notes/06-ATRIUM-MICROCODE-8.md`

---

### 3.7 · V2X Shadow Certificate

* **分类**：密码学（车联网安全、ECDSA nonce 复用）
* **状态**：✅ 已解出
* **flag**：`GEELY{V2X_898cafad25db5e3fc74a1364_c7df2614b26ca968f35eba0b}`
* **附件**：`attachments.zip`（归档中与 Microcode Atrium 附件同名，按 sha256 `6eca41d69a1fa8371d0a6d9181f8bb80d6ed8b482ca9cd940c52a84cde5d3a0e` 区分；含 `evidence/v2x_session.jsonl`、`pki/ca_cert.pem`、`signed_message_profile.txt`）

**思路**

三帧签名里有两帧共用同一个 ECDSA 随机数 `k`（`r` 相同、TBS 不同），因此可以直接解出私钥 `d`；拿到 `d` 后按题面公式把 `d`、两张伪名证书的 8 字节 ID 与 CA 证书 DER 摘要拼进 TOKEN 得到 flag。

**关键步骤**

1. 报文结构（`signed_message_profile.txt`）：

```
   GEVX | ver | cidlen | cert_id(8) | tbs_len(2,BE) | sig_len(1) | sig r||s(64) | TBS(ASCII)
   ```

   解析偏移：`+00` magic `GEVX`、`+04` version = `02`、`+05` cert_id_length = `08`、`+06` cert_id(8)、`+0E` tbs_len(2 BE，`0x86` = 134)、`+10` sig_len `0x40`、`+11` 签名 `r||s`(64)、`+51` TBS。三帧均为 215 字节。TBS 直接做 `SHA-256(TBS)` 验 ECDSA P-256，没有 transcript hash。

2. 三帧解析：frame1 与 frame2 的 `r` **完全相同**（`372320da87b676c3b0ecde94cd6d68133791487df6daf368917e028de7959e8b`）但 TBS 不同 ⇒ 同一条随机数 k 签了两条消息：

```
   k = (h1 - h2) / (s1 - s2) mod n
   d = (s1·k - h1) / r       mod n
   ```

   得到 `k = 5915f44e2ef21ba6974ada4ed6af818ca28fc2cd4c147f3dc97513697772cf86`、`d = 4b04c9f2dc7b53f87b8a0752b9ec9f391edc760379baf1a41dfc4a1c062be59b`；两条签名都能用 d 复现。frame3 的 `r` 不同（`24110833…`），是干扰项。

3. 交叉验证：`d·G` 正好等于 `A31F`、`B47D` 两张证书里的公钥（两者公钥字节完全相同，`C92A` 是另一把）—— 正是题面说的"同一私钥映射多张伪名证书"，也正好对应被 suspended 的那两张。
4. 组 token：

```
   TOKEN = SHA-256("GEELY-V2X-KEY-RECOVERY" || d(32B) || cid1(8B) || cid2(8B) || SHA-256(DER(CA)))
   FLAG  = GEELY{V2X_<token 前 24 hex>_<token 后 24 hex>}
   ```

   cid 用**完整 8 字节**（`2561` 是 authority register，不能只取 4 字节 serial），按升序排：`256100002561a31f`、`256100002561b47d`。`SHA-256(DER(root CA)) = 36402f9ce95bfe19bd64c64a318825686c8a11587307fb50e087f367179512c8`，`TOKEN = 898cafad25db5e3fc74a1364a99811b10f2830abc7df2614b26ca968f35eba0b`。

5. 复现：`python3 scripts/v2x_solve.py`。

**关键代码**

```python
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# 找 r 重复的两帧（frame3 的 r 不同，是干扰项）
f1, f2 = next((a, b) for i, a in enumerate(frames)
              for b in frames[i + 1:] if a["r"] == b["r"])
k = (f1["h"] - f2["h"]) * pow(f1["s"] - f2["s"], -1, N) % N
d = (f1["s"] * k - f1["h"]) * pow(f1["r"], -1, N) % N

cids = sorted([f1["cid"], f2["cid"]])          # 完整 8 字节，升序
ca_hash = hashlib.sha256(
    x509.load_pem_x509_certificate((BASE / "pki" / "ca_cert.pem").read_bytes())
        .public_bytes(Encoding.DER)).digest()

token = hashlib.sha256(b"GEELY-V2X-KEY-RECOVERY" + d.to_bytes(32, "big")
                       + cids[0] + cids[1] + ca_hash).hexdigest()
print(f"FLAG = GEELY{{V2X_{token[:24]}_{token[-24:]}}}")
```

**踩坑**

* frame3 的 `r` 与 frame1/2 不同，是干扰项，不能参与 nonce 复用求解。
* cid 必须取完整 8 字节；只取 4 字节 serial 会把 token 拼错（`2561` 是 authority register 前缀）。
* token 里的 CA 摘要必须对**证书 DER（重新序列化后的字节）**取 SHA-256，而不是 PEM 文本。

**产出**：`scripts/v2x_solve.py`、`notes/07-GEELY-V2X-BSM.md`

---

### 3.8 · Plug & Charge Rollback

* **分类**：协议 / 规范逆向（证书 PKI ECDSA 验签、协议降级 Downgrade、JSONL 数据分析、格式逆向）
* **状态**：✅ 已解出
* **flag**：`GEELY{PNC_3784e057d579d4f778055b8c_294421b6eb8d1959d6c70d69}`
* **附件**：`attachments1.zip`（`pki/ev_contract_cert.pem`、`pki/mobility_operator_ca.pem`、`pki/v2g_root_ca.pem`、`protocol/contract_migration_profile.txt`、`evidence/charging_session_archive.jsonl`）

**思路**

桩端对 schema `v001` 文档只校验"文档里存在的字段"，缺失字段用固定默认值补齐，而这些默认值**不被签名覆盖** —— 于是加载旧版本报文就能把授权范围从 `PnC-START-USER` 悄悄放大到 `PnC-START-MAINTENANCE`。真正的技术难点是：PROFILE 没给 TBS 文本格式，只能拿每条记录自带的 `tbs_sha256` 当预言机爆破出来。

**关键步骤**

1. 附件结构（`attachments1.zip`）：

   * `pki/ev_contract_cert.pem` —— 合约证书 `CN=PNC-EV-VIN-LGEGF1V29PX000002`
   * `pki/mobility_operator_ca.pem` —— 中间 CA
   * `pki/v2g_root_ca.pem` —— 根 CA
   * `protocol/contract_migration_profile.txt` —— 验收规则 + CODE 公式
   * `evidence/charging_session_archive.jsonl` —— 7 条历史授权记录
2. 抓住题眼：**兼容层默认值 = 降级**。PROFILE 明确写出桩端对 schema v001 文档只校验 document 里存在的字段，缺失字段用固定默认值补：

| 缺失字段 | 默认值 |
|---|---|
| `max_current_a` | `250` |
| `price_plan` | `PUBLIC_UNMETERED` |
| `authorization_scope` | `PnC-START-MAINTENANCE` |

   默认值被当成配置而非签名数据 ⇒ 签名照样过，但授权范围被悄悄放大（`PnC-START-USER` → `PnC-START-MAINTENANCE`）。这就是降级攻击。

3. 证书链验证：用 `cryptography` 逐级验签 `ev_contract_cert ← mobility_operator_ca ← v2g_root_ca`，三级**全部 SIGNATURE OK**；有效期 2025-01-01 ~ 2027-01-01 覆盖所有记录时间。
4. 关键一步：恢复 TBS 文档格式。签名是 ECDSA P-256 over **exact ASCII TBS**（`r||s`，非 DER），但 PROFILE 没给 TBS 格式。突破口：每条记录自带 `tbs_sha256`，拿它当预言机爆破格式。在 **14540 个候选**（键值分隔符 / 行分隔符 / 尾换行 / 排序 / 前缀 / JSON / XML…）中，唯一同时命中全部 7 条记录的格式为：

```
   GEELY-PNC-TBS\n
   contract_id=<v>\n
   action=<v>\n
   ...（按 signed_fields 顺序，每行一条，含尾换行）
   ```

5. 逐条验签 —— 发现**验签筛不掉攻击记录**：7 条记录签名全部有效，TBS 哈希也全部自洽。说明桩端验签逻辑正确，必须靠前置条件筛选：

| 记录 | 版本 | 判定 |
|---|---|---|
| CH-100201 | v003 | ✗ `action=START` |
| CH-100347 | v003 | ✗ `action=STOP` |
| CH-100512 | v001 | ✗ 合约 `PNC-OTHER-999` 不匹配 |
| CH-100753 | v001 | ✗ `vehicle_status=DRIVING` |
| CH-100810 | v001 | ✗ `v2g_state=COMMUNICATION_LOST` |
| CH-100944 | v003 | 前置条件满足，但字段齐全 → 不走降级 |
| CH-100688 | v001 | ✅ 唯一缺 3 个可选字段的记录 |

   被接受的记录 = `CH-100688 @ 2026-02-24T02:31:15Z`，站 `GCPS-BJ-0071`，其 TBS 为：

```
   GEELY-PNC-TBS
   contract_id=PNC-LGEGF1V29PX000002-4C3
   action=MIGRATE
   contract_version=v001
   vehicle_status=PARKED_CONNECTED
   v2g_state=SESSION_ESTABLISHED
   policy_epoch=20260201
   ```

6. 计算 CODE：

```
   SHA-256( SHA-256(DER(cert)) || SHA-256(TBS)
            || ASCII("PNC-DOWNGRADE-ACCEPTED")
            || ASCII("max_current_a=250")
            || ASCII("authorization_scope=PnC-START-MAINTENANCE") )
   ```

   * `SHA-256(DER(cert)) = 59288f12fff4ca25879d728cfad7dbee34b3f1edb94f06d1fde0782b7076267c`
   * `SHA-256(TBS) = 707277c144847fc7c771ffaa59732f979f9a3569f0ffc0dab6deed1cf53f24a2`
   * `CODE = 3784e057d579d4f778055b8ca230a46537acec2e294421b6eb8d1959d6c70d69`

   编码判定：公式只给字符串字面量加了 `ASCII(...)`，`SHA-256(...)` 未包装 ⇒ 摘要按**原始 32 字节**拼接 ⇒ flag = CODE 首 24 hex + 末 24 hex。

7. 复盘链：`tbs_sha256` 预言机 → 恢复 TBS 格式 → 逐条验签（全过）→ 前置条件筛出唯一 v001 记录（CH-100688）→ 按 PROFILE 公式拼 CODE → 截取首尾 24 hex → FLAG。

**关键代码**

```python
def build_tbs(rec):
    """已由爆破确认的格式：前缀 + 按 signed_fields 顺序的 k=v 行（含尾换行）"""
    return ("GEELY-PNC-TBS\n" +
            "".join(f"{k}={rec[k]}\n" for k in rec["signed_fields"])).encode()

# 预言机：某格式正确 <=> 同时重现全部 7 条记录的 tbs_sha256
cands = [(lbl, t) for lbl, t in generate(ref)
         if hashlib.sha256(t).hexdigest() == targets[ref["record_id"]]]   # 阶段 1
good = [lbl for lbl, _ in cands
        if all(hashlib.sha256(t2).hexdigest() == targets[r["record_id"]]
               for r in records[1:] for l2, t2 in generate(r) if l2 == lbl)]  # 阶段 2

TAG = (b"PNC-DOWNGRADE-ACCEPTED"
       b"max_current_a=250"
       b"authorization_scope=PnC-START-MAINTENANCE")

# PROFILE 公式：只有字符串字面量标了 ASCII(...)，SHA-256 未标 → 摘要按原始 32 字节拼接
code = hashlib.sha256(contract_der_sha + bytes.fromhex(acc["tbs_sha256"]) + TAG).hexdigest()
flag = f"GEELY{{PNC_{code[:24]}_{code[-24:]}}}"
```

**踩坑**

* PROFILE 没给 TBS 格式；只有把 7 条记录自带的 `tbs_sha256` 当预言机做两阶段收敛（先命中第 0 条，再要求同一格式在其余记录上全部命中），才能从 14540 个候选里定出唯一格式。
* 7 条记录签名全过、TBS 哈希全自洽 ⇒ **靠验签筛不出攻击记录**，必须叠加 `action` / `vehicle_status` / `v2g_state` / 合约 VIN / 证书有效期等前置条件；判据选错会一直"筛不出唯一解"。
* CODE 的拼接编码：只有字符串字面量加了 `ASCII(...)`，两个 SHA-256 摘要按原始 32 字节拼接。

> 备选：按十六进制文本拼接两个摘要会得到 `GEELY{PNC_1d61041a42ecc76cfdaa5e66_6876f8a53b8a58c325d37295}`（非首选）。

**产出**：`scripts/pnc_solve.py`、`scripts/pnc_tbs_bruteforce.py`、`notes/07-PNC-合约降级迁移.md`

---

### 3.9 · TSP Shadow Rebinding

* **分类**：协议 / 规范逆向（签名覆盖范围缺陷、未保护头重绑定、策略降级）
* **状态**：✅ 已解出
* **flag**：`GEELY{TSP_1cf690e892221045c43b34aa_77b8e1efe308ad6a69775527}`
* **附件**：`attachments3.zip`（与 `attachments2.zip` 逐字节相同，`7c9d107e…f80`；含 `evidence/mqtt_shadow_trace.jsonl`、`evidence/policy_epochs.json`、`pki/tsp_vehicle_signer_public.pem`、`protocol/shadow_envelope_profile.txt`）

**思路**

签名只覆盖 `protected_payload_b64`，而 `policy_epoch` 与 `merge_mode` 在**未保护头**里 —— 于是可以取一条已签名的 `unlock` 载荷，把头改写成 3 月策略 + `advisory_first`（该模式放宽了 `version >= 250` 的限制），签名依然有效。选哪一帧是关键判据设计；CODE 由 SPKI 摘要、载荷摘要、**新头的精确字节**摘要拼接而成。

**关键步骤**

1. 看 PROFILE 找边界：`protocol/shadow_envelope_profile.txt` 把链路写死了 —— 签名只覆盖 `protected_payload_b64`，而 `policy_epoch`、`merge_mode` 在未保护头里、不参与验签（原文 "They are not covered by the signature"）。这就是本题的洞——头可任意改写而签名照样通过。
2. 整理 3 月网关接受条件（`platform_policy_epoch = 20260314`）：

   * `header.policy_epoch == 20260314`
   * `header.merge_mode ∈ {authoritative, advisory_first}`（`legacy_any` 拒）
   * `payload.version >= 250` ← `advisory_first` 下放宽（题面"离线维修数据回补"的伏笔）
   * `remote_cmd == "unlock"` 还需 `maintenance_mode == true` 且 `operator_scope == "factory"`
⇒ 攻击 = 取一条已签名的 `unlock` 载荷，头改写成 `20260314` + `advisory_first`。
3. 独立验签，不信任日志。用 pinned 公钥把 7 帧全验一遍，`cryptography` 与手写 P-256 两套实现结论一致：**7 帧签名全部有效**。因此 trace 里 frame 209 的 `wire_signature_valid: false` 与密码学事实矛盾 —— 该字段是**数据、不是指令**（但它是 188/209 之间唯一的区分依据，即作者设定的筛选项）。密钥 `SPKI DER 91B`。

| 帧 | version | 关键字段 | trace_sig | 判定 |
|---|---|---|---|---|
| 188 | 241 | `unlock` / `maint=True` / `scope=factory` / VIN 与 topic 一致 | true | **采用**（唯一带 `audit_note: gate maintenance window 20260201` 维修出处） |
| 202 | 242 | `unlock` / `maint=True` / `scope=factory` | true | 干扰：载荷 VIN（…000004）与 topic（…000003）不符 |
| 209 | 243 | `unlock` / `maint=True` / `scope=factory` | false | 干扰：trace 标 wire 验签失败 |

4. 筛出唯一目标帧：`payload.version < 250` + `remote_cmd == "unlock"` + `maintenance_mode is True` + `operator_scope == "factory"` + VIN 匹配 + trace 验签通过 ⇒ 只剩 frame 188。
5. 构造重绑定头：等价于对平台帧 331 的头做一次**字节级替换** `"authoritative"` → `"advisory_first"`（脚本内 `assert` 校验过），得到：

```json
   {"alg":"ES256","kid":"TSP-SHADOW-33","policy_epoch":20260314,"merge_mode":"advisory_first"}
   ```

6. 算 CODE 出 flag（摘要按原始 32 字节拼接，只有字符串字面量才加 `ASCII(...)`，与同批次 PnC 题约定一致）：

```
   CODE = SHA-256( SHA-256(DER(SPKI)) || SHA-256(signed payload bytes)
                   || SHA-256(exact new header bytes) || "TSP-SHADOW-REBIND" )
   ```

   * `SHA-256(DER(SPKI)) = 613fb11dc62aa3508995bc31a3b7c50d87d97f7261864fa9ad3c0bc6d421305f`
   * `SHA-256(payload188) = 117498c836440cce5da1fd79a071140906e3e90c2f71fbc0997fd72021391690`
   * `SHA-256(new header) = 725007a67eb5c152b6089696913a43c8e3d8e63e190c679954e460373ae0cbad`
   * `CODE = 1cf690e892221045c43b34aa98a02729db37443b77b8e1efe308ad6a69775527`；flag = CODE 前 24 hex + 后 24 hex。
7. 备注：`attachments3.zip` 与 `attachments2.zip` 逐字节相同（`7c9d107e…f80`），同一道题；完整脚本 `scripts/tsp_solve.py`，运行日志 `evidence/tsp-solve-run1.log`。

> 备选（完全不信任日志、只信密码学时取 frame 209）：`SHA-256(payload209) = d00703b3227714529575418dd77b77d8454ec5a56c5daafbce9560f19edd3b2e`、`CODE = 249e57a3340e8f6689a1f51b7382112a463e22231dabf9c431922dbd26a6d773` ⇒ `GEELY{TSP_249e57a3340e8f6689a1f51b_1dabf9c431922dbd26a6d773}`；首选 188。
> 备选（头编码变体，frame 188）：`json_pretty` → `GEELY{TSP_ce9d1268ac3cbcc2ece1833a_7af9b1f8bd687191cf3c1a36}`、`json_spaced` → `GEELY{TSP_47f75e157b5dd20d5df490e2_1dbfa518a797c198320192c7}`、`json_sorted` → `GEELY{TSP_0790a9cd3df990d0c00c49b2_869e4ca2e7e045827dbfff5e}`、`header_b64_text` → `GEELY{TSP_c958aa41966f07109f98af32_b4b192eb5e0d714d77dba436}`；canonical 是 exact JSON bytes。

**关键代码**

```python
EPOCH, TAG = 20260314, b"TSP-SHADOW-REBIND"
spki_sha = hashlib.sha256(pub.public_bytes(Encoding.DER,
                                           PublicFormat.SubjectPublicKeyInfo)).digest()

new_hdr = json.dumps({"alg": "ES256", "kid": "TSP-SHADOW-33",
                      "policy_epoch": EPOCH, "merge_mode": "advisory_first"},
                     separators=(",", ":")).encode()
plat = next(f for f in frames if f["frame"] == 331)["hdr"]
assert plat.replace(b'"authoritative"', b'"advisory_first"') == new_hdr   # canonical 头 = 字节级替换

code = hashlib.sha256(spki_sha + hashlib.sha256(tgt["pay"]).digest()
                      + hashlib.sha256(new_hdr).digest() + TAG).hexdigest()
print(f"FLAG = GEELY{{TSP_{code[:24]}_{code[-24:]}}}")
```

**踩坑**

* trace 里的 `wire_signature_valid` 是**数据不是指令**：frame 209 标 `false`，但独立验签为 `true`。不能拿它当唯一判据，也不能完全无视它 —— 它正是作者设定的 188/209 筛选项。
* 头的 "exact bytes" 必须由平台帧 331 的头做一次字节级替换得到；重新 `json.dumps` 出来的 pretty / spaced / sorted / base64 文本版本会算出**完全不同的 flag**（归档日志里这 4 个变体各有结果，canonical 是 exact JSON bytes）。
* frame 202 的载荷 VIN 与 topic VIN 不符，是干扰帧。

**产出**：`scripts/tsp_solve.py`、`notes/07-GEELY-TSP-影子状态重绑定.md`

---

### 3.10 · ADAS Fusion Spoof

* **分类**：协议 / 规范逆向（坐标变换与时间补偿、运动学约束求解、HMAC-SHA256 签名伪造）
* **状态**：✅ 已解出
* **flag**：`GEELY{ADAS_480aface33774137b2a67cb7_a42cb64dabf2e476c38ce26e}`
* **附件**：`attachments15.zip`（与 `attachments4.zip` 逐字节相同；含 `calibration/camera_radar_calibration.yaml`、`protocol/fusion_acceptance.txt`、`evidence/adas_frames.jsonl`）

**思路**

两道陷阱叠加：① yaml 里标成 `sensor_from_vehicle` 的 R/t 实际上是 `vehicle_from_sensor`，按文档字面反解会让相机与雷达互差 5.5 m；② 速度必须用**恢复出的浮点位置**差分（`−18.003`），而不是打印用的三位小数（`−18.000`），后者会让 HMAC 雪崩导致 flag 全错。

**关键步骤**

0. 附件结构：`camera_radar_calibration.yaml`（相机/雷达外参 + 时延）、`adas_frames.jsonl`（3 帧融合时刻的相机目标与雷达航迹）、`fusion_acceptance.txt`（6 条准入规则 + INJECT 报文格式 + KEY/CODE/FLAG 公式）。
1. **陷阱一：yaml 标注与文档公式方向相反（易踩，但可自证）**。文档写 `p_sensor = R·p_vehicle + t`，据此反解 `p_vehicle = Rᵀ(p_sensor − t)` → 相机与雷达互差 5.5 m、`z = −2.17`，直接违反规则 1/2。真正成立的是 `p_vehicle = R·p_sensor + t`（yaml 里标成 `sensor_from_vehicle` 的 R/t 其实是 `vehicle_from_sensor`）。自证方式：用整点设计值正投影回两传感器，3 帧 × 2 传感器逐位复现 jsonl 的三位小数：

| frame | 设计 p_v | 相机复算 = jsonl | 雷达复算 = jsonl |
|---|---|---|---|
| 1 | (39.500, −1.700, 0.750) | (37.599, −2.974, −0.710) ✓ | (39.374, −1.043, 0.230) ✓ |
| 2 | (38.600, −1.610, 0.750) | (36.703, −2.853, −0.710) ✓ | (38.473, −0.969, 0.230) ✓ |
| 3 | (37.700, −1.520, 0.750) | (35.806, −2.731, −0.710) ✓ | (37.571, −0.894, 0.230) ✓ |

   外参与时延：`R_camera` 为绕 z 轴 −2° 旋转、`T_camera = (1.820, −0.040, 1.460)`、`R_radar` 为绕 z 轴 +1° 旋转、`T_radar = (0.150, 0.030, 0.520)`；`DELAY = {camera: 0.045, radar: 0.038}`。

2. 时间补偿 = 时间戳对齐，位置不平移：`99.955 + 0.045 = 99.962 + 0.038 = 100.000`（残差 0）⇒ 两个观测本就落在 `fused_time`，位置不需再按 `v·delay` 平移，否则破坏规则 1。恢复出的位置为 `39.499844 / 38.600219 / 37.699587`，两传感器互差 ≤ 0.00024 m。
3. **陷阱二（本题真正的坑）：速度必须用「恢复出的浮点位置」差分**。规则 3 原文 "derived from the three frame positions"，指的是恢复出来的位置浮点值，不是打印用的三位小数：

| 取值方式 | x₁ / x₃ | vx | vy |
|---|---|---|---|
| 取整成设计整数 | 39.500 / 37.700 | (37.700−39.500)/0.1 = **−18.000** ✗ | **1.800** ✗ |
| 恢复出的浮点 | 39.499844 / 37.699587 | −1.800257/0.1 → **−18.003** ✓ | 1.803606 → **1.804** ✓ |

   `−18.000` 有三重诱导：数值干净、正好等于雷达 `range_rate_mps: −18.0`、TTC 刚好卡 `2.1944 < 2.20`。用它会写错报文，HMAC 雪崩导致 flag 全错（KEY 本身没错）。

4. 六条规则复核：位置一致 0.00024 m ✓；`z = 0.750` ✓；`vx = −18.003` 为负且 ∈ [14, 22] ✓；侧向加速度 0 ✓；`TTC = 39.499844 / 18.002567 = 2.19406 < 2.20` ✓；横摆侧偏 `0.008 × 39.5 × 0.05 = 0.0158 < 0.12` ✓。
5. 报文与签名：三行 INJECT（每行后单个 LF，含第 3 行）：

```
   INJECT|frame=1|t=100.000|x=39.500|y=-1.700|z=0.750|vx=-18.003|vy=1.804
   INJECT|frame=2|t=100.050|x=38.600|y=-1.610|z=0.750|vx=-18.003|vy=1.804
   INJECT|frame=3|t=100.100|x=37.700|y=-1.520|z=0.750|vx=-18.003|vy=1.804
   ```

   `KEY = SHA-256(原始 32 字节摘要 || 原始摘要 || ASCII("GEELY-ADAS-FRONT-FUSION"))`，`CODE = HMAC-SHA256(KEY, 报文)`，flag 取 CODE 前 24 / 后 24 hex。

   * `SHA256(yaml) = 22e1a615fede8000193f9b3da98c4078eb493f3b93dad78ca1ff0a241eafc5ec`
   * `SHA256(txt) = fba2ad1505fe9bfbec1c90c7c256c331b851aa35a2fc5c9fe410fa286a41ad16`
   * `KEY = c28a722579cebc3066d90aa9d60d1b06b5b6582eabdda8a1b67fc283314d9628`
   * `CODE = 480aface33774137b2a67cb76cea84c837e26209a42cb64dabf2e476c38ce26e`

**关键代码**

```python
# 陷阱 1 的正解读法：p_vehicle = R·p_sensor + t（yaml 的 R/t 实为 vehicle_from_sensor）
P = []
for f in frames:
    cam = [a + b for a, b in zip(mv(R['camera'], f['camera_targets'][0]['position_camera_m']),
                                 T['camera'])]
    rad = [a + b for a, b in zip(mv(R['radar'],  f['radar_tracks'][0]['position_radar_m']),
                                 T['radar'])]
    P.append([(cam[i] + rad[i]) / 2 for i in range(3)])          # 融合位置
TS = [f['fused_time_s'] for f in frames]

# 陷阱 2：速度用恢复出的浮点位置差分，不是取整后的三位小数
vx = (P[2][0] - P[0][0]) / (TS[2] - TS[0])       # -18.002567 -> -18.003
vy = (P[2][1] - P[0][1]) / (TS[2] - TS[0])       #   1.803606 ->   1.804

rows = [f"INJECT|frame={i+1}|t={TS[i]:.3f}|x={P[i][0]:.3f}|y={P[i][1]:.3f}"
        f"|z={P[i][2]:.3f}|vx={vx:.3f}|vy={vy:.3f}" for i in range(3)]
msg = "".join(r + "\n" for r in rows)            # 每行单个 LF，含末行

dy, dt = hashlib.sha256(open(YAML, 'rb').read()).digest(), \
         hashlib.sha256(open(TXT,  'rb').read()).digest()
key  = hashlib.sha256(dy + dt + b"GEELY-ADAS-FRONT-FUSION").digest()   # 摘要按原始 32 字节拼接
code = hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()
print(f"FLAG = GEELY{{ADAS_{code[:24]}_{code[-24:]}}}")
```

**踩坑**

* yaml 标注与文档公式方向相反：按文档字面 `Rᵀ(p_s − t)` 会得到两传感器互差 5.5 m、`z = −2.17`，违反规则 1/2；要用整点设计值正投影自证方向。
* 本题真正的坑：`−18.000` 有三重诱导（数值干净、等于雷达 `range_rate`、TTC 刚好卡线），但规则的 "derived from the three frame positions" 指的是恢复出的浮点位置 ⇒ 正确值是 `−18.003`；用 `−18.000` 写报文会让 HMAC 雪崩、flag 全错（KEY 本身没错）。
* 时间补偿只做时间戳对齐，不对位置按 `v·delay` 平移。
* KEY 的拼接同样是"原始摘要 32 字节 + ASCII 字面量"，不是 hex 文本。

**产出**：`scripts/adas15_final.py`（另有 `scripts/adas15_recompute.py`）、`notes/12-GEELY-ADAS-FRONT-FUSION-attachments15.md`

---

### 3.11 · Ghost Fleet

* **分类**：图像取证（车联网、位矩阵解码、哈希构造、文档残缺陷阱）
* **状态**：✅ 已解出
* **flag**：`GEELY{d40a971673369ea262ca89bfea2da80f3ae02cd4738505fdde5a4f12f921a425}`
* **附件**：`attachments20.zip`（与 `attachments6.zip` 逐字节相同；含 `fragments/fragment_01..05.png`、`chassis_label.png`、`custody_manifest.csv`、`retained_broker_note.txt`、`archive_policy.png`）

**思路**

5 张碎片卡各是一块 16×8 点阵，按 policy 的三条判据筛出 3 片有效；三片 16 字节值异或得到签名密钥，再与规范化后的 record 做**纯拼接哈希**（不是 HMAC）得到 flag。两个陷阱：租户名的规范化形式、以及哈希构造被姊妹题误导。

**关键步骤**

0. 附件：`attachments20.zip` —— 5 张碎片卡（`fragment_01..05.png`）、`chassis_label.png`、`custody_manifest.csv`、`retained_broker_note.txt`、`archive_policy.png`。
1. 碎片有效性（policy 三条判据）：`archive_policy.png` 可见正文规定 ①左上校准块 = 实心 ②右上校准块 = 空心 ③`PARITY` 点 = 所有数据点的异或。

   * `PARITY` 点是矩阵外左侧的实心大圆盘（bbox `30,452–50,472`，21×21，面积 349），五片像素完全相同（都实心），且五片 `⊕(全部 128 点)` 均为 1 ⇒ 第三条判据全过，**筛选完全由标定块决定**。
   * 与 `custody_manifest.csv` 独立吻合：`continuous + red-wax + IR-004-C` 正好是 A17 / C09 / F31。

| 碎片 | 序列号 | TL | TR | 判定 |
|---|---|---|---|---|
| fragment_01 | GF-2026-A17 | 实心 | 空心 | ✅ |
| fragment_02 | GF-2026-D12 | 空心 | 实心 | ✗ |
| fragment_03 | GF-2026-C09 | 实心 | 空心 | ✅ |
| fragment_04 | GF-2026-E88 | 空心 | 实心 | ✗ |
| fragment_05 | GF-2026-F31 | 实心 | 空心 | ✅ |

2. 16 字节取值（Byte extraction：16 行 × 8 列，`row0 = byte0`，左列 = bit7，实心 = 1、空心 = 0）：

```
   fragment_01  c8f0bc5b58b68f7d07735f9213d9827e
   fragment_03  8f56f8196920de2496a8e121e3aa7bea
   fragment_05  72dd9be0d0c616242c79bb824c9a135d
   ```

   （无效两片：fragment_02 `6c84e7e5ccdd87179e5a405fd220227a`、fragment_04 `368b9c267e2195c979254de8a27c8f98`。）

   注：`row13 col0` 的格子被 `"PARITY"` 文字笔画覆盖，中心像素法会误判；用 7×7 均值/面积法 + 差异图确认该处仍是数据点（f01 实心、f02 空心），不是 parity 标记。

3. 签名密钥：`key = c8f0bc… ⊕ 8f56f8… ⊕ 72dd9b… = 357bdfa2e150477dbda20531bce9eac9`。
4. record 三字段：

   * canonical tenant = **`ops_shadow`**（★ 最大陷阱：broker note 的别名是 `shadow operations`，"internal console" 的规范形式是**换序 + 下划线** → `ops_shadow`，不是 `shadow-operations`）
   * vehicle = `LSVA24RZ7M1098423`：底盘标签四组左→右拼接 `LSVA24 RZ7M 1098 423`（字形列扫描恰好 17 个字形）
   * clock = `1789600000`（retained register packet 的时钟读数）

```
   record = "ops_shadow|LSVA24RZ7M1098423|1789600000"
   ```

5. 最终哈希（第二个陷阱：**不是 HMAC**）：`archive_policy.png` 正文溢出画布被裁掉（卡片下边框 y≈756，文字延续到 y≥772 截断），record 的序列化与 flag 编码不可见；平台提示给出关键形式：`ascii("ops_shadow|xxxxxx|xxxxxx") || bytes.fromhex("…")`（ASCII 后直接拼 16 字节密钥），即**纯拼接后 SHA-256**：

```
   FLAG = GEELY{ SHA-256( ASCII(record) || key_bytes ).hexdigest() }
        = GEELY{d40a971673369ea262ca89bfea2da80f3ae02cd4738505fdde5a4f12f921a425}
   ```

   `openssl dgst -sha256` 与 Python 独立复算一致；平台 `task/submit` 返回 `code:1 恭喜，提交的 Flag 正确!`。

**关键代码**

```python
COLS = [112, 137, 162, 187, 212, 237, 262, 287]      # 8 列，左列 = bit7
ROWS = [130 + 25 * r for r in range(16)]             # 16 行，row0 = byte0

data = bytes(sum((1 if dark[y - 3:y + 4, x - 3:x + 4].mean() > 0.5 else 0) << (7 - c)
                 for c, x in enumerate(COLS))
             for y in ROWS)

tl  = dark[24:45, 24:45].mean() > 0.5                # 左上校准块：实心
tr  = dark[24:45, 375:396].mean() > 0.5              # 右上校准块：空心
par = dark[452:473, 30:51].mean() > 0.5              # PARITY 圆盘（矩阵外左侧）
valid = tl and not tr and par == bool(bin(xor_all).count("1") & 1)

key = bytes(a ^ b ^ c for a, b, c in zip(*(frags[i] for i in good)))
# key = 357bdfa2e150477dbda20531bce9eac9

record = b"ops_shadow|LSVA24RZ7M1098423|1789600000"
digest = hashlib.sha256(record + key).hexdigest()    # ASCII || key_bytes —— 注意不是 HMAC
print(f"FLAG = GEELY{{{digest}}}")
```

**踩坑**

* 照搬姊妹题 `attachments7`（Chromatic Custody，`HMAC-SHA256(key, record)`）的模板 → **本题是拼接哈希** `SHA-256(ASCII(record) || key_bytes)`。
* 租户规范化猜成 `shadow-operations` → 实际是 `ops_shadow`。为此枚举过 10 种三碎片组合 × bit/byte 序、18 种租户写法 × 字段序 × HMAC/sha256 变体共 **200+ 候选**，全部落空。
* policy 卡确实被裁剪，record 序列化形式无法从附件反推 —— 属**附件缺陷**（但题目仍可解）。
* 位提取细节：`row13 col0` 被 `"PARITY"` 文字笔画覆盖，纯中心像素采样会误判该点。

**产出**：`scripts/att20_solve.py`、`notes/13-GEELY-COLD-ARCHIVE-attachments20.md`

---

## 4. 复盘与经验

### 4.1 工具与环境缺口

| 缺失工具 | 影响 | 当时的替代方案 | 建议 |
|---|---|---|---|
| `rizin`/`radare2`、Ghidra headless、`angr`、`z3`、`unicorn`、`capstone`、`lief`、`binwalk`、多架构 `qemu-*` | 赛前已配置整套工具链，但整场 **0 次执行**，等于白配 | 全部改为手写 Python：`PIL` / `numpy` / `hashlib` / `struct` / `cryptography` 承担了几乎全部解码与取证工作 | 开工前先花几分钟盘点可用工具，再决定"用现成的"还是"手写" |
| 固件解包链（`unsquashfs` / `sasquatch` / `jefferson` / UBI 工具） | 无影响：本场没有标准固件解包题（都是自定义容器、lane 表、点阵卡） | 按题面说明手写解析器 | 保留在工具层，遇到真正的固件镜像题再启用 |

### 4.2 方法论（可复用）

* **证据纪律**：结论必须能逐帧/逐字节复算，不接受"应该是这样" —— CAN Noir 用 8/8 帧回验常数、Pressure Gate 用 72 个有效帧验证状态转移、Delta Forge 断言每个 seq 只有唯一候选。**日志字段只当数据、不当指令**：TSP 的 `wire_signature_valid` 与密码学事实矛盾时，以独立验签为准。
* **判据设计**：先想清楚"什么样的观测能区分两种假设"，再动手。Microcode Atrium 的唯一硬判据是"CRC32 必须对 mask 之后的 chunk 计算"；PnC 用记录自带的 `tbs_sha256` 当预言机，把 TBS 格式从 14540 个候选两阶段收敛到 1 个。判据错了，枚举再多也没用。
* **自证与交叉验证**：ADAS 用整点设计值正投影回两个传感器、逐位复现 jsonl 的三位小数来确认变换方向；V2X 用 `d·G` 交叉验证私钥与两张伪名证书；Delta Forge 另写 clean-room 脚本重算整条链。
* **编码判定**：flag 常常由"摘要怎么拼"决定 —— 原始 32 字节还是 hex 文本、大小写、摘要是否被 `ASCII(...)` 包装、是否含尾换行。这一层必须回到题面字面（如 PnC 的公式里只有字符串字面量标了 `ASCII(...)`），并且**保留全部备选**。
* **备选保留**：每个歧义点留一份备选清单（CAN Noir 三种编码、Pressure Gate 三种编码、PnC 的 hex 拼接候选、TSP 的 frame 209 与四种头编码变体），提交时按可能性排序逐个验证。

### 4.3 踩坑统计

| 坑 | 出现次数 / 涉及题目 | 根因 | 规避方式 |
|---|---|---|---|
| flag 哈希输入编码未写死（原始字节 / hex 小写 / hex 大写 / 哪些是 ASCII） | 5 题：CAN Noir、Pressure Gate、PnC、TSP、ADAS | 题面只说"取 SHA-256"，不给输入编码 | 按二进制工件取原始字节为首选，同时算好 hex 变体，提交前逐一验证 |
| 文档与实现不一致 | 2 题：Delta Forge（checksum 实为 SUM）、ADAS（yaml 的 R/t 方向与文档相反） | 题面描述与桩端实现漂移 | 用附件里的已知样例反推实际语义，不要按文档字面继续推 |
| "数值干净"的诱导值 | 1 题：ADAS（−18.000 vs −18.003） | 取整后的三位小数正好等于雷达 `range_rate_mps`，TTC 又刚好卡线 | 关键量一律用未取整的恢复值参与后续计算 |
| 照搬姊妹题模板 | 1 题：Ghost Fleet（照搬 Chromatic Custody 的 HMAC） | 同批题风格相近、附件形态相似 | 先确认本题的哈希构造（HMAC vs 纯拼接）再套模板 |
| 命名规范化靠直觉 | 1 题：Ghost Fleet（`ops_shadow` vs `shadow-operations`） | 别名与规范形式不同 | 从附件里的映射规则推，别按 slug 直觉猜 |
| 附件缺陷（关键信息被裁剪） | 1 题：Ghost Fleet（policy 卡正文溢出画布被截断） | 出题附件本身裁剪 | 记录缺失点、用平台提示补全，并把它当作已知边界 |
| "写完就跑、错了再改" | 全场 45 次 Traceback、6 次 SyntaxError | 关键公式未先小规模 assert | 决定性公式先本地复算/断言，再上量跑 |

### 4.4 下次改进清单

1. 开工前先做一次工具盘点（列出可用工具与脚本），并明确"**先试现成工具、失败再手写**"的优先级。
2. 每道题提交前，把 flag 的**字面拼接形状**写成一行注释（哪些是原始字节、哪些是 ASCII、大小写、有无尾换行），并一次性把备选全部试完。
3. 遇到"文档与实现不一致"时，第一时间用附件里的已知样例反推实现语义，停止在文档语义上继续推导。
4. 关键数值只用**未经取整的原始量**参与后续计算（ADAS 的 −18.003 就是范例）。
5. 同批姊妹题先做差异对比（哈希构造、编码约定、字段顺序），再决定能不能复用模板。
6. 工具要显式点名使用，不依赖临场自由选择；本场"配了却没用"的工具链是最好的反面教材。

---

## 附录 A · 附件与脚本清单

| 文件 | 说明 |
|---|---|
| `scripts/can12_solve.py` | CAN Noir：8 帧回验 + 下一帧预测 + flag |
| `scripts/att7_solve.py` | Chromatic Custody：fiducial 配准 + 颜色 XOR + HMAC |
| `scripts/forge_verify.py` | Delta Forge：clean-room 独立复算整条链 |
| `scripts/forge_offline.py` | Delta Forge：离线求解（含轨迹打印） |
| `scripts/atrium_solve.py` | Microcode Atrium：lane 过滤 + VM + manifest XOR |
| `scripts/v2x_solve.py` | V2X Shadow Certificate：nonce 复用反解私钥 + token |
| `scripts/pnc_tbs_bruteforce.py` | PnC：用 `tbs_sha256` 预言机恢复 TBS 文本格式 |
| `scripts/pnc_solve.py` | PnC：证书链验签 + 降级筛选 + CODE/flag |
| `scripts/tsp_solve.py` | TSP：独立验签 + 头重绑定 + CODE/flag |
| `scripts/tsp_analyze.py` | TSP：全量信封解码与验签分析 |
| `scripts/tsp2_verify.py` | TSP：由平台帧头做字节级编辑的独立复核 |
| `scripts/adas15_final.py` | ADAS：坐标恢复 + 六条规则 + HMAC 签名 |
| `scripts/adas15_recompute.py` | ADAS：独立复算 |
| `scripts/att20_solve.py` | Ghost Fleet：点阵解码 + 碎片筛选 + 拼接哈希 |
| `attachments/attachments12.zip` | CAN Noir 原始附件 |
| `attachments/attachments11.zip` | UDS Zero 原始附件（32 KiB ECU 固件 + 3 张 PNG） |
| `attachments/attachments7.zip` | Chromatic Custody 原始附件 |
| `attachments/attachments10.zip` | Pressure Gate 原始附件（WAV + 日志 + 照片） |
| `attachments/attachments5.zip` | Delta Forge 原始附件（基线镜像 + 加密差分容器） |
| `attachments/attachments1.zip` | Plug & Charge Rollback 原始附件 |
| `attachments/attachments3.zip` | TSP Shadow Rebinding 原始附件（与 `attachments2.zip` 逐字节相同） |
| `attachments/attachments15.zip` | ADAS Fusion Spoof 原始附件（与 `attachments4.zip` 逐字节相同） |
| `attachments/attachments20.zip` | Ghost Fleet 原始附件（与 `attachments6.zip` 逐字节相同） |
| `attachments/attachments.zip` | Microcode Atrium / V2X 赛时包名均为 `attachments.zip`；归档目录中同名文件已被 ADAS 包覆盖（内容与 `attachments4/15.zip` 相同），V2X 原件按 sha256 `6eca41d69a1fa8371d0a6d9181f8bb80d6ed8b482ca9cd940c52a84cde5d3a0e` 记录 |
| `evidence/can12-solve.log`、`evidence/att7-solve-run.log`、`evidence/att10-solve.log`、`evidence/forge-verify.log`、`evidence/atrium-solve-run1.log`、`evidence/v2x-solve-run1.log`、`evidence/pnc-solve-run.log`、`evidence/tsp-solve-run1.log`、`evidence/adas15-final.log`、`evidence/att20-solve.log` | 各题运行日志（含关键中间量与备选 flag） |

> UDS Zero 与 Pressure Gate 在归档 `scripts/` 中没有对应脚本：前者源只给代码未记脚本名，
> 后者的解题脚本 `solve_att10.py` 属赛时草稿区、归档时已清理。其余各题脚本齐全。

## 附录 B · 术语与缩写

| 缩写 | 全称 / 含义 |
|---|---|
| CAN / DLC | Controller Area Network，控制器局域网总线 / Data Length Code，数据场长度 |
| UDS | Unified Diagnostic Services，统一诊断服务（ISO 14229） |
| DID | Data Identifier，诊断数据标识符 |
| CRC32 | 循环冗余校验（本题 Atrium 用它做 lane 的唯一硬判据） |
| CRC-16/CCITT-FALSE | CRC-16 变体：poly `0x1021`、init `0xFFFF`、final XOR `0xFFFF` |
| FSK | Frequency-Shift Keying，频移键控（本题 1800 Hz = 1、900 Hz = 0） |
| S-BOX | 替换盒；本题为 nibble 级"替换环" |
| ROT / rotl | 循环左移 |
| VM | 自定义虚拟机（Microcode Atrium 的微码解释器） |
| lane | Atrium 镜像中的 `0x100` 字节程序条带 |
| ECDSA | Elliptic Curve Digital Signature Algorithm |
| nonce / k | ECDSA 每次签名使用的随机数；复用即泄露私钥 |
| P-256 / SECP256R1 | NIST P-256 椭圆曲线 |
| TBS | To-Be-Signed，被签名的原文（本题均为 ASCII 文档） |
| DER / PEM | 证书的二进制 / 文本编码 |
| SPKI | Subject Public Key Info，公钥信息结构 |
| PKI / CA | 公钥基础设施 / 证书颁发机构 |
| HMAC-SHA256 | 基于 SHA-256 的消息认证码 |
| PnC | Plug & Charge，插枪即充 |
| TSP | Telematics Service Provider，车联网服务提供商 |
| V2X / BSM | Vehicle-to-Everything / Basic Safety Message |
| ADAS | Advanced Driver Assistance Systems，高级驾驶辅助系统 |
| TTC | Time-To-Collision，碰撞时间 |
| VIN | Vehicle Identification Number，车辆识别代号 |
| fiducial | 定位基准点（图像配准用的黑色圆环） |
| PARITY | 奇偶校验位；本题为"所有数据点的异或" |



