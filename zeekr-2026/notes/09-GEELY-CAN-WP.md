# Writeup — GEELY CAN 无钥匙进入滚动令牌（attachments12.zip）

> 赛事：2026 极氪全球挑战赛线上赛 · 附件题
> 附件：`firmware/attachments12.zip` sha256 `df80b07c2fe3023dafeacfaae801910a28a07e40896f881c0fbedb7f3a92b5da`
> flag：`GEELY{CAN_8a663785962c9a67_8c45eed5b4fd503c}`

---

## 0. 一句话思路

返修擦掉了密钥配置区，但**算法结构**留在了 `field_service_extract.txt`，**全部数值常数**留在了两张照片里（PCB 电阻色块 → `K/M`、U1 丝印 → `S`、旋转级三角形数 → `R`）。用 8 帧已接受的 CAN 记录把常数**逐一验证到逐位一致**，再用同一个变换推进到第 9 帧（计数器 0x0048），最后按题面取下一帧完整数据的 SHA-256 前/后 16 位。

---

## 1. 附件与格式

```
attachments/
├── can_signal_notes.txt          总线抓包说明（帧格式）
├── can_unlock_trace.log          8 帧已接受的解锁帧
├── field_service_extract.txt     算法结构（常数被抹掉）
└── maintenance_photos/
    ├── keyless_pcb.png           返修照片：R1..R8 色块 + U1 丝印 + 旋转级
    └── decode_card.png           厂商色卡：颜色 → nibble
```

总线记录（candump 风格，仲裁 ID `18FF50A5`，DLC=8）：

```
(1789601000.000000) can1 18FF50A5#00407D62BB96F88A
(1789601003.430000) can1 18FF50A5#00417D8778600EAD
(1789601006.886000) can1 18FF50A5#00427DAB242B148F
(1789601010.368000) can1 18FF50A5#00437DCFE475DEBE
(1789601013.876000) can1 18FF50A5#00447DD3A1BC40B7
(1789601017.410000) can1 18FF50A5#00457DF46F5AEF16
(1789601020.970000) can1 18FF50A5#00467D182D513768
(1789601024.556000) can1 18FF50A5#00477D3CEF4FFF59
```

`can_signal_notes.txt` 给出数据场布局：

| byte | 含义 |
|---|---|
| 0-1 | 16 位计数器，**大端**（0x0040 … 0x0047） |
| 2 | 固定相位标记 `0x7D` |
| 3-6 | 滚动令牌，**大端** |
| 7 | byte0..byte6 的 XOR |

8 帧的 byte7 异或校验全部成立，相位标记恒为 `0x7D`，计数器严格 +1 ⇒ 下一帧计数器 `0x0048`。

`field_service_extract.txt` 给出变换结构（数值全被抹掉，要从照片读）：

```
K = R1..R4 nibble pairs
S = value printed in U1
M = R5..R8 nibble pairs
R = number of diode triangles
N = 16-bit counter, big-endian

X = K xor (N * S)
X = rotate_left(X, R)
X = X xor M
T = X xor (X >> 13)
```

---

## 2. 从照片恢复常数

### 2.1 色卡 → nibble

对 `decode_card.png` 取样得到精确调色板（与 PCB 上的色块 RGB **逐字节相同**，因此不存在近似判色问题）：

| nibble | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|---|
| RGB | `000000` | `7B4A12` | `DD2222` | `FF8800` | `FFE680` | `1C8A3A` | `2060D0` | `8A4ED0` |

| nibble | 8 | 9 | A | B | C | D | E | F |
|---|---|---|---|---|---|---|---|---|
| RGB | `8D8D8D` | `FFFFFF` | `C87533` | `D8D8D8` | `E040C0` | `00B7D0` | `808000` | `002080` |

### 2.2 PCB 色块 → K / M

程序化连通域取样（`evidence/can12-photo-decode.log`），每个电阻两个色块、左块为高 nibble：

| 元件 | 左块 | 右块 | nibble pair |
|---|---|---|---|
| R1 | 淡黄(4) | 白(9) | `49` |
| R2 | peru(A) | 藏青(F) | `AF` |
| R3 | 橙(3) | 红(2) | `32` |
| R4 | 品红(C) | 紫(7) | `C7` |
| R5 | 绿(5) | peru(A) | `5A` |
| R6 | 棕(1) | 紫(7) | `17` |
| R7 | 品红(C) | 黑(0) | `C0` |
| R8 | 青(D) | 橄榄(E) | `DE` |

```
K = 0x49AF32C7      (R1..R4)
M = 0x5A17C0DE      (R5..R8)
```

> 注意：R2/R5 的 `C87533` 是色卡里的 **A**（peru），不是橙 `3`；同理 R8 的 `808000` 是 **E** 而不是黄 `4`。这两个是最容易看错的位。

### 2.3 U1 丝印 → S（本题最大的坑）

照片上 U1 是一个黑盒，里面两行：

```
U1   9E37
     79B1
```

按字面读会得到两个 16 位数（`S=0x9E37` 或 `0x79B1`），**两种都验不过 8 帧**。
正确读法是：这是**一个 32 位常数** `0x9E3779B1` —— 也就是黄金比例常数 `⌊2³²/φ⌋`，哈希算法里极常见的魔数。拼起来后 8 帧立刻全中。

```
S = 0x9E3779B1
```

### 2.4 旋转级 → R

`ROTATION STAGE` 一行画了 **7** 个二极管三角形，对应 `rotate_left(X, 7)`：

```
R = 7
```

（扩散固定为 `X ^ (X >> 13)`，不需要从照片读。）

---

## 3. 8 帧回验（常数唯一确定）

按结构实现变换：

```python
MASK = 0xFFFFFFFF
def rol(x, r): return ((x << r) | (x >> (32 - r))) & MASK

def token(n):
    x = K ^ ((n * S) & MASK)   # K=0x49AF32C7 S=0x9E3779B1
    x = rol(x, R)              # R=7
    x ^= M                     # M=0x5A17C0DE
    return (x ^ (x >> 13)) & MASK
```

| 计数器 N | 线上令牌 | 重算令牌 | 结果 |
|---|---|---|---|
| 0x0040 | `62BB96F8` | `62BB96F8` | OK |
| 0x0041 | `8778600E` | `8778600E` | OK |
| 0x0042 | `AB242B14` | `AB242B14` | OK |
| 0x0043 | `CFE475DE` | `CFE475DE` | OK |
| 0x0044 | `D3A1BC40` | `D3A1BC40` | OK |
| 0x0045 | `F46F5AEF` | `F46F5AEF` | OK |
| 0x0046 | `182D5137` | `182D5137` | OK |
| 0x0047 | `3CEF4FFF` | `3CEF4FFF` | OK |

**8/8 逐位一致**，且每次 byte7 异或校验成立 ⇒ `K/S/M/R` 的读取是唯一解，不是拟合。

关键：因为 `S` 一旦读成 16 位（`9E37`/`79B1`）或 `R` 读错（三角形数），8 帧里任何一帧都对不上，所以这个回验同时也**反向确认了色块解码和 nibble 顺序**。

---

## 4. 预测第 9 帧

计数器严格递增，被擦掉的下一帧是 `N = 0x0048`：

```
X = 0x49AF32C7 ^ (0x0048 * 0x9E3779B1)   # mod 2^32
  = ...
T = 0x409043D7
```

按布局拼数据场（byte7 = byte0..6 异或 = `71`）：

```
payload = 00 48 7D 40 90 43 D7 71
candump = can1 18FF50A5#00487D409043D771
```

> 附带发现：时间戳差值为 3.430 / 3.456 / 3.482 / 3.508 / 3.534 / 3.560 / 3.586（每帧 +0.026），
> 若需要整行，下一行时间戳应为 `1789601028.168000`。题面只要求“完整数据”，flag 不涉及时间戳。

---

## 5. flag

题面：`GEELY{CAN_<sha256前16位>_<sha256后16位>}`。对下一帧完整数据场（8 字节）取 SHA-256：

```
SHA-256(00 48 7D 40 90 43 D7 71)
= 8a663785962c9a6724c9a31ac5e5f93bbe4510a16b0d7efc8c45eed5b4fd503c
```

```
FLAG = GEELY{CAN_8a663785962c9a67_8c45eed5b4fd503c}
```

题面未写死哈希输入的编码形式，按“二进制工件取原始字节”的既有出题习惯选原始 8 字节为首选；
同一令牌/同一数据场的其他编码结果（备用提交）：

| 哈希输入 | SHA-256 | flag |
|---|---|---|
| 原始 8 字节（首选） | `8a663785962c9a67…8c45eed5b4fd503c` | `GEELY{CAN_8a663785962c9a67_8c45eed5b4fd503c}` |
| 十六进制小写字符串 | `c99276b6468e2122…41060ddd01210ae2` | `GEELY{CAN_c99276b6468e2122_41060ddd01210ae2}` |
| 十六进制大写字符串 | `c5007c61406904bf…f65dc5131e39daea` | `GEELY{CAN_c5007c61406904bf_f65dc5131e39daea}` |
| 仅 4 字节滚动令牌原始字节 | `964372d2f1397c89…39de91c494296ca6` | `GEELY{CAN_964372d2f1397c89_39de91c494296ca6}` |

---

## 6. 复现

```bash
cd ~/ctf-2026
python3 scripts/can12_solve.py          # 8 帧校验 + 预测下一帧 + 输出 flag
```

证据文件：

- `evidence/can12-solve.log` — 8 帧逐帧复现输出
- `evidence/can12-photo-decode.log` — 照片色块 → nibble 的程序化解码

---

## 7. 完整脚本

```python
#!/usr/bin/env python3
"""GEELY CAN keyless-entry rolling token (attachments12.zip)"""
import hashlib, re, sys, functools

K = 0x49AF32C7      # R1..R4 pads
S = 0x9E3779B1      # U1 "9E37"/"79B1" = 32-bit golden-ratio constant
M = 0x5A17C0DE      # R5..R8 pads
R = 7               # 7 diode triangles
PHASE = 0x7D
MASK = 0xFFFFFFFF

def rol(x, r):
    return ((x << r) | (x >> (32 - r))) & MASK

def token(n):
    x = K ^ ((n * S) & MASK)
    x = rol(x, R)
    x ^= M
    return (x ^ (x >> 13)) & MASK

def frame(n):
    body = bytes([(n >> 8) & 0xFF, n & 0xFF, PHASE]) + token(n).to_bytes(4, "big")
    return body + bytes([functools.reduce(lambda a, b: a ^ b, body)])

frames = [bytes.fromhex(m.group(1)) for m in
          (re.search(r"18FF50A5#([0-9A-Fa-f]{16})", l)
           for l in open("work/att12/attachments/can_unlock_trace.log")) if m]

assert all(token(int.from_bytes(f[:2], "big")) == int.from_bytes(f[3:7], "big")
           for f in frames)                       # 8/8 OK

nxt = int.from_bytes(frames[-1][:2], "big") + 1
payload = frame(nxt)
print("next payload:", payload.hex().upper())
h = hashlib.sha256(payload).hexdigest()
print(f"FLAG = GEELY{{CAN_{h[:16]}_{h[-16:]}}}")
```

---

## 8. 踩坑清单

1. **U1 两行是一个 32 位数**，不是两个 16 位候选值 —— 这是本题唯一“照片谜题”之外的设计陷阱。
2. **peru(A) vs 橙(3)**、**橄榄(E) vs 黄(4)** 容易混；必须用色卡 RGB 精确匹配。
3. nibble 顺序按“左块 = 高 nibble”，靠 8 帧回验可自证。
4. 令牌/计数器都是大端；byte7 异或校验可用于过滤“拒绝帧”（本题 8 帧全接受）。
5. 时间戳等差递增只是生成器习惯，不要把它塞进哈希。
