# GEELY CAN — 无钥匙进入滚动令牌（attachments12.zip）

- **flag（首选）**: `GEELY{CAN_8a663785962c9a67_8c45eed5b4fd503c}`
- 附件: `firmware/attachments12.zip` → `attachments/maintenance_photos/{keyless_pcb,decode_card}.png` + `can_signal_notes.txt` + `can_unlock_trace.log` + `field_service_extract.txt`
- 解题脚本: `scripts/can12_solve.py`
- 证据: `evidence/can12-solve.log`、`evidence/can12-photo-decode.log`

## 1. 总线格式（can_signal_notes.txt）

`can1 18FF50A5#00407D62BB96F88A`，DLC=8：

| byte | 含义 |
|---|---|
| 0-1 | 16 位计数器，大端（0x0040…0x0047） |
| 2 | 固定相位标记 `0x7D` |
| 3-6 | 滚动令牌，大端 |
| 7 | byte0..6 的 XOR（逐帧校验通过） |

## 2. 变换（field_service_extract.txt）

```
X = K xor (N * S)
X = rotl(X, R)
X = X xor M
T = X xor (X >> 13)
```

常数必须从返修照片读：`decode_card.png` 是色卡，`keyless_pcb.png` 给出 R1..R8 两个
色块 + U1 两行数字 + 旋转级三角形数量。逐块取样 RGB 与色卡精确配色：

| 元件 | 左块 | 右块 | 位 |
|---|---|---|---|
| R1 | 淡黄(4) | 白(9) | 49 |
| R2 | peru(A) | 藏青(F) | AF |
| R3 | 橙(3) | 红(2) | 32 |
| R4 | 品红(C) | 紫(7) | C7 |
| R5 | 绿(5) | peru(A) | 5A |
| R6 | 棕(1) | 紫(7) | 17 |
| R7 | 品红(C) | 黑(0) | C0 |
| R8 | 青(D) | 橄榄(E) | DE |

- `K = 0x49AF32C7`（R1..R4）
- `M = 0x5A17C0DE`（R5..R8）
- `S = 0x9E3779B1` —— U1 两行 `9E37` / `79B1` 是**一个 32 位常数**（黄金比例常数），不是两个 16 位值。
- `R = 7` —— ROTATION STAGE 的 7 个二极管三角形；扩散固定 `X ^ (X>>13)`。

## 3. 校验

用上述常数对 8 帧逐帧重算，令牌与线上字节**完全一致**（8/8 OK，且 byte7 校验和成立），
因此 K/S/M/R 读取唯一确定，不是拟合。

## 4. 下一帧（未被捕获的接受帧）

计数器递增为 1 ⇒ `N = 0x0048`：

```
T = 0x409043D7
payload = 00 48 7D 40 90 43 D7 71
candump = can1 18FF50A5#00487D409043D771
```

## 5. flag

按题面“对下一帧完整数据取 SHA-256，取前 16/后 16 位十六进制”：

```
SHA-256(00 48 7D 40 90 43 D7 71) =
8a663785962c9a6724c9a31ac5e5f93bbe4510a16b0d7efc8c45eed5b4fd503c

FLAG = GEELY{CAN_8a663785962c9a67_8c45eed5b4fd503c}
```

同一算法下其他编码方式的备选（题面未明确哈希输入的字节/文本形式，按“二进制工件用原始
字节”的既有出题习惯取原始 8 字节为首选）：

| 哈希输入 | sha256 | flag |
|---|---|---|
| 原始 8 字节（首选） | `8a663785962c9a6724c9a31ac5e5f93bbe4510a16b0d7efc8c45eed5b4fd503c` | `GEELY{CAN_8a663785962c9a67_8c45eed5b4fd503c}` |
| 16 位十六进制小写字符串 | `c99276b6468e2122ee8776fd9b9524945befa1f7fb20611b41060ddd01210ae2` | `GEELY{CAN_c99276b6468e2122_41060ddd01210ae2}` |
| 16 位十六进制大写字符串 | `c5007c61406904bff895b0b55e5d48c32ec010ff03bc7f79f65dc5131e39daea` | `GEELY{CAN_c5007c61406904bf_f65dc5131e39daea}` |
| 仅 4 字节令牌原始字节 | `964372d2f1397c891f473105910764cd981cf150a293736339de91c494296ca6` | `GEELY{CAN_964372d2f1397c89_39de91c494296ca6}` |

## 复现

```bash
python3 scripts/can12_solve.py
```
