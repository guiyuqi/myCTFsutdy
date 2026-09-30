# GEELY FRONT ADAS FUSION ACCEPTANCE / BUILD 8.7.2（attachments15.zip）

- **flag（平台已确认）**: `GEELY{ADAS_480aface33774137b2a67cb7_a42cb64dabf2e476c38ce26e}`
- **附件**: `firmware/attachments15.zip`
  - sha256 `48998e83bb9b394c57cbd2a15caae73f97b0665bc65f0f76dd877d952708c705`
  - 与 `attachments.zip`、`attachments4.zip` **逐字节相同**（md5 `d30c5fc614e8574866efd8a2aaa71017`）
- **确认解脚本**: `scripts/adas15_final.py`
- **证据**: `evidence/adas15-final.log`
- **候选全表（复盘用）**: `evidence/adas15-candidates.txt`

> 用户题面里的 `attachments7.zip` 是**模板残留**：Chromatic Custody 那题
> （`session-7e359773`）的 prompt 里逐字也是同一句「题目环境：attachments7.zip」。
> `firmware/attachments7.zip` 装的其实是 Chromatic Custody，那题已解并已被平台接受
> （`notes/11`，`GEELY{80e4bf16…}`）。本题数据就是 `attachments15.zip`。

---

## 真正的陷阱：速度必须由「恢复出来的位置」反推，而不是取整后的设计整数

前两轮（`notes/08`、`session-386fe245`）都在这里翻车。题面规则 3 原文是：

> 3. relative longitudinal velocity **derived from the three frame positions** is
>    negative and has magnitude in [14.0, 22.0] m/s;

"the three frame positions" = **恢复出来的车体系位置**（浮点），不是把浮点四舍五入到
打印用三位小数之后的值。这两个值肉眼看都是 `(39.500, −1.700)`，但差分完全不同：

| 取值方式 | x₁ / x₃ | vx | vy |
|---|---|---|---|
| 取整后的设计整数 | 39.500 / 37.700 | `(37.700−39.500)/0.1 = −18.000` ✗ | 1.800 ✗ |
| **恢复出的浮点（正确）** | 39.499844 / 37.699587 | `−1.800257/0.1 = −18.002567 → −18.003` ✓ | `1.803606 → 1.804` ✓ |

`−18.000` 看起来很"干净"、还正好等于雷达的 `range_rate_mps: −18.0`、TTC 也刚好卡在
`2.1944 < 2.20` —— 这三个"设计感"全是**诱导**。只要照规则 3 的字面从位置差分，就是 `−18.003`。
把 `−18.000` 当答案，HMAC 的输入字节就错了，flag 必然全错（HMAC 雪崩）。

## 另一个陷阱（这个踩对了）：yaml 的 `sensor_from_vehicle` 名字与文档公式方向相反

文档写 `p_sensor = R·p_vehicle + t` ⇒ 反解 `p_vehicle = Rᵀ(p_sensor − t)`。**照文档算是错的**：
相机与雷达互差 5.5 m、z 落到 −2.17（直接违反规则 1/2）。

真正成立的是 **`p_vehicle = R·p_sensor + t`**（yaml 里被标成 `sensor_from_vehicle` 的 R/t
实际是 vehicle_from_sensor）。逐位验证：用设计整点正投影 `Rᵀ(p_v − m)` 回两传感器：

| frame | 设计 p_v | 相机复算 = jsonl | 雷达复算 = jsonl |
|---|---|---|---|
| 1 | (39.500, −1.700, 0.750) | (37.599, −2.974, −0.710) ✓ | (39.374, −1.043, 0.230) ✓ |
| 2 | (38.600, −1.610, 0.750) | (36.703, −2.853, −0.710) ✓ | (38.473, −0.969, 0.230) ✓ |
| 3 | (37.700, −1.520, 0.750) | (35.806, −2.731, −0.710) ✓ | (37.571, −0.894, 0.230) ✓ |

（三帧 × 两传感器全中，残差仅来自观测量的三位小数截断。）

## 时间补偿 = 时间戳对齐，位置不平移

`camera: 99.955 + 0.045 = 100.000`、`radar: 99.962 + 0.038 = 100.000`，两个残差**精确为 0**。
所以"补偿后位置"就是同一组位置；不要按 `v·delay` 再平移（那会破坏两传感器一致性）。

## 六条规则（用 −18.003/1.804 复核）

| # | 规则 | 计算 | 判定 |
|---|---|---|---|
| 1 | cam/radar ≤ 0.25 m | max\|Δ\| = 0.00024 m | PASS |
| 2 | z ∈ [0.40, 1.90] | 0.750 | PASS |
| 3 | vx<0 且 \|vx\|∈[14,22] | −18.003 | PASS |
| 4 | 侧向加速度 ≤ 2.5 | 0.000000 m/s² | PASS |
| 5 | TTC < 2.20 s | 39.499844 / 18.002567 = 2.19406 | PASS |
| 6 | 横摆侧偏 < 0.12 m | 0.008 × 39.5 × 0.050 = 0.0158 | PASS |

## 被接受的注入报文（每行单个 LF，含第 3 行）

```
INJECT|frame=1|t=100.000|x=39.500|y=-1.700|z=0.750|vx=-18.003|vy=1.804
INJECT|frame=2|t=100.050|x=38.600|y=-1.610|z=0.750|vx=-18.003|vy=1.804
INJECT|frame=3|t=100.100|x=37.700|y=-1.520|z=0.750|vx=-18.003|vy=1.804
```

## KEY / CODE / FLAG

摘要按**原始 32 字节**拼接（与 PnC/V2X 同族约定；文档只给字符串字面量套了 `ASCII(...)`）：

```
SHA256(camera_radar_calibration.yaml) = 22e1a615fede8000193f9b3da98c4078eb493f3b93dad78ca1ff0a241eafc5ec
SHA256(fusion_acceptance.txt)         = fba2ad1505fe9bfbec1c90c7c256c331b851aa35a2fc5c9fe410fa286a41ad16
KEY  = SHA-256( d_yaml ‖ d_txt ‖ ASCII("GEELY-ADAS-FRONT-FUSION") )
     = c28a722579cebc3066d90aa9d60d1b06b5b6582eabdda8a1b67fc283314d9628
CODE = HMAC-SHA256(KEY, 三行报文)
     = 480aface33774137b2a67cb76cea84c837e26209a42cb64dabf2e476c38ce26e
FLAG = GEELY{ADAS_480aface33774137b2a67cb7_a42cb64dabf2e476c38ce26e}
```

注意 KEY 与"错误速度"版本完全相同（`c28a72…`）——**唯一差别就是报文里的 `vx/vy` 两个数**。

## 复现

```bash
python3 scripts/adas15_final.py work/redo15/attachments
```

## 复盘：前两轮为什么全错

| 轮次 | 报文 vx/vy | ⟹ CODE | 结果 |
|---|---|---|---|
| `session-1f70c339`（notes/08） | −18.000 / 1.800 | `9ed30db5…` | 平台判错 |
| `session-386fe245` 第一次 | 全时延平移 + 平均（x=38.753…） | `5b514c64…` | 平台判错 |
| `session-386fe245` 候选表 | 8 个口径，多数用了 −18.000 | — | 平台判错 |
| **本轮** | **−18.003 / 1.804（浮点差分）** | `480aface…` | ✅ 平台确认 |

教训：**打印用三位小数 ≠ 参与差分的数据也是三位小数**；规则说 "derived from the
three frame positions"，就老老实实拿浮点位置差分，不要"顺手取整"。
