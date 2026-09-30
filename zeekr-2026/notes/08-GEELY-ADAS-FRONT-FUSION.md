# GEELY FRONT ADAS FUSION ACCEPTANCE / BUILD 8.7.2（attachments4.zip）

> ## ⛔ 本笔记的 flag 是**错的**，已被平台判错
> 本笔记用了 `vx=-18.000 / vy=1.800`（把恢复出的浮点位置取整后再差分）。
> 规则 3 要求的是 **从恢复出的位置直接差分**：`(−1.800257)/0.1 = −18.002567 → −18.003`，
> `vy → 1.804`。坐标变换、时间补偿、六条规则、KEY 全部与正解一致，**只差这两个数**。
>
> - ✅ **正解**：`GEELY{ADAS_480aface33774137b2a67cb7_a42cb64dabf2e476c38ce26e}`（平台已确认）
> - 正解笔记与确认脚本：`notes/12-GEELY-ADAS-FRONT-FUSION-attachments15.md`、`scripts/adas15_final.py`
>
> 下面内容保留作为复盘：坐标约定陷阱的推导过程本身是正确的。

- **flag（错误，勿用）**: `GEELY{ADAS_9ed30db5dd978907d765ad30_110fed3a2ed6cf3506b5595e}`
- **附件**: `firmware/attachments4.zip`
  sha256 `48998e83bb9b394c57cbd2a15caae73f97b0665bc65f0f76dd877d952708c705`
- **解题脚本**: `scripts/adas_fusion_solve.py`
- **证据**: `evidence/adas4-solve-run.log`

## 关键点 1：坐标变换约定的“文档陷阱”

`fusion_acceptance.txt` 与 yaml 注释都写 `p_sensor = R·p_vehicle + t`，
因此文档给出 `p_vehicle = R^T·(p_sensor − t)`。**但这个读法是错的**：

- 按文档逆变换：cam 与 radar 的 |Δ| ≈ 5.5 m（远超 0.25 m），且 z 落到 −2.17/−0.29；
- 按 `p_vehicle = R·p_sensor + t`（即 yaml 的 R 实际是 vehicle_from_sensor 的转置写反了）：
  cam 与 radar 的 |Δ| ≈ 0.0001~0.0002 m，z 恒为 0.750。

判据不是“哪个更像”，而是**设计值是整数**：用
`(39.500, −1.700, 0.750) / (38.600, −1.610, 0.750) / (37.700, −1.520, 0.750)`
正投影回相机/雷达坐标系，**逐位精确复现** jsonl 里的 3 位小数坐标
（残差仅 ~1e-4，来自观测量的 3 位小数截断）。所以真值就是这三个整点。

## 关键点 2：时间补偿

`camera_capture_time_s + camera.transmission_delay_s = 99.955 + 0.045 = 100.000`
`radar_capture_time_s  + radar.transmission_delay_s  = 99.962 + 0.038 = 100.000`

即“补偿”就是把时间戳对齐到 fused_time。**位置无需再平移** ——
两个传感器给出的车体系位置本来就一致（|Δ|≤2e-4），若额外按 −18 m/s×delay 平移
反而把整数设计值（39.500 等）破坏掉，且无法唯一确定用哪个 delay。
故 INJECT 的 x/y/z 就是上表的整点。

## 关键点 3：运动学闭环

三个位置 `39.500 → 38.600 → 37.700`，Δt=0.050：
`vx = (37.700 − 39.500)/0.100 = −18.000`（与 radar `range_rate_mps: −18.0` 吻合）；
`vy = (−1.520 + 1.700)/0.100 = +1.800`。

| 规则 | 计算 | 判定 |
|---|---|---|
| 1 位置一致 | max\|cam−rad\| = 0.0002 m | ≤0.25 ✓ |
| 2 高度 | z = 0.750 | ∈[0.40,1.90] ✓ |
| 3 纵向相对速度 | −18.000 m/s | 负、\|v\|∈[14,22] ✓ |
| 4 侧向加速度 | 0.0000 m/s² | ≤2.5 ✓ |
| 5 TTC | 39.500/18.000 = 2.1944 s | <2.20 ✓（阈值卡得很紧，佐证 x₁=39.500 是设计值） |
| 6 横摆侧偏 | 0.008×39.500×0.050 = 0.0158 m | <0.12 ✓ |

## 被接受的注入报文

```
INJECT|frame=1|t=100.000|x=39.500|y=-1.700|z=0.750|vx=-18.000|vy=1.800
INJECT|frame=2|t=100.050|x=38.600|y=-1.610|z=0.750|vx=-18.000|vy=1.800
INJECT|frame=3|t=100.100|x=37.700|y=-1.520|z=0.750|vx=-18.000|vy=1.800
```
（每行后接单个 LF）

```
SHA256(yaml) = 22e1a615fede8000193f9b3da98c4078eb493f3b93dad78ca1ff0a241eafc5ec
SHA256(txt)  = fba2ad1505fe9bfbec1c90c7c256c331b851aa35a2fc5c9fe410fa286a41ad16
KEY  = SHA-256( 两个原始 32 字节摘要 || ASCII("GEELY-ADAS-FRONT-FUSION") )
     = c28a722579cebc3066d90aa9d60d1b06b5b6582eabdda8a1b67fc283314d9628
CODE = HMAC-SHA256(KEY, 三行报文) 
     = 9ed30db5dd978907d765ad3094ba655c874aaff5110fed3a2ed6cf3506b5595e
FLAG = GEELY{ADAS_9ed30db5dd978907d765ad30_110fed3a2ed6cf3506b5595e}
```

摘要拼接按**原始 32 字节**（与 PnC 题 PROFILE 的 `SHA-256(...)` 编码风格一致）。
备选（十六进制字符串拼接）得
`GEELY{ADAS_1d258c1d669234b63e191ba4_767882dffe09073036a2e623}`，非首选。

## 复现

```bash
python3 scripts/adas_fusion_solve.py
```
