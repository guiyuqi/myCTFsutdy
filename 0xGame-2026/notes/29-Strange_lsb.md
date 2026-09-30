# 29 · Strange_lsb

- **flag**: `0xGame{LSB_x0r_Pl4n3_1s_4w3s0m3!}`
- **分类**: Misc / 图片隐写（离线题，无容器）
- **分值**: 792 | 解出人数: 10
- **提交**: `code=200 {"result": true}` ✅
- **可复现脚本**: `scripts/29-solve.py`
- **证据**: `evidence/29-xor-lsb-plane.png`（XOR 位平面，可直接看到 QR 码）

---

## 题目

> 艺术家绘制了一幅现代艺术画作，并声称他在画作中封印了一段密语。
> 「单一的色彩只是噪音，唯有**三原色交织**之时，真相才会显现。」

附件：`firmware/29_Strange_lsb/week1-misc-strange_lsb.zip` → 单个 `challenge.png`（1256×1224, 8-bit RGB）。

---

## 关键洞察 —— 「三原色交织」= 三通道 LSB 逐位异或

### 踩过的坑（全部无效）

`challenge.png` 是一张 JPEG 转存的夜空照片（有 8×8 JPEG 痕迹），**三个通道本质是同一张灰度图**
（只是各自加了不同 DC 偏移：`G-R ≈ +4`，`B-G ≈ +30`）。

因此逐通道看 LSB 完全是**均匀噪声**，这误导了很大一部分搜索：

| 指标 | 实测值 | 含义 |
|---|---|---|
| 每个通道 LSB 的 1 比例 | 0.4997 ~ 0.4999 | 均匀 |
| 相邻像素 LSB 自相关 | 0.001 | 无空间结构 |
| 102×102 分块 LSB 偏置 | max 0.016 | 无局部载荷 |
| `(R_lsb,G_lsb,B_lsb)` 两两一致率 | 0.5000 ~ 0.5003 | 两两独立 |

在这种"全平面随机"下，下面这些**全部试过且全部无果**：

- 位平面 0–7（整张 / 逐行 / 逐列），6 种通道顺序，MSB/LSB 两种打包；
- `R:a, G:b, B:c` 全部 8³ = 512 种组合 × 交织/拼接两种布局；
- 通道间位运算（`^`、`&`、`|`、`(R&G)|B`、加法进位）后取每个位平面；
- 多平面组合（每通道取 2~3 个位平面）、旋转/翻转/转置/蛇形/分块（tile 2~64）扫描；
- 步长 1~32 + 所有相位偏移；`stride`/`offset` 重同步；
- 派生化（`R+G+B`、`2R-G-B`、 luminance、`abs` 差、YCbCr/HSV/LAB/CMY 色彩空间）；
- 文件级：PNG 尾部数据、IDAT 内附加数据（`unused_data`=0）、逐行 filter type 序列、压缩流 LSB；
- 各种 magic 扫描（`PK\x03\x04`/zlib/gzip/`\x89PNG`/JFIF/xz/7z…）+ 最长可打印串检测。

结论：**没有任何"逐通道"或"单平面"式的载荷**。

### 真正的解法

题目说「单一的色彩只是噪音」——单通道确实是噪声；
「唯有三原色交织之时」——把**三个通道的 LSB 逐位异或**：

```
plane = (R & 1) ^ (G & 1) ^ (B & 1)
```

得到的 1bpp 位图**置位比例只有 0.1393**（而不是随机应有的 0.5）——
这就是唯一的统计异常信号。

渲染这张位图（`xor*255`），正中央出现一个完整的 **QR 码**：

- bbox：`x=301, y=285, side=654 px`
- QR **version 4**（33×33 模块），约 19.82 px/模块
- 轴对齐，无旋转/透视，**反色**（`xor==1` 是 QR 的黑色模块）
- EC level **H**，mask **2**，format 信息纠错位数 = 0

用脚本内置的纯 Python QR 解码器（环境无 zbar/zxing/pyzbar/cv2）读取 byte 模式数据段：

```
0xGame{LSB_x0r_Pl4n3_1s_4w3s0m3!}
```

---

## 复现

```bash
cd ~/ctf-2026
python3 scripts/29-solve.py
# [*] R_lsb^G_lsb^B_lsb 置位比例: 0.1393
# [*] QR version : 4  (33x33 modules, 19.82 px/module)
# [*] EC level   : H ; mask=2 ; format 纠错位数=0
# [+] FLAG = 0xGame{LSB_x0r_Pl4n3_1s_4w3s0m3!}
```

只依赖 `numpy` + `Pillow`；QR 定位（自动遍历 version 1–10 + finder pattern 校验）、
format 信息 BCH 纠错、去掩码、之字形取码、反交织、byte/alphanumeric/numeric 解析
全部在脚本内实现。

---

## 一句话总结

> 三个通道的 LSB 单看都是纯噪声，**异或之后**才浮现出藏在图正中的 QR 码 —— 这就是"三原色交织"。
