# Ghost Fleet / 隐藏车队记录（attachments20.zip）

- **flag**: `GEELY{d40a971673369ea262ca89bfea2da80f3ae02cd4738505fdde5a4f12f921a425}`
- **平台**: 已提交验证 —— `code:1 恭喜，提交的Flag正确!`（task id 385 · Ghost Fleet）
- **附件**: `firmware/attachments20.zip`（sha256 `9d470770…963b`，与 `attachments6.zip` 逐字节相同）
- **解题脚本**: `scripts/att20_solve.py`
- **证据**: `evidence/att20-solve.log`

## 正解链路（关键修正：record 用 **拼接** 而非 HMAC）

```
FLAG = GEELY{ SHA-256( ASCII(record) || key_bytes ).hexdigest() }
record = "ops_shadow|LSVA24RZ7M1098423|1789600000"
key    = 357bdfa2e150477dbda20531bce9eac9        # 三个有效碎片 16 字节值逐字节 XOR
```

`openssl dgst -sha256` 与 Python 独立复算一致 = `d40a971…1a425`。

## 1. 碎片筛选（policy 的三条判据）

| 碎片 | 序列号 | TL | TR | PARITY | 16 字节 | 判定 |
|---|---|---|---|---|---|---|
| fragment_01 | GF-2026-A17 | 实心 | 空心 | 实心 | `c8f0bc5b58b68f7d07735f9213d9827e` | ✅ |
| fragment_02 | GF-2026-D12 | 空心 | 实心 | 实心 | `6c84e7e5ccdd87179e5a405fd220227a` | ❌ |
| fragment_03 | GF-2026-C09 | 实心 | 空心 | 实心 | `8f56f8196920de2496a8e121e3aa7bea` | ✅ |
| fragment_04 | GF-2026-E88 | 空心 | 实心 | 实心 | `368b9c267e2195c979254de8a27c8f98` | ❌ |
| fragment_05 | GF-2026-F31 | 实心 | 空心 | 实心 | `72dd9be0d0c616242c79bb824c9a135d` | ✅ |

- PARITY 标记是**矩阵外左侧的实心大圆盘**（bbox 30,452–50,472，21×21，面积 349≈π·10.5²），
  五个碎片**像素完全相同**（都实心）；五个碎片的 ⊕(全部 128 点) 也全为 1 → 第三条判据全通过。
  筛选完全由标定块决定 → 恰好 3 个有效。
- 与 `custody_manifest.csv` 独立吻合：`continuous` + `red-wax` + `IR-004-C` = A17 / C09 / F31。
- `key = 357bdfa2e150477dbda20531bce9eac9`

## 2. record 三个字段

- **canonical tenant = `ops_shadow`**（★ 本题的坑）
  broker note 里的别名是 `shadow operations`；"internal console" 的规范形式是
  **换序 + 下划线**：`ops_shadow`。我最初按 slug 猜成 `shadow-operations`，
  连 18 种租户写法 × 字段序都试遍仍不对；平台提示给出该形式后才命中。
- **vehicle = `LSVA24RZ7M1098423`**
  `chassis_label.png` 四组左→右拼接 `LSVA24 RZ7M 1098 423`（字形列扫描确认恰好 17 个字形，
  无前后缀杂mark）。
- **clock = `1789600000`**（retained register packet 的时钟读数）

## 3. 我踩过的坑（记录备查）

1. 误照搬姊妹题 `attachments7`（Chromatic Custody，已解）的 **HMAC-SHA256(key, record)** 模板；
   本题是 **纯拼接后 SHA-256**：`SHA-256(ASCII(record) || key_bytes)`，不是 HMAC。
2. 租户规范化猜成 kebab-case `shadow-operations`；实际是 `ops_shadow`。
3. policy 卡（980×780）正文确实**溢出画布被裁掉**（卡片下边框在 y≈756，文字继续到 y≥772 被截断），
   所以 record 的序列化形式无法从附件反推 —— 这条只能靠平台提示补全。
   用过的枚举（全 10 种三碎片组合 × bit/byte 序、54 种 record 形态、HMAC/sha256 各种组合）
   全部记录在 `evidence/att20-solve.log` 的早期版本里，均已排除。

## 复现

```bash
python3 scripts/att20_solve.py
# FLAG = GEELY{d40a971673369ea262ca89bfea2da80f3ae02cd4738505fdde5a4f12f921a425}
```
