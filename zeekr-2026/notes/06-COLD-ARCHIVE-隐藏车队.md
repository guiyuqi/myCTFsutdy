# GEELY COLD ARCHIVE / 隐藏车队记录（attachments6.zip）

- 附件: `firmware/attachments6.zip`
  sha256 `9d470770d6f04219d30d47b6806ee5547a93713166196978c9496c9b7c7e963b`
- 解题脚本: `scripts/att6_solve.py`
- 证据: `evidence/att6-extract.log`

> ⚠️ **本文档的「未确定部分」结论已被推翻**（2026-09-19 复核）。
> `attachments20.zip` 与本附件逐字节相同；借同批姊妹题 `attachments7`
> （平台已接受的 CHROMATIC CUSTODY，`authentication: HMAC-SHA256`）反推出
> 生成器模板：`record = operator|vehicle|epoch` →
> `FLAG = GEELY{HMAC-SHA256(secret, record).hex()}`。
> 最终 flag 见 **`notes/13-GEELY-COLD-ARCHIVE-attachments20.md`**：
> `GEELY{c00a735f49ca1b27a89bf0c2ae79865b11fb829f179c674a03939fbcd5ac6eb1}`

## 已确定部分（构件完全确定）

`archive_policy.png` 可见正文给出判据：

```
A fragment is valid only when all checks pass:
 1. top-left calibration mark = filled
 2. top-right calibration mark = empty
 3. PARITY mark equals XOR of all data dots

Byte extraction:
 - 16 rows x 8 columns; row0=byte0 ... row15=byte15
 - left column = bit7, right column = bit0; filled=1, hollow=0
```

`custody_manifest.csv` 独立给出同一结论（continuous + red-wax + IR-004-C）：

| 碎片 | 标定块 | 矩阵值 |
|---|---|---|
| GF-2026-A17 (fragment_01) | TL filled / TR empty ✅ | `c8f0bc5b58b68f7d07735f9213d9827e` |
| GF-2026-D12 (fragment_02) | TL empty / TR filled ❌ | `6c84e7e5ccdd87179e5a405fd220227a` |
| GF-2026-C09 (fragment_03) | TL filled / TR empty ✅ | `8f56f8196920de2496a8e121e3aa7bea` |
| GF-2026-E88 (fragment_04) | TL empty / TR filled ❌ | `368b9c267e2195c979254de8a27c8f98` |
| GF-2026-F31 (fragment_05) | TL filled / TR empty ✅ | `72dd9be0d0c616242c79bb824c9a135d` |

五个碎片的 PARITY 点均为实心，且 ⊕(全部数据点)=1，故 parity 校验全部通过；
筛选完全由标定块决定，恰好 3 个有效 → 与托管记录（continuous+red-wax+batch IR-004-C）一致。

```
SIGNING SECRET = c8f0…827e ⊕ 8f56…7bea ⊕ 72dd…135d
               = 357bdfa2e150477dbda20531bce9eac9   (16 bytes)
```

其余确定值：
- `chassis_label.png` → VIN = `LSVA24RZ7M1098423`（四组左到右拼接，去掉组间标记）
- `retained_broker_note.txt` → tenant 别名 `shadow operations`（需 canonical 形式）、
  register clock `1789600000`、"only the canonical tenant form … is used as signature material"

## 未确定部分（题目附件本身残缺）

`archive_policy.png` = 980x780，正文最后一行 **只渲染出上半截**：
`y=772..779` 残留 "XOR the three values byte by byte" 的字头，画布在 780 处截断。
即卡片在 "XOR the three values byte by byte" 之后的内容（register packet 的
序列化形式 / 签名算法 / flag 编码）**没有落在画布内**，属于附件自身残缺。

平台只给到 `GEELY{<sha256_hex>}`（64 hex）。因此最终一步只能枚举，
按可能性排序（`scripts/att6_solve.py`）：

| # | 形式 | flag |
|---|---|---|
| 1 | HMAC-SHA256(secret, `shadow-operations\|LSVA24RZ7M1098423\|1789600000`) | `GEELY{c00a735f49ca1b27a89bf0c2ae79865b11fb829f179c674a03939fbcd5ac6eb1}` |
| 2 | 同上，tenant 用 `shadow_operations` | `GEELY{c95378675f2241dd9d8c582ea2f614b854952307a22d40e634f657d735a014ac}` |
| 3 | 同上，`tenant=…\|vehicle=…\|clock=…` | `GEELY{357a13df07216049613e68471842d6e70e8835fe535a1fa800157477466a36ef}` |
| 4 | SHA256(HMAC #1) | `GEELY{d3e9b1843400369acdc5db891661d877913ef3abb49aba60e8784dfeb9d9055c}` |
| 5 | SHA256(signing secret 原始 16 字节) | `GEELY{44519f5d6d9ac64f6f36ea1d416aaa8a2fd2b50695136842f69bef806c690446}` |
| … | 其余（逗号/JSON/字段行/tenant-only、SHA256(secret‖msg) 等） | 见 `evidence/att6-extract.log` |

- flag: 首选 `GEELY{c00a735f49ca1b27a89bf0c2ae79865b11fb829f179c674a03939fbcd5ac6eb1}`（未在平台验证）
- 判定依据: 题面 5 个构件全部参与 → 不是单纯的 sha256(secret)；note 明确写
  "used as signature material"，与同批 attachments7（custody envelope 卡写
  `authentication: HMAC-SHA256`，题面要求"计算 custody 记录的认证摘要"）同构。
- 缺口: register packet 的具体分隔符/字段顺序写在被裁掉的那几行里，无法从现有
  构件反推；建议按上表顺序在平台试提交。

## 关键命令

```bash
mkdir -p work/att6 && cd work/att6 && unzip -o ../../firmware/attachments6.zip
python3 analysis/frag.py                     # 碎片矩阵 → 16 字节
python3 ~/ctf-2026/scripts/att6_solve.py     # 已确定值 + 候选枚举
```
