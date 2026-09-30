# GEELY MOSAIC CARRIER（attachments30.zip ；与 attachments9.zip 逐字节相同）

- **flag（首选）**: `GEELY{9d94b88d7e1544a0b504602613ac02c246e2ade60663d7f76bf8acb8cdce320e}`
- 平台提示（ROM 2026-09-19 11:05:11）: 载体没有文件系统/magic/明文 manifest；
  真实页需同时满足 CRC、状态、reserved marker、mosaic table；掩码依赖 family、
  page id、order，**不能直接异或原始页数据**。
  → 与本文链路完全一致（四重校验筛出 21/24/27/2B/2E，先解掩码再异或）。
  提示未给出 page_id/order 的编码方式，故保留两条轴的候选（见文末）。
- 附件:
  - `firmware/attachments30.zip` sha256 `b57d766b6f11bbc2b342000abd1853c700a05c3d0e3ebef1b89399abda96d663`
  - `attachments/carrier.bin` sha256 `926507301e83905e0fc506a01040f4f3f90557a61cc4db4e46bf613dfd3744c6`
  - `attachments/carrier_map.png` sha256 `53f697106671ec9d8807e4a08b53fd07b8e55d5efc591d662ed22bd26409fa87`
- 解题脚本: `scripts/att30_solve.py`；证据: `evidence/att30-solve.log`

## 载体结构（carrier_map.png / REVISION 7）

```
页 = 0x200 字节 × 16
  +000..+01F  masked share (32B)
  +1E0        page id       (1B，表里按十六进制显示：21 24 27 2B 2E …)
  +1E2        status byte   参与页 == 0x5A
  +1E4        CRC32 of +000..+1DF, big endian
  +1EC        reserved      参与页 == 0xA5
参与条件: status==5A 且 reserved==A5 且 CRC 匹配 且 page id 在 mosaic 表内
mosaic 表: 21->1, 24->2, 27->3, 2B->4, 2E->5
mask = SHA256(FAMILY || page_id || order)[0:32]   FAMILY = "MOSAIC-CARRIER-7"
share = masked share XOR mask ;  secret = 所有参与页 share 逐字节 XOR (32B)
```

## 16 页校验结果

全部 16 页 CRC32 都合法（CRC 不是筛选条件），status/resv/表成员才是：

| page | id | status | reserved | CRC | 表内 | 参与 |
|---|---|---|---|---|---|---|
| 1 | 21 | 5A | A5 | ok | ✅ | ✅ |
| 4 | 24 | 5A | A5 | ok | ✅ | ✅ |
| 7 | 27 | 5A | A5 | ok | ✅ | ✅ |
| 11 | 2B | 5A | A5 | ok | ✅ | ✅ |
| 14 | 2E | 5A | A5 | ok | ✅ | ✅ |
| 10 | 2A | 5A | A5 | ok | ❌ | ❌（陷阱：四项里前三项都过） |
| 5 / 15 | 25 / 2F | 5A | BC / 54 | ok | ❌ | ❌ |
| 其余 | — | ≠5A | — | ok | ❌ | ❌ |

## 掩码输入编码的判定

卡片公式**没有**写编码方式（同批出题器在 `atrium_protocol.txt`
`LANE_MASK = SHA256(FAMILY || uint16be(lane_id) || uint32be(seed) || ASCII("ATRIUM-LANE"))`
和 `forge_protocol.txt` `SHA256(FAMILY || parent_id || uint16be(S))` 里都会显式标注
`uint16be/uint32be/ASCII`；纯字节串如 `parent_id` 则不标）。

- page id 在页内是 **1 字节**（+1E0，+1E1 是随机填充：20FD/21FD/22BB…），
  卡片也写明 `CRC … big endian` 这种需要标注的地方；
- 因此 `page_id` / `order` 是单字节值：`bytes([pid])` / `bytes([order])` —— **首选**；
- 备选读法是把表里的文本拼进去（`"21"+"1"`），本脚本也一并给出。

## 结果

首选（raw 单字节拼接）：

```
manifest secret = 9d94b88d7e1544a0b504602613ac02c246e2ade60663d7f76bf8acb8cdce320e
flag(secret.hex())        = GEELY{9d94b88d7e1544a0b504602613ac02c246e2ade60663d7f76bf8acb8cdce320e}
flag(sha256(secret).hex()) = GEELY{42cca432af2340bac408b9b070d5a7a92cefaec2aaaa631cfb5d4b996da21550}
```

备选（ascii 文本拼接 "21"+"1"）：

```
manifest secret = a96568eafd709f88d8ee53f778385de0e0ea64c70a22fd40f1962d059cb0aeb3
flag(secret.hex())        = GEELY{a96568eafd709f88d8ee53f778385de0e0ea64c70a22fd40f1962d059cb0aeb3}
flag(sha256(secret).hex()) = GEELY{b09d38b77f39d4f3c78df09df8db5ce22ead36811a93622bde9c50a0378b3729}
```

首选 `secret.hex()` 的依据：同批已确认的 flag 都是「最终物件的 hex 直接进 flag」
（ATRIUM 的 32 字节 KEY → `GEELY{ATRIUM_<key hex>}`；CHROMATIC/COLD ARCHIVE 的
HMAC 摘要、ADAS 的 CODE → 摘要 hex），没有「再哈希一次」的先例；而本卡片的推导
到 32 字节 secret 为止，不再有哈希步骤。

## 提交顺序（若平台判否）

两条轴：
- 掩码输入：`raw` = page_id/order 各 1 字节（卡片公式未标 ASCII/uintN，同批
  `forge_protocol.txt` 里裸字节串 `parent_id` 同样不标注 → 首选）；
  `ascii` = 按表内文本 `"21"+"1"` 拼接。
- flag 取值：`secret.hex()`（同批已确认题目 ATRIUM/CHROMATIC/COLD ARCHIVE/ADAS
  的 flag 都是最终物件 hex，无二次哈希 → 首选）；`sha256(secret).hexdigest()`。

| # | flag | 口径 |
|---|---|---|
| 1 | `GEELY{9d94b88d7e1544a0b504602613ac02c246e2ade60663d7f76bf8acb8cdce320e}` | raw + secret.hex()（首选） |
| 2 | `GEELY{42cca432af2340bac408b9b070d5a7a92cefaec2aaaa631cfb5d4b996da21550}` | raw + sha256(secret) |
| 3 | `GEELY{a96568eafd709f88d8ee53f778385de0e0ea64c70a22fd40f1962d059cb0aeb3}` | ascii + secret.hex()（上次 att9 会话未给此值作首选） |
| 4 | `GEELY{b09d38b77f39d4f3c78df09df8db5ce22ead36811a93622bde9c50a0378b3729}` | ascii + sha256(secret)（`session-ff459216` 的首选，可能已判否） |
| 5 | `GEELY{bf5e40ec48e12fb9ae91a7862291c2380e6f96d160a5eb5c743f17a0d9acca73}` | raw pid + order=槽位(0基) |
| 6 | `GEELY{dc6e72be4cc601917350d9ed0beaf78948b70ea69b9ab841605fc8eee0e5273a}` | raw pid + order=uint16be |

其它已算过的组合（pid∈{raw,hexU,hexl,u16be,dec,槽位} × order∈{raw,dec,dec2,u16be,u32be,hexU}）
见 `evidence/att30-solve.log` 与本文会话记录。

## 关键命令

```bash
mkdir -p work/att30 && cd work/att30 && unzip -o ../../firmware/attachments30.zip
cd ~/ctf-2026 && python3 scripts/att30_solve.py | tee evidence/att30-solve.log
```

---

## 追加结论（2026-09-19，6 个候选全判否后）：断言不完整，附件无法唯一确定 flag

1. **卡片漏了掩码输入的编码**：`SHA256(FAMILY || page_id || order)[0:32]` 没写
   page_id / order 是"单字节值"还是"表内文本"。同批出题器在
   `atrium_protocol.txt`（`uint16be(lane_id) || uint32be(seed) || ASCII("ATRIUM-LANE")`）
   和 `forge_protocol.txt`（`parent_id || uint16be(S)`）里都会显式标注编码 ——
   本题卡片没有，导致 32 字节 secret 不唯一。
2. **四重校验实际只有三重有效**：CRC32 在 **全部 16 页** 都合法（已逐页验证），
   筛页完全靠 status==5A / reserved==A5 / 表成员 → {21,24,27,2B,2E}（2A 是陷阱）。
3. **附件没有隐藏数据**：
   - PNG：IDAT 解压后正好 1100×1500×3+1500 字节，无多余 zlib 流/尾部数据；
     像素只有背景色+黑+抗锯齿，无 LSB/异色隐写。
   - ZIP：EOCD 后无尾随数据，无额外 local header / 数据描述符。
   - carrier.bin 正好 8192 字节。
4. **伪造不出可验证性**：按"文档风格"枚举了约 10 万种掩码格式（family × tag ×
   pid/order 编码 × 分隔符 × 摘要/hexdigest 掩码），得到 **177,525 个不同 secret**；
   其中没有任何一个能在附件里找到对应物（无明文拷贝）、也没有可读/结构化特征、
   与诱饵页也没有一致性关系。由于 flag = 该 secret 的哈希，**离线无法判别对错**。
5. **随机数不可逆推**：把 8192 字节当作连续小端 dword 序列做 MT19937 temper 逆运算 +
   旋转递推检验，1061 个可检验四元组 **0 通过** → 填充数据不是 Python `random`
   （MT19937），因此无法通过恢复 RNG 状态反推 secret。
6. 结论：题目断言缺失关键参数，**任何解都只能靠猜生成器实现细节**，
   "没有人解出"符合预期。建议按 `notes/30-...` 的证据向主办方申诉/索要修正版，
   或（平台允许时）用提交接口批量试 `work/att30/candidates.tsv` 中的候选。

候选表：`work/att30/candidates.tsv`（tier1 整数宽度风格 / tier2 其它编码 /
tier3 生成器漏解掩码的 bug 变体 / tier4 文件级 sha256；每行给
flag=secret.hex()、sha256(secret)、sha256(hex(secret)) 三种写法）。

## 提示 2（ROM 2026-09-19 11:28:31）与最新状态

```
对每页：
share = bytes(a ^ b for a, b in zip(page[0:32], mask_for(page_id, order)))
五个解掩码后的份额逐字节异或得到 XXXX(被平台打码)
```

→ 平台的参考解与我们的链路**逐行一致**：5 页(21/24/27/2B/2E)、先 `mask_for`
解掩码、再逐字节异或。表页集合、份额偏移、异或步骤全部确认无误。
仍未给出的只有 `mask_for` 的函数体（字节编码）。已试：1B/1B、hexU/dec 两种读法
× {secret.hex(), sha256(secret)} 全判否。

全量候选表：`work/att30/candidates_full.tsv`（FAMILY 变体 × tag × pid/order 编码 ×
分隔符去重后的全部 secret，每行 3 种 flag 写法），生成脚本
`scripts/att30_candidates_full.py`。等第 3 条提示给出 `mask_for` 即可一步定解。
