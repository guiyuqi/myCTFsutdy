# GEELY TSP 影子状态头重绑定（attachments3.zip）

- **flag**: `GEELY{TSP_1cf690e892221045c43b34aa_77b8e1efe308ad6a69775527}`
- **附件**: `firmware/attachments3.zip`
  sha256 `7c9d107eb24cb5e9b76c78d25401404846e382045626ecb7850025740ed1af80`
  （与 `attachments2.zip` 逐字节相同，是同一道题）
- **解题脚本**: `scripts/tsp_solve.py`
- **产出**: `work/att3/solve-result.json`、`evidence/tsp-solve-run1.log`

## 漏洞点：签名不覆盖 header（未保护头）

`protected_payload_b64` 的 P-256 签名只覆盖 payload 字节；
`policy_epoch` 与 `merge_mode` 位于**未保护头** `header_b64`，不在签名范围内
（PROFILE 原话：*"policy_epoch and merge_mode are in the unprotected header.
They are not covered by the signature."*）。

3 月网关策略（`platform_policy_epoch = 20260314`）的接受条件：

| 条件 | 说明 |
|---|---|
| `header.policy_epoch == 20260314` | 必须等于平台策略纪元 |
| `header.merge_mode ∈ {authoritative, advisory_first}` | `legacy_any` 被拒 |
| `payload.version >= 250` | **`advisory_first` 下放宽**（离线维修数据回补） |
| `remote_cmd == "unlock"` | 还需 `maintenance_mode == true` 且 `operator_scope == "factory"` |

因此攻击 = 拿一条**已签名的 unlock/factory/maintenance 载荷**，
把它的未保护头改写成 `policy_epoch=20260314 + merge_mode="advisory_first"`，
签名依然通过。

## 关键步骤

1. **独立验签**（不信任 trace 里的 `wire_signature_valid`）：
   7 帧全部用 pinned 公钥验签，`cryptography` 与手写 P-256 两套实现结论一致
   —— **7 帧签名全部有效**。
   → trace 中 frame 209 的 `wire_signature_valid: false` 与密码学事实矛盾，
   是**日志层面的误导**（该字段是纯数据，不是指令）。

2. **筛选可重绑定目标**（签名有效 + topic VIN 匹配 + unlock/factory/maintenance + version<250）：

   | 帧 | version | topic VIN | payload VIN | trace_sig | 判定 |
   |---|---|---|---|---|---|
   | 188 | 241 | ...000003 | ...000003 | true | ✅ 采用 |
   | 202 | 242 | ...000003 | **...000004** | true | ✗ VIN 不匹配（干扰项） |
   | 209 | 243 | ...000003 | ...000003 | **false** | ✗ 被 trace 标为 wire 验签失败（干扰项） |

   frame 188 是唯一同时满足「有效签名 + VIN 匹配 + trace 验签通过」的 unlock 记录，
   且是唯一带维修出处 `audit_note: "gate maintenance window 20260201"` 的帧
   （对应题面「离线维修数据回补」）。

3. **构造新头**（等价于把平台帧 331 的头做一次字节级替换
   `"authoritative"` → `"advisory_first"`，已断言校验）：

   ```json
   {"alg":"ES256","kid":"TSP-SHADOW-33","policy_epoch":20260314,"merge_mode":"advisory_first"}
   ```
   SHA-256 = `725007a67eb5c152b6089696913a43c8e3d8e63e190c679954e460373ae0cbad`

4. **算 CODE**（摘要按**原始 32 字节**拼接，字符串字面量才加 `ASCII(...)`）：

   ```
   CODE = SHA-256( SHA-256(DER(SPKI)) ||
                   SHA-256(signed payload bytes) ||
                   SHA-256(exact new header bytes) ||
                   ASCII("TSP-SHADOW-REBIND") )
   ```

   - `SHA-256(DER(SPKI))` = `613fb11dc62aa3508995bc31a3b7c50d87d97f7261864fa9ad3c0bc6d421305f`
   - `SHA-256(payload 188)` = `117498c836440cce5da1fd79a071140906e3e90c2f71fbc0997fd72021391690`
   - `SHA-256(new header)` = `725007a67eb5c152b6089696913a43c8e3d8e63e190c679954e460373ae0cbad`
   - `CODE` = `1cf690e892221045c43b34aa98a02729db37443b77b8e1efe308ad6a69775527`

5. **编码 flag**（CODE 前 24 hex + 后 24 hex）：

   ```
   GEELY{TSP_1cf690e892221045c43b34aa_77b8e1efe308ad6a69775527}
   ```

## 备选与判定依据

| 备选 | flag | 为何非首选 |
|---|---|---|
| payload = frame 209 | `GEELY{TSP_249e57a3340e8f6689a1f51b_1dabf9c431922dbd26a6d773}` | 其签名实际有效（作者签名生成有误），但 trace 明确标记 wire 验签失败；该字段是 188/209 之间**唯一**的区分依据，即作者设定的筛选条件。且 209 无 `audit_note` 维修出处 |
| header 用 JSON 带空格 / 缩进 / 排序键 | 见 `work/att3/solve-result.json` | PROFILE 说 `exact … bytes`，与 `protected_payload_b64` 同为「紧凑 JSON 原始字节」；且字节级替换 331 头得到的就是紧凑形式 |

> 注：`attachments2.zip` 与 `attachments3.zip` 内容完全相同，本题两个包是同一道题。

## 复现

```bash
source ~/re-tools/fw-env.sh
cd ~/ctf-2026
python3 scripts/tsp_solve.py
```

## 第二轮独立复核（attachments2.zip，未复用上述脚本）

针对 `firmware/attachments2.zip`（sha256 `7c9d107e…1af80`，与 `attachments3.zip` 逐字节相同）
从零重算一遍，**新头不再靠 JSON 重新序列化**，改为对平台帧 331 的头部做字节级替换：

```python
new_header = header_331.replace(b'"authoritative"', b'"advisory_first"')
```

三种构造（字节替换 331 头 / `json.dumps(..., separators=(",",":"))` / 改写 188 头）
**逐字节一致**（脚本内 `assert` 通过），因此 "exact new header bytes"（91 字节）无歧义。

独立复算结果与原结论完全一致：

| 项 | 值 |
|---|---|
| SHA256(DER SPKI) | `613fb11dc62aa3508995bc31a3b7c50d87d97f7261864fa9ad3c0bc6d421305f` |
| SHA256(payload 188) | `117498c836440cce5da1fd79a071140906e3e90c2f71fbc0997fd72021391690` |
| SHA256(new header) | `725007a67eb5c152b6089696913a43c8e3d8e63e190c679954e460373ae0cbad` |
| CODE | `1cf690e892221045c43b34aa98a02729db37443b77b8e1efe308ad6a69775527` |
| **FLAG** | **`GEELY{TSP_1cf690e892221045c43b34aa_77b8e1efe308ad6a69775527}`** |

本轮附加验证：

1. **负向对照**：对 7 帧 payload 各翻转 1 字节，签名全部由 VALID 变 INVALID
   → 验签流水线能真正识别坏签名，上面「7 帧全有效」的结论不是假阳性。
2. **交叉验签矩阵**：每帧签名只对其自身 payload 通过（7×7 对角阵），
   排除「签名串被复制到别帧」的可能。
3. **`openssl pkeyutl -verify` 复核**：r||s 手工转 DER 后，7 帧全部
   `Signature Verified Successfully` —— 与 `cryptography` 两套独立实现结论一致。

因此 trace 中 frame 209 的 `wire_signature_valid: false` 与密码学事实**确实矛盾**
（作者签名生成/标注不一致）。选用 frame 188 的三条理由：
有效签名 + topic VIN 匹配 + 唯一带维修出处 `audit_note:"gate maintenance window 20260201"`
（对应题面「离线维修数据回补」），而 209 无维修出处且被 trace 标为 wire 失败。
备选 `GEELY{TSP_249e57a3340e8f6689a1f51b_1dabf9c431922dbd26a6d773}` 已记录。

- 复核脚本：`scripts/tsp2_verify.py`
- 复核日志：`evidence/tsp-independent-verify.log`
- 全帧解码表：`work/att2/decoded_envelopes.json`、`evidence/tsp-analyze.log`
