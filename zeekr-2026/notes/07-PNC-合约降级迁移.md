# PnC 合约降级迁移（Plug & Charge schema v001）

- **flag**: `GEELY{PNC_3784e057d579d4f778055b8c_294421b6eb8d1959d6c70d69}`
- **附件**: `firmware/attachments1.zip`
  sha256 `eb643190c81d01a2debc03c4ac0b9b15035e6fd861d6e8274e5f8f75e44f8f0d`
- **被接受的记录**: `CH-100688` @ 2026-02-24T02:31:15Z, 站 `GCPS-BJ-0071`
- **解题脚本**: `scripts/pnc_tbs_bruteforce.py`, `scripts/pnc_solve.py`
- **产出**: `work/pnc1/result.json`

## 漏洞点

桩端兼容层在历史 `schema v001` 文档**缺少可选约束字段**时套用固定默认值：

| 缺失字段 | 兼容默认值 |
|---|---|
| `max_current_a` | `250` |
| `price_plan` | `PUBLIC_UNMETERED` |
| `authorization_scope` | `PnC-START-MAINTENANCE` |

默认值被当作**配置**而非签名数据，因此签名仍验证通过，但授权范围被静默放大
（`PnC-START-USER` → `PnC-START-MAINTENANCE`），即降级攻击（downgrade）。

## 关键步骤

1. **证书链**：`ev_contract_cert` ← `mobility_operator_ca` ← `v2g_root_ca`
   三级 ECDSA P-256 签名全部验证通过；合约证书 CN `PNC-EV-VIN-LGEGF1V29PX000002`，
   有效期 2025-01-01 ~ 2027-01-01，覆盖所有记录时间。

2. **恢复 TBS 格式**（`tbs_sha256` 作预言机）：
   在 14540 个候选格式中唯一自洽解（7 条记录全部命中）= 前缀 `GEELY-PNC-TBS\n`
   + 按 `signed_fields` 顺序的 `key=value\n`（含尾换行）。

3. **逐条验签**：7 条记录签名与 TBS 哈希**全部有效** —— 桩端验签本身没问题，
   所以不能靠验签筛掉攻击记录，必须靠**前置条件**筛选。

4. **筛选**：要求 `MIGRATE` + `PARKED_CONNECTED` + `SESSION_ESTABLISHED`
   + 签名有效 + 证书当时有效 + 合约匹配。
   - `CH-100753` `DRIVING` ✗、`CH-100810` `COMMUNICATION_LOST` ✗
   - `CH-100512` 合约 `PNC-OTHER-999` ✗
   - `CH-100944` 也满足前置条件，但它是 **v003**（字段齐全，不触发兼容默认值）
   - ✅ **`CH-100688`** —— 唯一 `v001`，缺 3 个可选字段，正是降级路径

5. **算 CODE**：
   ```
   SHA-256( SHA-256(DER(合约证书)) || SHA-256(TBS) ||
            "PNC-DOWNGRADE-ACCEPTED" || "max_current_a=250" ||
            "authorization_scope=PnC-START-MAINTENANCE" )
   ```
   - `SHA-256(DER(cert))` = `59288f12fff4ca25879d728cfad7dbee34b3f1edb94f06d1fde0782b7076267c`
   - `SHA-256(TBS)` = `707277c144847fc7c771ffaa59732f979f9a3569f0ffc0dab6deed1cf53f24a2`
   - `CODE` = `3784e057d579d4f778055b8ca230a46537acec2e294421b6eb8d1959d6c70d69`

## 编码判定

PROFILE 只给字符串字面量加了 `ASCII(...)` 包装，`SHA-256(...)` 未包装 → 摘要按
**原始 32 字节**拼接。同批次 `attachments.zip`（V2X 题）的 TOKEN 公式同样显式标注
`32 bytes` / `8 bytes` / `SHA-256(DER(...))`，编码风格一致，佐证该读法。

> 备选（十六进制字符串拼接）得到
> `GEELY{PNC_1d61041a42ecc76cfdaa5e66_6876f8a53b8a58c325d37295}`，非首选。

## 复现

```bash
python3 scripts/pnc_tbs_bruteforce.py   # 恢复 TBS 格式
python3 scripts/pnc_solve.py            # 验签 + 出 flag
```
