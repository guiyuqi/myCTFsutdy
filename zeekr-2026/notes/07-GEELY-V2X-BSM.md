# GEELY V2X — BSM 伪名证书私钥复用 (attachments.zip)

- flag: `GEELY{V2X_898cafad25db5e3fc74a1364_c7df2614b26ca968f35eba0b}`
- 出处: `firmware/attachments.zip` → `evidence/v2x_session.jsonl` frame1/frame2 的 ECDSA nonce 复用
- 附件 sha256: `6eca41d69a1fa8371d0a6d9181f8bb80d6ed8b482ca9cd940c52a84cde5d3a0e` (attachments.zip)
- 关键命令: `python3 scripts/v2x_solve.py`
- 证据: `evidence/v2x-solve-run1.log`、`work/v2x/solve-result.json`

## 题目结构

`GEELY V2X SIGNED MESSAGE PROFILE / REVISION 2`，包格式：

| 偏移 | 长度 | 字段 |
|---|---|---|
| +00 | 4 | magic `GEVX` |
| +04 | 1 | version = 02 |
| +05 | 1 | cert_id_length = 08 |
| +06 | 8 | certificate_id（`25 61` 寄存器 + `00 00` 保留 + 4 字节 serial） |
| +0E | 2 | TBS 长度（BE，0x86 = 134） |
| +10 | 1 | 签名长度 0x40 = 64 |
| +11 | 64 | ECDSA P-256 签名 `r‖s` |
| +51 | var | TBS（纯 ASCII 文档，SHA-256 后直接验签，无 transcript hash） |

三帧均为 215 字节，TBS 为 `GEELY-V2X-TBS\npsid=…\ntimestamp=…\nlat=…\nlon=…\nheading=…\nsequence=…\nevent=BSM\n`。

## 关键发现

1. **nonce 复用**：frame1 与 frame2 的 `r` 完全相同
   `372320da87b676c3b0ecde94cd6d68133791487df6daf368917e028de7959e8b`，
   而 TBS（⇒ hash）不同 ⇒ 两帧共用了同一个 k。frame3 的 r 不同，是另一把密钥。

2. **同一私钥映射多个伪名证书**（题面所述"私钥被映射到多个伪名证书"）：
   `pseudonym_bundle.pem` 里 A31F 与 B47D 的 SubjectPublicKeyInfo 逐字节相同
   （`04 432f55d8…acb1`），C92A 的是另一把（`04 117f0913…1939`）。
   与 `evidence/revocation_schedule.txt` 中被 suspended 的两张证书（A31F、B47D）一致。

3. **本地重算确认**：恢复出的 `d·G` == A31F/B47D 证书内公钥；且 `k·G` 的 x 坐标 == 复用的 `r`。

## 解题步骤

1. 解析 `v2x_session.jsonl` 三帧，取出 `cid / r / s / TBS`，算 `h = SHA-256(TBS)`。
2. 找相同 `r` 的两帧（frame1、frame2），非复用时：

   ```
   k = (h1 - h2) / (s1 - s2)  mod n
   d = (s1 * k - h1) / r      mod n
   ```

   ```
   k = 5915f44e2ef21ba6974ada4ed6af818ca28fc2cd4c147f3dc97513697772cf86
   d = 4b04c9f2dc7b53f87b8a0752b9ec9f391edc760379baf1a41dfc4a1c062be59b
   ```

3. 用 `d` 复现两帧签名（含 `cryptography` 库独立验签）→ 均 OK；`d·G` 匹配 A31F/B47D 公钥。
4. 按 profile 组 TOKEN：

   ```
   TOKEN = SHA-256( ASCII("GEELY-V2X-KEY-RECOVERY")
                  || d (32B BE)
                  || cid1 (8B) || cid2 (8B)      # 升序
                  || SHA-256(DER(root CA cert)) )
   ```

   - 两个 cid（升序）：`256100002561a31f`、`256100002561b47d`
   - `SHA-256(DER(CA)) = 36402f9ce95bfe19bd64c64a318825686c8a11587307fb50e087f367179512c8`
   - `TOKEN = 898cafad25db5e3fc74a1364a99811b10f2830abc7df2614b26ca968f35eba0b`

5. 编码 flag（token 前 24 hex + 后 24 hex）：

   ```
   GEELY{V2X_898cafad25db5e3fc74a1364_c7df2614b26ca968f35eba0b}
   ```

## 复用要点

- 三帧里 `r` 撞了就是 nonce 复用，直接出私钥，不用碰证书链之外的密码学。
- 私钥漏在"同一 SPKI 出现两次"上：先 diff `pseudonym_bundle.pem` 的公钥字节，
  锁定共同密钥的那两张证书，再用它们的证书 ID 组 token。
- token 里的证书 ID 必须是**升序**的 8 字节；`25 61`(authority register) 也要一起带上，
  不能只取 4 字节 serial。
- frame3（C92A，valid）是干扰项，拿它算 `d` 得到的是错误值。
