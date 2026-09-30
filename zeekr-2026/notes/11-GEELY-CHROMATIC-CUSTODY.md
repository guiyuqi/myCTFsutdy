# GEELY CHROMATIC CUSTODY (attachments7.zip)

- flag: `GEELY{80e4bf16c0cd763f6c9bf3220af0fe6b37729e7ff7042b54f131ba41f747f69b}`
- 附件 sha256:
  - `firmware/attachments7.zip` `???` (to record)
- 平台: Chromatic Custody / task id 388，平台已接受该 flag。

## 关键步骤

1. front/rear 板上各有 128 个数据环，排成 16 行 × 8 列；黑色三点为定位 fiducial。
2. fiducial 配准得到 rear→front 相似变换（旋转约 4.37°，平移约 +58/-32）。
3. 每格环分大/小两种状态；front 与 rear 大环=1、小环=0，逐位 XOR。
4. 密钥（row0 byte0, left col bit7）:
   `2b9811754604d2c8c40268e21e903777`
5. custody record 按板上字段顺序用 `|` 拼接:
   `overlay-custody|LGXFE4SB8N2077653|1790412800`
6. `HMAC-SHA256(key=密钥, msg=record)`:
   `80e4bf16c0cd763f6c9bf3220af0fe6b37729e7ff7042b54f131ba41f747f69b`
7. 平台提交成功（`code:1`）。
