# GEELY DELTA FORGE（attachments5.zip）

- **flag**: `GEELY{DELTA_801198DDD1CF0B93_D390327DAF554E2C}`
- 出处: `ecu_delta_container.bin` 12 条真实补丁链 + `MANIFEST` 密钥解密
  `base_image.bin[0x1F00:0x1F60]` 得到的 manifest：
  `DELTA|12|GEELY{DELTA_801198DDD1CF0B93_D390327DAF554E2C}|`（0xA5 padding，40 字节）
- 附件: `firmware/attachments5.zip` sha256 `1c9c...`（见 evidence/forge-verify.log）
- 解题脚本: `scripts/forge_verify.py`（clean-room，逐字节独立复算）
- 证据: `evidence/forge-verify.log`

## 协议还原（forge_protocol.txt 描述 + 实测修正）

```
块内密钥流 = SHA256(FAMILY || parent_id || uint16be(S)) 重复
container   = 记录向量：uint16 BE payload length + payload（共 20 条）
真实补丁 plaintext:
  +00 EC 4F                magic
  +02 offset uint16 BE
  +04 op uint8             A0 overwrite / A1 xor / A2 add mod256 / A3 rotl
  +05 length uint8         data 长度
  +06 data[length]
  +06+len chain hint uint16 BE
  +08+len checksum uint8       <-- 整条长度 = 9+len
链接: S=1 用 ROOT ID；之后 parent_id = SHA256(FAMILY||image_after||uint16be(S))[0:8]
      chain hint  = 同一摘要 [0:2]
MANIFEST_KEY = SHA256(FAMILY || base_image[0:0x1F00] || uint16be(12) || "MANIFEST")
                = 888210bfaa24a284e4149f23cf9aab79a7bb6387967baee0e06c0776454f57a4
manifest = base_image[0x1F00:0x1F00+0x60] XOR (MANIFEST_KEY 重复)，再去掉尾部 0xA5
```

### 两处文档与实现不一致（解题卡点）

1. **checksum 实为 8-bit SUM mod 256，不是文档写的 XOR**
   （rec0 明文 `ec4f1951a3010331a724`：XOR=0xdc 不符，SUM=0x24 = 字段值）。
2. **整条记录长度为 `9 + length`**（文档 `+08+len checksum`），
   若按 `8+len` 解析会全部判废。

### 链条结果（唯一解，已逐 seq 断言 1 个候选）

| seq | 记录 idx | offset | op | data |
|---|---|---|---|---|
| 1 | 0 | 0x1951 | A3 rotl | 03 |
| 2 | 3 | 0x1EE0 | A2 add | 21ef4c407475 |
| 3 | 4 | 0x0EC0 | A0 overwrite | aa298e534b |
| 4 | 6 | 0x060E | A3 rotl | 01 |
| 5 | 8 | 0x0B28 | A1 xor | 50bd2f613c |
| 6 | 9 | 0x0E68 | A2 add | 31835b621d9fb1 |
| 7 | 10 | 0x053A | A2 add | d507 |
| 8 | 11 | 0x0E44 | A3 rotl | 04 |
| 9 | 12 | 0x0202 | A3 rotl | 03 |
| 10 | 14 | 0x00F0 | A2 add | cb14ca |
| 11 | 16 | 0x1099 | A3 rotl | 03 |
| 12 | 17 | 0x1B33 | A0 overwrite | 26d3d77ddd54 |

- 诱饵记录: idx 1, 2, 5, 7, 13, 15, 18, 19
- final image sha256 = `771cc12691d6e5b922e788f3e161e291cc753c7ac473a442c2bcc5f01c5d43db`

## 远程服务 <target>:33221（`nc`）状态

框架：请求/响应均为 `uint32 BE length || body`；body[0] 为状态（00 ok / 01 err）。

| op | 行为 |
|---|---|
| 01 | 返回 `00` + 48 字节随机（每次/每连接都不同） |
| 02 | 检查 `arg[-32:]`，返回 `0001`（通过）/ `0000`；无状态（跨会话 token 也通过）；随机 32B 通过率 ≈ 1/256（4000 次 15 次通过） |
| 03 | 恒返回 `01 "denied"`；给 ROOT ID / final parent / MANIFEST_KEY / flag / manifest 等 27 组候选均为 denied |
| 其它 | `01 "unknown opcode"` |

结论：该服务未提供 flag；flag 完全来自附件离线推导（manifest 明文内含 flag）。
远程 op2 的 1/256 判定与 op3 的认证条件未再深挖（无必要）。

## 关键命令

```bash
mkdir -p work/forge && cd work/forge && unzip -o ../../firmware/attachments5.zip
cd ~/ctf-2026 && python3 scripts/forge_verify.py | tee evidence/forge-verify.log
```
