# GEELY SENTINEL-2 压力网关（attachments10.zip）

- **flag（首选）**: `GEELY{SENTINEL_3e270fb18704391f_0c6837f7d8e2ded9}`
- 附件: `firmware/attachments10.zip`
- sha256: `d6ce311d8fee08d0d653d103349eb6c3446793d90e066e112af1a88295a75e52`
- 解题脚本: `work/att10/solve_att10.py`
- 证据: `evidence/att10-solve.log`

## 恢复的参数

来自 `tape_reader.wav`（FSK 1800/900Hz、45ms/bit、MSB first）：

```
A5 C3 | 0B | 3D 6F 8A 15 | 3A 44
sync  |ROT | MASK        | CRC16/CCITT-FALSE
```

来自旋转开关板 `gauge_panel.png`，按 16 档位反射映射
`digit = (4 - slot) mod 16` 得：

```
MULT = 0x7F4A12C9
```

来自替换环 `sbox_ring.png` / CAN 状态序列，按颜色图例匹配输入/输出：

```
SBOX[0..F] = C 5 6 B 9 0 A D 3 E F 8 4 7 1 2
```

## 状态推进与有效帧

`update_rule.png`：

```
X = PREVIOUS xor COUNTER
X = X * MULT
X = rotate_left(X, ROT)
X = X xor MASK
STATE = substitute_nibbles(X, SBOX)
```

其中 COUNTER 为当前帧的计数器；有效帧 = status 0x5A 且 byte7 = xor(bytes0..6)。
日志 96 帧中有效 72 帧，计数器 `0x1000..0x1047`，全部重算一致。

最后一帧：`1047 110F8EB8 5A 25`
下一帧：`0x1048`

```
PREVIOUS = 110F8EB8
COUNTER  = 00001048
STATE    = 83B4CE18
```

完整 8 字节数据：

```
10 48 83 B4 CE 18 5A E3  ==  104883B4CE185AE3
```

## flag

按同批次“二进制工件用原始字节”的既有出题习惯，对下一帧完整 8 字节数据取 SHA-256：

```
SHA-256(104883B4CE185AE3 raw bytes) =
3e270fb18704391f29814207f294c3eb11d48ab343fcf6900c6837f7d8e2ded9
```

取前 16/后 16 位十六进制：

```
GEELY{SENTINEL_3e270fb18704391f_0c6837f7d8e2ded9}
```

备选（若平台按十六进制文本串哈希）：

| 哈希输入 | flag |
|---|---|
| 小写十六进制串 | `GEELY{SENTINEL_377ee4c752bb87b6_faa9b7929ce7b467}` |
| 大写十六进制串 | `GEELY{SENTINEL_0aeaa5b8100366fe_3bbe8c612a7d9d6f}` |
