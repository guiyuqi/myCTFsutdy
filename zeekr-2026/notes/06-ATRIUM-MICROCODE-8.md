# ATRIUM-MICROCODE-8 (attachments.zip)

- flag: `GEELY{ATRIUM_007C1B66052D3321_86B3F3C6DBDD9B5C}`
- 出处: `work/attachments/firmware/atrium_boot.bin` → lane table 解密 → VM 程序输出 key → manifest @0x1C00 XOR 解密
- 附件 sha256: `6d2555ff95868c5df62a7fa4bacc94b4a73b504e5dd66773d471e3987d49f508`
- 关键命令: `python3 scripts/atrium_solve.py`
- 证据: `evidence/atrium-solve-run1.log`

## 题目结构

`ATRIUM PROTOCOL / REVISION 8`，镜像 0x2000：

| 区域 | 偏移 | 说明 |
|---|---|---|
| lane table | 0x1000 | 16 lane × 0x100 stride，仅 6 个 valid |
| manifest | 0x1C00 | 0x60 字节，repeating-KEY XOR 加密 |

Lane record（`+000` masked chunk 0x20 / `+020` lane_id u16be / `+022` status /
`+023` reserved / `+024` seed u32be / `+028` crc32 u32be / `+02C` "ATRM"）：

```
LANE_MASK = SHA256("ATRIUM-MICROCODE-8" || u16be(lane_id) || u32be(seed) || "ATRIUM-LANE")
unmasked  = masked XOR LANE_MASK
valid ⟺ status==0x6D && reserved==0xC3 && marker=="ATRM" && crc32==CRC32(unmasked)
```

## 解题步骤

1. **过滤 lane**：16 个 lane 里只有 6 个通过四项校验（status/reserved/marker/crc32），
   与 protocol 的 `VALID LANES 6` 一致。lane#8~#15 连 marker 都不是 `ATRM`，是伪造项；
   lane#6/#7 的 marker 和 crc 对但 status/reserved 错，属于"损坏 lane"。
   > 注意：crc 校验必须用 **mask 后的 unmasked chunk** 算，这是区分真伪的关键。

2. **排序拼接**：按 `CRC32(unmasked)` 升序排 6 个 lane，chunk 依次拼接 → 正好 0xC0 字节 VM 程序。

3. **跑 VM**：R0..R5 = 有效 lane 的 lane_id（0xBE1F, 0x3C4D, 0x7A8B, 0x5E6F, 0x9C0D, 0x1A2B），
   R6..R15 = 0。指令 2 字节：`byte0=[opcode(4)|dst(4)]`，`byte1=[src(4)|imm(4)]`。
   执行 192 字节，OUT 恰好吐出 **32 字节 = KEY**：

   ```
   KEY = 007c1b66052d332186b3f3c6dbdd9b5c 5ceb50b4eadce3efd1faa763eceb87eb
   ```

4. **解 manifest**：0x1C00 起 0x60 字节与 KEY 循环 XOR：

   ```
   ATRIUM|GEELY{ATRIUM_007C1B66052D3321_86B3F3C6DBDD9B5C}|<0xA5 padding>
   ```

   去掉 0xA5 padding 得 flag。

## 复用要点

- VM 里 OUT 的低字节序列就是 key；先跑 VM 拿 key 再解 manifest，不要先去猜 manifest。
- lane_id 同时是"mask 参数"和"VM 初值寄存器"，两边必须一致。
