# iov-Autopilot

- 结果：💀 未解出
- 关联 run：run-2703728｜合计 token ≈ 10.9M

## 题面 / 结论 / 可复用资产
**题面**：

```
iov-Autopilot
场景地址:
nc <target> 33233
```

**run-2703728 最后事实**：

- 目标已迁到 <target>:33499 且是新实例: 33233 拒连, OTA/V2X 密钥按实例重建, 已恢复本实例 OTA 私钥并 PUT flags=1 工程包成功 本 Step 全为真实往返/静态核对，增量（与 fact_001..010 不重复）： A) 地址/端口变更（关键操作性事实） - 旧地址 <target>:33233 现为 ConnectionRefusedError；Operator 给出的 <target>:33499 可用（`FILE\0\0` 正常返回 475B FLST）。 - 33499 是**全新实例**：SOME GetObjectList 返回 count=0（objects.bin 已重置，无 0xbeef 幽灵对象）；OTA 列表仍为 fw_base.ota/fw_1.ota/fw_2.ota/pubkey.txt；OTA 三个包的 48B 密文与旧实
- 静态确认 fusion_node 中 FUSION_KEY 仅被死代码打印函数引用(无其他用途), .bss 对象区恰好 0x30000; 13 个猜测 SM4 工程密钥均解不出可读 OTA 明文 本 Step 为静态核对 + 有限实测，增量如下（与前 Fact 不重复）： A) fusion_node 对 FUSION_KEY 的引用面已完整枚举（静态，字节级） - 全二进制仅两处引用 .bss 0x403af0（FUSION_KEY 的 16 字节存放处）：0x4011b4（main 启动时把环境变量 FUSION_KEY 的 hex 解析进 0x403af0）与 0x401e02（0x401de0 的 "KEY:" 打印函数）。 - 0x401de0 在 .text 中无任何 call/jmp 引用；.init_array 只有 0x4015b0；方法分派表 0x402060 的 8 个条目分别指向 0x401bef(ER
- 静态确认 fusion_node 中 FUSION_KEY 仅被死代码打印函数引用(无其他用途), .bss 对象区恰好 0x30000; 13 个猜测 SM4 工程密钥均解不出可读 OTA 明文 本 Step 为静态核对 + 有限实测，增量如下（与前 Fact 不重复）： A) fusion_node 对 FUSION_KEY 的引用面已完整枚举（静态，字节级） - 全二进制仅两处引用 .bss 0x403af0（FUSION_KEY 的 16 字节存放处）：0x4011b4（main 启动时把环境变量 FUSION_KEY 的 hex 解析进 0x403af0）与 0x401e02（0x401de0 的 "KEY:" 打印函数）。 - 0x401de0 在 .text 中无任何 call/jmp 引用；.init_array 只有 0x4015b0；方法分派表 0x402060 的 8 个条目分别指向 0x401bef(ER

## 归档说明

- 原始事件流：`evidence/run-logs.tar.gz` 内 `run-2703728.jsonl`
- 逐 run 详细摘要：`retrospective/digests/`
- 完整复盘：`retrospective/RETRO-2026-11-08.md`
