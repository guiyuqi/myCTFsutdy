# misc-日志的秘密

- 结果：💀 未解出
- 关联 run：run-107924｜合计 token ≈ 17.5M

## 题面 / 结论 / 可复用资产
**题面**：

```
一台 GW 网关从台架上拆下来，工作台上留着一份压缩包：12 个历史升级包、一份台架升级日志、
一份供应商说明，还有一个解不开的故障快照。
```

**run-107924 最后事实**：

- notes.txt 明确"口令算法无文档但 3 条记录足以验证一种猜测"；实测记录值非任何归档镜像在 10 变体×10 哈希下的摘要（含 hex/反转），即口令必须由 (name,image_sha256) 记录本身派生而非从归档镜像内容重建 本 Step 独立重解包（unzip -oq shared/extract/ota_bundle/packages/*.zip -d /tmp/w/pk/<名>）并通读说明文件，新增可判读结论： 1) 叙事约束（新，此前 Fact 未记录 notes.txt/codes.txt 原文语义）：notes.txt 三节关键句——"某些镜像原厂内置了维护入口，装上之后台架可以进入维护会话，用于导出故障快照"；"口令的算法没有对外文档，但那几条记录足够验证一种猜测是否成立"；"fault_snapshot.bin 是加密的，解开它需要维护口令"；"这台 GW 网关目前跑的是 1.4.2"。code
- 新阴性：口令不是 name/image_sha256/ts 的 1~3 段拼接在含 blake2b(digest_size=8)/shake/ripemd 未截断摘要族下的派生；0x100..0x104 与 offset-12 两个候选校验字段也都不是 (a,b)×zero/del/full 变体下 7 类哈希或 7 类 32 位校验的取值 本 Step 独立重解包（zipfile 解 packages/*.zip 到 /tmp/x/pk/<名>，12 个 payload 均在，sha256 前缀与 bench_history 一致；samples 与 fault_snapshot 直接读 shared/extract/ota_bundle/），只测前序 Fact 未覆盖的空间，结果 0 命中： 1) 新阴性（口令派生的“未截断摘要”家族，前序 Fact 004/006/010/014/015/019 用的都是 64/32 字节
- 新阴性：口令不是 name/image_sha256/ts 的 1~3 段拼接在含 blake2b(digest_size=8)/shake/ripemd 未截断摘要族下的派生；0x100..0x104 与 offset-12 两个候选校验字段也都不是 (a,b)×zero/del/full 变体下 7 类哈希或 7 类 32 位校验的取值 本 Step 独立重解包（zipfile 解 packages/*.zip 到 /tmp/x/pk/<名>，12 个 payload 均在，sha256 前缀与 bench_history 一致；samples 与 fault_snapshot 直接读 shared/extract/ota_bundle/），只测前序 Fact 未覆盖的空间，结果 0 命中： 1) 新阴性（口令派生的“未截断摘要”家族，前序 Fact 004/006/010/014/015/019 用的都是 64/32 字节

## 归档说明

- 原始事件流：`evidence/run-logs.tar.gz` 内 `run-107924.jsonl`
- 逐 run 详细摘要：`retrospective/digests/`
- 完整复盘：`retrospective/RETRO-2026-11-08.md`
