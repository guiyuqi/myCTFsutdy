# iov-猎隼折翼

- 结果：💀 未解出
- 关联 run：run-35254｜合计 token ≈ 14.6M

## 题面 / 结论 / 可复用资产
**题面**：

```
实验室抓到一次签名密钥展开的功耗轨迹，并用“全系数相同”的克隆密钥做 profiling
```

**run-35254 最后事实**：

- 实测: fpylll 0.6.4 可在本环境装回, 但 fact_021 的 1024 维 NTRU 朴素基在 LLL(method=fast) 下抛 ReductionError "infinite loop in babai"; 格攻击仍未取得结果 承接 fact_021 的"格攻击 pk"建议, 本 Step 只完成环境复核与判据实跑尝试(未取得 LLL 结果, 不对 pk 真伪下任何结论): 1) 环境复核: 当前 python3 为 3.14.4, 起始无 fpylll; `pip install --break-system-packages fpylll cysignals` 实测成功(fpylll 0.6.4 + cysignals 1.13.1, cp314 wheel), `import fpylll` 正常 → 1024 维整数格 LLL 在本机可跑(与 fact_021 一致)。 2) 新实测(工程性,
- A 模板对 |v|≤7 单射、仅 |v|≥8 为 8 元歧义; 且四个 128 窗象限各自都含 3~11 个 |v|≥8 窗(含无 B 精修的象限), 故"每 bank 512 系数"读法本质上无法精确解码 本 Step(独立 root campaign A)实测增量, 输入 shared/prev-analysis/diag_{trace,profiles,pk}.bin, 脚本 mywork/{a1,q,ntru512}.py: 1) A 模板(5 位尖峰图样, 位置 {4,10,16,22,28})的可分性精确边界: 值与码的对应表逐条打印后确认 —— 对 |v|≤7 模板**完全单射**(-7..-4→(4,22,28), -3,-2→(4,22), -1→(4,28), 0→(10), 1→(28), 2,3→(22), 4..7→(22,28)), 而 |v|≥8 只有两个码: (16,)→+8..+15 与 (4,
- A 模板对 |v|≤7 单射、仅 |v|≥8 为 8 元歧义; 且四个 128 窗象限各自都含 3~11 个 |v|≥8 窗(含无 B 精修的象限), 故"每 bank 512 系数"读法本质上无法精确解码 本 Step(独立 root campaign A)实测增量, 输入 shared/prev-analysis/diag_{trace,profiles,pk}.bin, 脚本 mywork/{a1,q,ntru512}.py: 1) A 模板(5 位尖峰图样, 位置 {4,10,16,22,28})的可分性精确边界: 值与码的对应表逐条打印后确认 —— 对 |v|≤7 模板**完全单射**(-7..-4→(4,22,28), -3,-2→(4,22), -1→(4,28), 0→(10), 1→(28), 2,3→(22), 4..7→(22,28)), 而 |v|≥8 只有两个码: (16,)→+8..+15 与 (4,

## 归档说明

- 原始事件流：`evidence/run-logs.tar.gz` 内 `run-35254.jsonl`
- 逐 run 详细摘要：`retrospective/digests/`
- 完整复盘：`retrospective/RETRO-2026-11-08.md`
