# iov-静默译码

- 结果：💀 未解出
- 关联 run：run-40288｜合计 token ≈ 17.0M

## 题面 / 结论 / 可复用资产
**题面**：

```
某车型中央网关 GW-A1 的 V2X 安全会话使用的加密算法存在缺陷，请你从固件中进行分析并获取flag。
```

**run-40288 最后事实**：

- 补齐"泄漏向量=HQC 秘密分量"的除法方向（h·y=s⊕v_i 与 s·x=h⊕v_i 均无 weight-16 解），并否定"稀疏向量位置/朴素 XOR keystream 直接编码 flag" 本 Step（campaign A g22）实测增量（数据 shared/prev-analysis/diag/，LSB-first；脚本 w22/gfpoly.py、w22/gfsolve2.py）： 1) 新覆盖的除法方向（此前 fact_011 只测了乘法方向 weight(s⊕h·v_i)、weight(h⊕s·v_i)）： - 环 GF(2)[X]/(X^1153+1)：因 weight(h)=582、weight(s)=574 均为偶数，(X+1) 同时整除 h、s，故 h 与 s 都**不可逆**；对 h 的线性系统实测 rank=1152、nullity=1，零空间恰为 {0, 全 1 向量(1153 ones)}（
- 用纯 Python 无进位乘法（int 位运算，非 numpy）独立复核 pk/session 代数关系：h·r_i⊕r_j 不等于 h/s，s⊕h·v_i 权重 592/576/558，与旧结论一致（numpy 单元值缺陷未污染这些判定） 本 Step 实测（数据 shared/prev-analysis/diag/{0_pk,1_session,3_payload}.bin；n=1153，GF(2)[X]/(X^1153−1)，循环卷积用 Python 大整数移位异或实现，完全不经过 numpy）： 1) 复核口径：h=bit0..1152（权 582）、s（权 574）、session 三向量各权 16；payload 75B = 4c0f710b67347c6c…f765d2d9（首字节 0x4c，末 3 字节 65 d2 d9），与该 diag 记录一致。 2) 独立复核的三条否定（比旧事实更强的依据，因为 fact_
- 用纯 Python 无进位乘法（int 位运算，非 numpy）独立复核 pk/session 代数关系：h·r_i⊕r_j 不等于 h/s，s⊕h·v_i 权重 592/576/558，与旧结论一致（numpy 单元值缺陷未污染这些判定） 本 Step 实测（数据 shared/prev-analysis/diag/{0_pk,1_session,3_payload}.bin；n=1153，GF(2)[X]/(X^1153−1)，循环卷积用 Python 大整数移位异或实现，完全不经过 numpy）： 1) 复核口径：h=bit0..1152（权 582）、s（权 574）、session 三向量各权 16；payload 75B = 4c0f710b67347c6c…f765d2d9（首字节 0x4c，末 3 字节 65 d2 d9），与该 diag 记录一致。 2) 独立复核的三条否定（比旧事实更强的依据，因为 fact_

## 归档说明

- 原始事件流：`evidence/run-logs.tar.gz` 内 `run-40288.jsonl`
- 逐 run 详细摘要：`retrospective/digests/`
- 完整复盘：`retrospective/RETRO-2026-11-08.md`
