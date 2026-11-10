# iov-重生的种子

- 结果：✅ 解出
- 关联 run：run-37596｜合计 token ≈ 15.0M

## 题面 / 结论 / 可复用资产
**题面**：

```
某车型 BCM-A3 在产线做诊断密钥灌注。7 月 14 日工位电源,出现连续电压跌落，之后出现了灌注记录异常。BCM 的私钥在灌注后写入安全存储，从未导出。我们从产线工装恢复了这次灌注使用的 OTA 固件包。请你分析异常，获取flag。
```

**run-37596 最后事实**：

- 75B payload 的标准 AEAD/流密码解密（以 K3/K9/K14、m、s 编码、全部16个tag/ek/ct、config 字段为密钥的多布局扫描）全部失败，排除"直接 KDF 后标准 DEM"路线 本轮（campaign A g7）实测增量，均为阴性但有界，避免后继重复。 1) 已在共享事实基础上继承：槽 3/9/14 共享同一 s/e，已恢复 s（768 系数 |c|≤2）、三槽 m/K，且 reencrypt c'==ct 已验证（fact_008/009）。本轮用这些真值搜索 payload 解密。 2) 扫描范围（payload=75B，取自 work/diag.pkl）： 密钥源：K3/K9/K14、m3/m9/m14、ct3/ct9/ct14、ek3/ek9/ek14、tag3/tag9/tag14、全部 16 个 keylog ek、全部 16 个 handshake ct/tag、s 的编码（s_c
- 独立复核 tag 公式成立并固化三故障槽 K_fin 真值；75B payload 的"密钥材料直接作 XOR 流/计数器流"路线有界排除（0 命中） 本轮（bootstrap/campaign A g8）实测增量，脚本 /tmp/x1.py、/tmp/x2.py（一次性，逻辑内联在下方，依赖 kyber-py 1.2.0 装于 /tmp/kpylib：`pip download kyber-py==1.2.0 -d /tmp/kd --no-deps && pip install --target /tmp/kpylib /tmp/kd/*.whl`；Crypto 3.23.0 可用）。 1) 独立复核 fact_010 的 ACK 公式：K_fin = SHAKE256(K || SHA3-256(ct), 32)（K/m/ct/ek 取自 shared/known3.pkl info），tag == HMAC-SHA256
- 独立复核 K_fin/HMAC tag 公式(3/3 True)并固化三槽 K_fin；新增 1.01M 组 AEAD + 151×14 种流密码扫描（含 ts、s/e 编码、三槽 K_fin 拼接/XOR）仍未解出 75B payload 本轮（campaign A g9）实测增量，脚本落盘 shared/brute_g9.py（依赖 kyber-py 1.2.0 已重装于 /tmp/kpylib 但本脚本只用 Crypto/hashlib/pickle；输入 work/diag.pkl、shared/known3.pkl、shared/se.pkl）。 1) 独立复核（正向）：用 known3.pkl 的 K/ct 重算 K_fin=SHAKE256(K‖SHA3-256(ct),32)，并算 HMAC-SHA256(K_fin, b"BCM/DIAG/ACK/v1")，槽 3/9/14 全部严格字节相等（3/3 True）

## 归档说明

- 原始事件流：`evidence/run-logs.tar.gz` 内 `run-37596.jsonl`
- 逐 run 详细摘要：`retrospective/digests/`
- 完整复盘：`retrospective/RETRO-2026-11-08.md`
