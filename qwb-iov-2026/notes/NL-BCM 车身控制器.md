# NL-BCM 车身控制器

- 结果：✅ 解出
- 关联 run：run-363803, run-35187｜合计 token ≈ 3.6M

## 题面 / 结论 / 可复用资产
**题面**：

```
试验台上有一块虚构的 NL-BCM 车身控制器。附件 `BCM_UPDATE.fwpk` 是车间升级包，里面是这台控制器正在执行的同一份闪存，但是做了封装。控制器按这份闪存里的机器码处理诊断请求。
```

**run-363803 最后事实**：

- 服务端 <target>:32783 使用 ISO 13400 DoIP 协议，车辆识别与路由激活已实测通过 实测结论（Python socket 直连，静默监听、无 banner，必须按 DoIP 帧格式发才响应）： 1) FWPK 文件头（前 32 字节，小端）：magic "FWPK" | hdr_len=0x20 | payload_len=0x1e065 (=122981 = 文件总长 123013-32) | 0x13572468（疑似层标识）| 0xeeadd93e（疑似 CRC/校验）| load_addr=0x08000000（Cortex-M4 flash 基址）| 0x1258 (=4696, 疑似第一层/引导区长度) | 0。payload 整体熵 7.78~7.85 bits/byte（全段加密/压缩，无任何明文字符串，`strings` 仅 "FWPK"），因此不改包无法直接解出固件。 2)
- 服务端 UDS 服务集与 SecurityAccess 门槛已实测：0x23 读内存恒 NRC 0x13，0x27/0x01 仅扩展会话返回 5 字节随机种子；FWPK 头第 5 字段为 payload 的 CRC32 实测（2026-11-08，复现脚本 shared/bcm/doipcli.py、shared/bcm/scan.py）： 1) DoIP/UDS 已固化为可复用原语：路由激活 SA=0x0E00 → 响应 0e00 00e1 10 00000000，即 ECU 逻辑地址是 **0x00E1**（此前 fact_001 把 0x0E00 当作目标地址有误，0x0E00 是测试仪源地址）。UDS 帧 = payload type 0x8001 + [SA 2B=0E00][TA 2B=00E1][UDS]；响应 payload 同样以 4 字节 SA/TA 前缀（00E1 0E00）开头。 2) SID 枚举：支持
- 服务端 UDS 服务集与 SecurityAccess 门槛已实测：0x23 读内存恒 NRC 0x13，0x27/0x01 仅扩展会话返回 5 字节随机种子；FWPK 头第 5 字段为 payload 的 CRC32 实测（2026-11-08，复现脚本 shared/bcm/doipcli.py、shared/bcm/scan.py）： 1) DoIP/UDS 已固化为可复用原语：路由激活 SA=0x0E00 → 响应 0e00 00e1 10 00000000，即 ECU 逻辑地址是 **0x00E1**（此前 fact_001 把 0x0E00 当作目标地址有误，0x0E00 是测试仪源地址）。UDS 帧 = payload type 0x8001 + [SA 2B=0E00][TA 2B=00E1][UDS]；响应 payload 同样以 4 字节 SA/TA 前缀（00E1 0E00）开头。 2) SID 枚举：支持

**题面**：

```
试验台上有一块虚构的 NL-BCM 车身控制器。附件 `BCM_UPDATE.fwpk` 是车间升级包，里面是这台控制器正在执行的同一份闪存，但是做了封装。控制器按这份闪存里的机器码处理诊断请求。
```

**run-35187 最后事实**：

- 服务 32783 接受 TCP 但不应答任何探测输入；同主机 32784/22 亦开放；工作区无 fwpk 附件 实测（本地 python socket + /dev/tcp 探测，2026-11-08）： 1) 工作区无题目附件：`inputs/`（by-name、objects）为空，manifest.json 的 inputs 为 []，全盘未找到 BCM_UPDATE.fwpk；因此升级包只能从服务端/其他途径获取，不能假设本地已有。 2) `<target>:32783` TCP 三次握手成功（nc -vz 报 succeeded），连上后服务端在 10s 内不发送任何字节（无 banner/提示），也不主动关闭。 3) 向 32783 发送 b''、b'\n'、b'\r\n'、b'help\n'、b'A'*4096 后，各等待 2–4s 均获得 0 字节回包，连接保持（无 EOF、无 RST）；即服务端在等
- 端口 32783 是 DoIP（ISO 13400）服务：路由激活成功，UDS 经 payload type 0x8001 可达并返回 0x7E00 实测（2026-11-08，脚本 shared/a/doip_a.py）： 1) 32783 不是明文协议，而是 DoIP。帧头 = 02 FD | payload_type(u16 BE) | payload_len(u32 BE) | payload。明文/单字节/HTTP/TLS 探测全部 0 字节无响应（解释了此前 fact_001 的“不应答”）。 2) 车辆识别请求：pt=0x0001，payload `0e 00 80 01 00 00` → 响应 pt=0x0004，len=0x21，payload = ASCII `NLBC1FA704F42700B`(17B, VIN) + `00 E1`(逻辑地址 0x00E1) + 12 字节 0x02(EID/GID 填充
- 端口 32783 是 DoIP（ISO 13400）服务：路由激活成功，UDS 经 payload type 0x8001 可达并返回 0x7E00 实测（2026-11-08，脚本 shared/a/doip_a.py）： 1) 32783 不是明文协议，而是 DoIP。帧头 = 02 FD | payload_type(u16 BE) | payload_len(u32 BE) | payload。明文/单字节/HTTP/TLS 探测全部 0 字节无响应（解释了此前 fact_001 的“不应答”）。 2) 车辆识别请求：pt=0x0001，payload `0e 00 80 01 00 00` → 响应 pt=0x0004，len=0x21，payload = ASCII `NLBC1FA704F42700B`(17B, VIN) + `00 E1`(逻辑地址 0x00E1) + 12 字节 0x02(EID/GID 填充

## 归档说明

- 原始事件流：`evidence/run-logs.tar.gz` 内 `run-363803.jsonl, run-35187.jsonl`
- 逐 run 详细摘要：`retrospective/digests/`
- 完整复盘：`retrospective/RETRO-2026-11-08.md`
