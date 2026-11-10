---
name: local-replica
description: 靶机稀缺/脆弱时，把服务链在本地复刻出来
when: "多服务/多跳协议；或每试一次都要占容器"
bind_tools: [env.ensure, bash]
acceptance: ["本地能复现一段输入→输出", "复刻与远端行为对照记录"]
failure_modes:
  - {symptom: "直接改二进制导致段错误", fix: "用附件自带 ld-linux --library-path . 跑"}
  - {symptom: "socket 路径写死绝对路径", fix: "等长替换成相对路径再起"}
---

## 做法

1. 先写最小 mock（单接口/单命令）。
2. 需要多服务时：等长替换 socket 路径（`/run/x/x.sock` → `s/b.sock`）、资源路径改短、自带 loader 起链。
3. 本地故意造"假 flag/假文件"，用来验证**读链**是否通（与远端行为分离）。

## 判据

- 本地跑通的那一段，其常量/偏移/协议必须与远端一致；不一致就写进 ledger（可能是部署差异）。

## 本场实例

- 12073：5 服务复刻（broker/manifestvault/keeper/oracle/xmlbridge），40 分钟搭成，之后协议试验零成本。
