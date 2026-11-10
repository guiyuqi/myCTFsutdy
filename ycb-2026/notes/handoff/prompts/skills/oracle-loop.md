---
name: oracle-loop
description: 把服务端回包变成一个"对/错"判定器，用它驱动搜索
when: "有回显但不确定语义；或需要二分/增量搜索时"
bind_tools: [net.probe, challenge.send]
acceptance: ["oracle 定义（输入→正确/错误）", "单变量实验记录"]
failure_modes:
  - {symptom: "同时改多个参数看回包", fix: "每次只改一个"}
  - {symptom: "把 401 当被拦", fix: "用返回合法结构的 payload 区分'被拦'与'执行但抛错'"}
---

## 做法

1. 找到能区分状态的字段：错误文案、长度、状态码、布尔字段、时间差。
2. 固定其它变量，只改一个；记录"改了什么 → 回包怎么变"。
3. 用 oracle 做二分（长度/字符/偏移），而不是枚举。

## 本场实例

- 12063：`ledger[0x48]` 单点 oracle 定两层 hash 布局。
- 12086：submit 的 `reason` 文案切换 = 阶段推进判据。
- 12064：`eval` 返回合法 dict 得 200 ⇒ 证明反序列化真的执行了（而不是被拦）。
