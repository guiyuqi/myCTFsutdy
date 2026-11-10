---
name: coverage-matrix
description: 用矩阵枚举替代字典爆破
when: "Web/协议入口发现；或"扫了很多都 404"之后"
bind_tools: [net.probe, web.js]
acceptance: ["维度清单", "命中判定器", "扫描器自检记录"]
failure_modes:
  - {symptom: "只扫单段前缀", fix: "显式枚举一二三段前缀组合"}
  - {symptom: "把 405/500 当不存在", fix: "只有 404 且 body 是框架 not-found 才算不存在"}
---

## 做法

1. 定维度：`前缀 {/, /api, /api/v1, /api/<service>}` × `方法 {GET,POST,OPTIONS}` × `Host {原名, localhost, 127.0.0.1}` × `Content-Type` × `认证态`。
2. 先跑"已知命中"的样本，确认扫描器能记到。
3. 每轮 ≤300 请求、单 keep-alive、300ms 间隔；响应变慢即停。

## 判据

- 只有 `404` + 框架 not-found 模板才算"不存在"；`405/500` 一律算"存在"。
- 两段式/三段式前缀必须出现在矩阵里（本场 `12086` 的正门就是 `/api/federation/log`）。
