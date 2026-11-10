# 工作项交接模板（换人或换会话时必填）

```
item: <题号> <题名>
state: <打通到第几跳 / 缺哪一环>
acceptance: [x] a  [x] b  [ ] c
missing: <缺哪条原语/哪个数据（不是"难"）>
next_action: <下一轮第一件事，可执行动词>
artifacts: <绝对路径…>
env: <url / expires_at / 是否 ghost>
budget: wall=<已用/总> conns=<已用/总>
风险: <最可能失败的方式>
```

规则：
- 不写"我觉得/大概/应该"；只写证据与下一步。
- 换人时先读 `next_action`，不要重跑旧路。
- 三分钟内能接手，否则说明交接不合格。
