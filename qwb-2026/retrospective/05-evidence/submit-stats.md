# 提交台账统计（赛后复核）

> 数据源：`evidence/submit-log.jsonl`（749 行，全部经 `scripts/qwb.py submit`）。生成本文件时现场重算。

| 项 | 值 |
|---|---|
| 提交总数 | **749** |
| 判为正确 | **3**（4yUAPAGmS0zRzdjp, KVlvgNuOwJXPAyAQ, ZvAQO9Mw5mvCyfj8） |
| 判错（`答案错误`） | **509** |
| 限流（`太过频繁`） | **235** = 223 条 `kind=throttle,result=null` + **12 条被误记成 `kind=param,result=false`**（都在 vmshare） |
| 网络失败 | 1 |

## 按题目

| 题号 | 提交数 |
|---|---|
| `KVlvgNuOwJXPAyAQ` | 477 |
| `brz2pZwJzt8gV8r6` | 268 |
| `4yUAPAGmS0zRzdjp` | 2 |
| `9999` | 1 |
| `ZvAQO9Mw5mvCyfj8` | 1 |

## 三条复盘要点（数字支撑）

1. **火力极度集中**：749 条里 745 条只打在 2 道题（CMB 477 / vmshare 268），其余 39 道题几乎没有提交尝试。
2. **限流≠判错，犯了两次**：CMB 220 条 `result=null`（正确串就在里面，靠 `work/cmb-redo.py` 重提第 5 条命中）；vmshare 12 条被写成 `result=false`，任何按 `result=false` 去重的扫描器都会把它们当"已判错"。
3. **大小写/书写先验**：官方 vmshare 写法 `flag{3174812_31af718}` 在台账里 **0 次**；被判错的是 `flag{3174812_31AF718}`（只差大小写）。
