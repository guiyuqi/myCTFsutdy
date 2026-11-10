---
name: <skill-id>
description: <一句话：何时用>
when: "<触发条件：题型/现象>"
bind_tools: [<工具动词白名单>]
acceptance: [<2–4 条可判定的中间态>]
failure_modes:
  - {symptom: "<现象>", fix: "<处置>"}
---

> ⚠️ **勘误 2026-10-24（B1）：这个模板本身上面的写法在 DSH 上不可用。**
> `dsh-skill-filesystem` 只读取 `name` / `description` / `whenToUse` / `metadata`（外加两个 invocation 布尔值）；
> 顶层 `when` / `bind_tools` / `acceptance` / `failure_modes` **既不报错、也不保留**——技能装进去只剩名字和一句描述。
> 可直接使用的版本见同目录 **`_template.dsh.md`**（把这些字段放进 `metadata:`，`when` 改成 `whenToUse`）。
> 本文件保留原来的写法，是为了记住"为什么当时以为是可用的"。

## 做法（可执行步骤）

1. …
2. …

## 判据

- 成功 = …
- 失败 = …

## 本场实例

- <题号>：…

## 反例（不要做）

- …
