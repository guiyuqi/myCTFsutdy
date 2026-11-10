---
name: <skill-id>
description: <一句话：何时用>
whenToUse: "<触发条件：题型/现象>"
metadata:
  bind_tools: [<工具动词白名单>]
  acceptance: [<2–4 条可判定的中间态>]
  failure_modes:
    - {symptom: "<现象>", fix: "<处置>"}
---

> 本文件是 `_template.md` 的**可用版本**（勘误 B1）。字段差异只有三处：
> ① `when` → `whenToUse`（加载器只认这个名字）；
> ② `bind_tools` / `acceptance` / `failure_modes` 移到 `metadata:` 子对象里（顶层未知键会被静默丢弃）；
> ③ `description` 保持顶层（它是唯一会进入技能目录的一句话）。
>
> **重要限制**：`metadata` 只会被**保留**，不会被**强制执行**。
> `dsh-skill-filesystem` 把 `metadata` 原样交给消费方，自己不做任何校验。
> 所以"越界调用工具被拒"这件事，靠 SKILL.md 做不到，只能靠：
> - `agent.ctx` 作用域——子代理根本看不见白名单外的工具（推荐，最硬）；
> - 或 `ctx.tools.guard()`——单调守卫，拒绝后不能被后续 listener 翻案。
>
> 也就是说：这个模板解决的是"契约不被静默丢弃"，不解决"契约被强制执行"。

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
