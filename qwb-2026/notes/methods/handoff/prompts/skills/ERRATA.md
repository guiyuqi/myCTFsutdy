# 本目录勘误（2026-10-24）

> 全量勘误见上级目录 `../../ERRATA.md` 的 **B1**。这里只记本目录的处置。

## 问题

本目录 9 个 `*.md` 的 frontmatter 都用了**顶层** `when:` / `bind_tools:` / `acceptance:` / `failure_modes:`。
核实结论（读 `@deepseek-ai/dsh-skill-filesystem` 的 `parseSkillFile`）：

- 加载器只取 `name`、`description`、`whenToUse`、`metadata`，外加两个 invocation 布尔值；
- **顶层未知键既不报错、也不保留**；
- `metadata` 本身会被保留，但**不会被校验或执行**。

后果：按原样装进 DSH，技能只剩"名字 + 一句话描述"，
`bind_tools`/`acceptance`（也就是 R6 的全部内容）**静默消失**——而且没有任何报错。

## 处置

| 文件 | 处置 |
|---|---|
| `_template.md` | 保留原写法（作为"为什么会以为是可用的"证据），顶部加了勘误说明 |
| `_template.dsh.md` | **新增**：可直接使用的正确版本（`whenToUse` + `metadata:`） |
| `timebox-park.md` | 加了两处标记：B1（frontmatter）由 `_template` 覆盖；另有 **A1**（"14:00–15:00 空窗"已被证伪，见 `../../ERRATA.md` A1） |
| `coverage-matrix.md`、`dual-path.md`、`judge-triangulation.md`、`local-replica.md`、`oracle-loop.md`、`submit-discipline.md`、`tool-plan.md` | **未逐文件改动**。内容本身没有本次查出的错误；只有 frontmatter 的 B1 问题，按 `_template.dsh.md` 一次性改写即可 |

## 要真正"强制执行"，还差一步

把 `bind_tools` 写进 `metadata` 只让契约**可见**，不让它**生效**。要生效只有两条路：

1. **`agent.ctx` 作用域**（推荐）：给 Solver 子代理的 ctx 注册一个**子集**工具——它根本看不见 `env.*` / `submit.flag`，比"调用了再拒"干净，也不会浪费轮次。
2. **`ctx.tools.guard()`**：单调守卫，排在 `tools/pre-execute` 之后，拒绝后不能被后续 listener 翻案。

单靠 SKILL.md 无法实现 R6。这一点原交接包没有意识到。
