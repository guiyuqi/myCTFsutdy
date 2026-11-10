# 版本控制：这个库是干什么的

> 建于 2026-10-25（羊城杯赛后）。基线标签 `baseline-20261025`。

## 为什么不是"备份"

备份回答"怎么回到昨天"，版本控制回答**"这场比赛到底改了什么"**——后者才是我们要的。

赛季里的真实场景：`AGENTS.md` 被精简、`RULES.md` 被砍、`platform-current.md` 被整篇重写。
**没有 diff，你只能凭记忆说"我好像改过这条"**；有 diff，你能看到

```
git diff pre-<comp>..post-<comp> -- AGENTS.md
```

——一个赛场把一个提示词从 346 行砍到 110 行，砍掉了哪几条、为什么砍，全在 diff 里。
这就是"内化"的物证。

## 跟踪什么、不跟踪什么

| 入库 | 原因 |
|---|---|
| `AGENTS.md`、`notes/` | 规则与方法：每场都会改，diff 就是复盘 |
| `scripts/` | 工具：改坏了要能退回去 |
| `plugins/` | 门禁：行为变了要能对比 |
| `skills/local/` | 自己写的技能（`upstream/` 由安装脚本拉取，不入库） |

| 不入库 | 原因 |
|---|---|
| `firmware/` `work/` `decompiled/` | 题目原件与草稿；赛后在 `~/self/ctf/<comp>/` 归档 |
| `evidence/` `ghidra-proj/` | 本场证据与项目文件，同理随场归档 |
| `.config/` `.dsh/` | 工具缓存与索引（5.7M+），删了能重建 |
| `*.env` `creds*` | **凭据永不入库** |

## 三条命令够用

```bash
git status                    # 现在改了什么（干净=没改）
git diff                      # 具体改了哪几行
git log --oneline -10         # 最近的提交
```

## 一场比赛的正常流程

```bash
# ① 开赛前：打一个"开赛点"标签（这样赛后能精确对比这一场的所有改动）
git tag pre-<comp>            # 例：git tag pre-dasctf-1750

# ② 赛中：只在一处稳定下来之后提交，别一边解一边 commit
git add -A && git commit -m "赛中: 补 XXX 平台的容器语义"
#    —— 注意：commit 时不要粘贴 flag 原文（见下面「三条禁令」）

# ③ 赛后：提交 + 打标签 + 看这场教了我们什么
git add -A && git commit -m "赛后: <comp> 复盘沉淀"
git tag post-<comp>
git diff --stat pre-<comp>..post-<comp>      # 改了哪些文件、多少行
git diff pre-<comp>..post-<comp> -- AGENTS.md notes/methods/   # 逐行看
```

## 改坏了怎么退

```bash
git diff HEAD -- AGENTS.md            # 先看清改了什么
git checkout -- AGENTS.md             # 整篇退回上次提交
git checkout -p notes/methods/        # 按 hunk 逐块挑选要退的部分
git log --oneline -- scripts/ycb.py   # 这个脚本谁改过、什么时候
git show <sha>:scripts/ycb.py > /tmp/old.py   # 取出某个历史版本对比
```

## 三条禁令

1. **不提交 flag 原文、token、cookie。** 台账里有 `<FLAG>{}` 占位可以，真值不行。
   本库不打算公开，但"不公开"不等于"可以写"——一次误提就是永久的。
2. **不提交 `firmware/` 里的题目附件。** 它们已被 ignore；`git add -f` 也不行。
3. **不在赛中 rebase / 强推。** 赛中只做 `add` + `commit`；整理历史留到赛后。

## 自检

```bash
git status --short            # 应为空（除正在做的改动）
git tag -l                    # 应有 baseline-20261025 与各场 pre-/post- 标签
```
