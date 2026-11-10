# 子代理通用规则

你被分配**一道题**。只做这一道题。读完本文件 + `notes/briefs/<题号>.md` 再动手。

> 本文件只留**硬规则**。技能路由表在 `notes/methods/skill-routing.md`，
> 技法包在 `notes/methods/tech-packs.md`，平台事实在 `notes/methods/platform-current.md`。
> **先按题型 read 那张路由表，再动手**（这是强制动作，不是建议）。

---

## ★ 0.05 等待协议（违反 = 白烧墙钟）

**禁止在回合内用 `sleep` / 反复轮询外部状态来"等"。一个回合里出现第 2 个 `sleep` ⇒ 立即结束回合。**
（门禁插件会直接拒绝 `sleep`；别试。）

| 你在等什么 | ❌ 错误 | ✅ 正确 |
|---|---|---|
| 子代理跑完 | `sleep 30` 再问 | **结束回合**；完成事件会叫回你 |
| 后台 job | `sleep` 后 `job_list` | `job_output <id> --wait` |
| 容器就绪 | 循环 `env status` | `scripts/container-pool.py acquire` |
| 现在几点 | 凭记忆估 | `date +%H:%M:%S` |

> 依据：2026-10-24 羊城杯，turn 52 单回合 89 次调用里 41 次在"等"；13 个 >20 steps 的回合吃掉 50% 墙钟；
> 长轮询曾把 12:23 说成"12:40"（漂移 17 分钟）。

---

## ★ 0.06 负结论三重对照（写"不存在 / 不可解"之前必过）

任何**负结论**（不存在 / 不可解 / 无端点 / 未命中）落盘或提交前必须过三道，
**缺一条只能写"假设"**：

1. **正向对照**：把**已知为真**的样本喂给判据，判据必须判"真"（否则是扫描器坏了）。
2. **负向对照**：只改**一个**变量，看判据是否翻转（403 可能是权限，不是"路由不存在"）。
3. **外部反证**：读平台「**已答出 N 次**」。**N > 0 ⇒ 你的负结论必错**，回去补覆盖。

措辞收窄：写 **"在我枚举的 N 个候选里不存在"**，不写"不存在"。
**工具**：`python3 scripts/verify-flag.py verdict <题号> --claim not-exists`（N>0 直接拒）。

> 依据：本场 6 次"判死"全部被解出数推翻（12062/12079×2/12086/12073 + 一次假 SOLVED），每次返工 ~20 分钟。

---

## ★ 0.07 分诊与排序（入场 15 分钟决定本场分数）

**排序不是按分值**（本场 500 分的题解出数 0，200 分的题解出 7 道）。

```
优先级 = 类型清晰度 ÷ 预计验证轮次      （分值只在同清晰度内 tiebreak）
类型清晰度 := 我能不能在 5 分钟内写出第一条能证伪它的实验
```

1. **T-0 → T+15 粗分**：每题 30 秒，只填 `type / needs_env / 附件 / 第一条证伪实验`；
2. **T+15 立刻为 4 道（=槽位数）申请环境**，不等精分；
3. **硬停**：连续 2 轮（≤20min/轮）无新 artifact ⇒ 强制 park，写 `missing / next_action / revisit_at`。

---

## ★ 0. 第一步：加载技能（强制）

**动手前先 read `notes/methods/skill-routing.md`，按题型找到候选技能，用 `skill` 工具加载。**
加载后用 1–2 行说明该技能给出的**关键判据**（避免"加载了没读"）。

报告必须写 `SKILLS:` 与 `SKILLS_USED:` 两个字段（没匹配写 `SKILLS: none — <原因>`）。
> 依据：0xGame 2026 全程 skills 调用 0 次，隐写题把无效搜索空间跑穷才想到检查跨通道 LSB。

---

## 0.1 硬性边界（违反即任务失败）

1. **不攻击比赛平台**：只允许提交 flag 与起停**你自己题目**的容器；禁止扫描/枚举/fuzz。
2. **不暴力枚举 flag**：平台上限每题 50 次，本地按"可复现才提"执行；**猜写法一次都算浪费**。
3. **只碰分配给你的目标**：动态地址只访问 brief 里那一个 host。
4. **★ 空转检测**：**连续 5 次工具调用没有新证据**（新文件/新符号/新偏移/新日志结论）⇒
   换一条**本质不同**的路线，或写 `BLOCKED: <卡在哪 + 已排除什么 + 需要什么>` 回报。
   **"跑了很多步"不是进度。**
5. **★ 中途回报**：每确认一组独立事实就立刻按 §4.1 短格式回报；超过 10 分钟无回报且
   `work/<题号>_*/` 无新文件 → 父代理判定失联。卡住时把 `NEXT:` 换成 `STUCK:`。
6. **不装东西**：不 `pip install` / `npm install` / 改 `~/re-tools/`、`~/.dsh/`、`/usr`、`/etc`。
   要装 → 在报告里写「需要人类批准安装 X」。

---

## 1. 环境

```bash
source ~/re-tools/fw-env.sh     # 每次开工第一句
cd ~/ctf-2026
```

- `fw-decompile <target> 40` → C 伪代码落到**当前目录**的 `decompiled/`。⚠️ 多代理共享工作区，
  **先 `cd work/<题号>_*/` 再跑**；**不要在有隐藏目录的 cwd 下跑**（Ghidra 拒绝 `.` 开头的路径元素）。
- `web-probe <url> -o evidence/xxx` → 真实浏览器抓 DOM/请求/cookie/截图；`pwpython` 写 playwright。
- 字典 `~/re-tools/wordlists/seclists/`；`jadx`/`apktool`/`adb`/`frida` 已装。
- **移动/UE 题先跑** `python3 scripts/mobile-static.py <apk> --textures`（本机无 KVM，模拟器不可用）。
- 目录约定：草稿 `work/<题号>_<短名>/`；成品 `scripts/<题号>-solve.py`；笔记 `notes/<题号>-<题名>.md`；证据 `evidence/<题号>-*`。

---

## 2. 提交 flag

```bash
python3 scripts/verify-flag.py check <题号> '<flag>' --evidence <来源文件> --agent <你的名字>
# 退出码 0 才允许提交；然后：
CTF_AGENT=<你的代理名> python3 scripts/ycb.py submit <题号> '<flag>'
```

- **`ycb.py submit` 会校验一次性票**（由 `verify-flag.py check` 产出）；无票即拒。
- 平台**只收 `{}` 内裸串**；`40001` = flag 错（会回报剩余次数）；**`40401`/`403`/`401` 不是 flag 错**
  （先查 token / matchId / 阶段未开）。
- 同题失败满 2 次 ⇒ 停手回报父代理；`--force` 只有父代理/人类能决定。

---

## 3. 动态环境（brief 里 `需要容器: True`）

**只能通过 `scripts/container-pool.py`**（唯一写者；直接 `ycb.py env` 会被拒）：

```bash
python3 scripts/container-pool.py acquire <题号>   # 就绪后给 URL
python3 scripts/container-pool.py release <题号>   # 用完立刻释放
```

- 槽位上限开局实测（本场 4 台）；**用完立刻 release**，占着做离线检索是最贵的浪费。
- `check-exercise-env` 的 `data:false` **无判别力**；就绪判据见 pool 内部实现。

---

## 4. 最终报告格式（必填）

```
FLAG: <flag 原文，或 NONE>
SUBMIT: <平台返回的 code/msg 原文，或 NOT_ATTEMPTED>
CONFIDENCE: <high|medium|low>
EVIDENCE: <关键证据一句话 + evidence/ 里的文件路径>
SKILLS: <加载的技能名列表，或 "none — <为什么没有匹配>">
SKILLS_USED: <该技能给出的哪个具体判据真被用上了；加载未用写 "loaded but unused — <原因>">
NOTES: notes/<题号>-<题名>.md
BLOCKED: <若未解出，一句话说清卡在哪；需要人类做什么>
```

拿不到 flag 也要写清卡点和已排除方向，不要空手回来。

### 4.1 中途回报格式（长任务必用）

```
FACT: <一句话结论，带数字/地址/偏移>
EVIDENCE: <evidence/ 或 work/ 下的文件路径>
NEXT: <下一步做什么>
```
卡住时把 `NEXT:` 换成 `STUCK: <已排除什么 + 需要什么>`。**三条以内**，不贴命令原文。
