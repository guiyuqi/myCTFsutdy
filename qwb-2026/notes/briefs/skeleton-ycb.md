【任务 <id> · <题名>】→ 详见 `python3 scripts/ycb.py detail <id>`
【先读】`notes/briefs/RULES.md` 的 **§0（技能路由）/ §0.0（本届平台）/ §0.1（硬性边界）/ §4（报告）/ §4.1（短回报）**
【平台】DASCTF `ycb-bk.dasctf.com`，比赛号 1750。**题要你自己拉**（父代理不贴原文）：
```bash
cd ~/ctf-2026 && source ~/re-tools/fw-env.sh
python3 scripts/ycb.py detail <id>        # 先读描述、flag 格式、靶机字段
python3 scripts/ycb.py download <id>      # 附件 → firmware/<id>_<slug>/
```
【技能】<技能名 1>、<技能名 2>　←　动手前用 `skill` 工具加载，并**用 1–2 行说明该技能给出的关键判据**
【意图·去重键】目标 <拿到什么>｜范围 <只碰哪个附件/哪个 host>｜方法 <怎样算解出>
【flag 格式】<按题目描述明示；禁硬套前缀>
【纪律】
① 每确认一组事实立即回报 `FACT:` / `EVIDENCE:` / `NEXT:`（卡住换 `STUCK:`）；不要攒到最后
② 连续 5 次工具调用无新证据 → 换**本质不同**路线，或报 `BLOCKED`
③ 不自行装包（缺工具写报告里）；不碰平台接口做扫描/fuzz；只访问本题靶机
④ **容器**：先 `ycb.py env status <id>` 看有没有；要起先跟父代理要槽位，**用完立刻 `env stop`**
⑤ **提交额度每题 50 次（队内共享）**：拿到**可复现** flag 才提，**不要猜写法**；
   `CTF_AGENT=<你的代理名> python3 scripts/ycb.py submit <id> '<flag>'`，
   脚本拒提（退出码非 0）立即停手并上报；`--force` 不许自己加
⑥ 报告格式（缺一不可）：
```
FLAG: <flag 原文 或 NONE>
SUBMIT: <平台返回原文 或 NOT_ATTEMPTED>
CONFIDENCE: <high|medium|low>
EVIDENCE: <一句话 + evidence/ 路径>
SKILLS: <加载的技能名>
SKILLS_USED: <技能里哪个具体判据真被用上；没用到写 loaded but unused — 原因>
NOTES: notes/<id>-<题名>.md
BLOCKED: <卡在哪 + 已排除什么 + 需要什么>
```
