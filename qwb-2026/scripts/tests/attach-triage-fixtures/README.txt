本目录 = `scripts/attach-triage.py` 的**自测样本**，不是比赛附件。

- 生成方式：7z/zip 造的加密样本（密码 Pass123 / Inner9）、嵌套样本（nest_outer.zip → nest_inner.7z）、
  1x1 PNG、`/usr/bin/true` 副本当 ELF 样本。
- 用途：验证"开赛才给密码"这条链路：格式识别 → 加密判定（头加密 vs 仅内容）→ 带密码解包 → 嵌套递归。
- 证据：`evidence/attach-triage-smoke.log`（2026-10-23 实测，含每个样本的 enc/OK/FAIL 行）。
- 里面的 `FLAG{smoke}` 是**假 flag**，任何 flag 汇总都不要采信本目录。

真实附件请放 `firmware/`（只读），然后：

```bash
python3 scripts/attach-triage.py                       # 先分诊（无密码，只判格式/加密）
python3 scripts/attach-triage.py --password '<开赛给的密码>'   # 一键解包（含嵌套 2 层）
```
