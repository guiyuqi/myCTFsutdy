# AM3flsrbnudME5TM · frozen（Crypto）

- 平台：872 队解出（快照 2026-11-01 11:52）；我方状态：平台已解出（队友提交，我方无 submit-log 正确记录）
- flag：未在本地记录（`evidence/submit-log.jsonl` 无本题任何一行；我方**从未提交过任何 flag**，不编）
- 性质：四道题里**唯一有实质我方工作**的一题，但**工作未拿到真 flag**；真 flag 与最终解法在队友处。

## 我方实际做了什么

我方代理做过一条**独立的离线复现线**（未申请容器、未连远程、未提交），产物全在可丢弃的 `work/frozen/`：

- **题目语义**（`work/frozen/notes.md`）：附件 `task.py` 是 Falcon/NTRU 方向，`N=128, q=12289, sigma≈19.16`；
  `flag = flag XOR keystream(sha256("frozen:"+D))`，`D = f·adj(f)+g·adj(g)` 只依赖私钥。
- **自己推出的关键代数关系**：`memory` 里 Falcon LDL 树的 `G00 = |fft(f)|²+|fft(g)|² = fft(D)`
  ⇒ 被腐蚀的树**直接泄漏 sha256 的原像 D**，反 FFT 即得 `D`；**不需要 NTRU 格攻击、不需要公钥 `h`、不需要还原 `f/g`**。
- **腐蚀结构定位**：`corrupt_blob` 对 float64 的 bit∈{0..55,63} 独立翻转（`rho10=0.01`/`rho01=0.001`），
  bit56–62（指数高位）永不改；26.6% 的 double 有位翻转，但仅 12.1% 显著，其中 **99.2% 恰好 1 个 bit**。
  `head=8*128` 砍掉前 1024 个 double（`fh,gh,Fh,Gh`），只剩树 2304 doubles。
- **实测成绩**（`work/frozen/bench5.py`，20 实例）：clean blob **3/3** 精确还原（0.1 s）；
  真实 `rho=0.01` 下 **16/20**，平均 **0.98 s**、最大 **18.2 s**。
  判据：`solve.recover(mem, ct)`；无 ct 时用全树重放率（正确 D ≈ 0.78–0.85，错误 ≈ 0）。
- **端到端"解出"的只是本地 keygen-lite 自造的测试串（本地自定内容），不是本题真 flag**——勿当 flag 用。
- **卡点**（`work/frozen/handoff3.md`）：4 个失败实例 seed **2006/2010/2011/2014** 都在 `n=4/16/32` 某一层
  "选到残差小但整数错"的解；现行 widening 只枚举单 dof + 前 80 个 dof 对，`nd>=2` 的真值仍可能不在候选集。
- **下一步（未做）**：widening 换成**逐层 beam search**（每层留 top-W，用子树重放 + 该层残差打分），
  或对 `nd>=2` 的 dof 用全并集（108）交分块 MITM。
- **环境限制**：本机无 fpylll，直接 `import task.py` 会失败 ⇒ 用 `work/frozen/fw.py` 截断 exec + stub，
  本地 keygen-lite 伪造 F,G（`G00` 只依赖 `f,g`，故 `_T(G00)` 部分统计与真实例一致）。

## 交接口径

需队友（提交者待补：平台未按题拆开，`team/INDEX.md` 记「本队队员提交（提交者待补）」，彭艺棋/丁枫洳本轮各 +1）提供：
1. **真 flag 原文**（或脱敏后半段 + 长度）——我方台账该题 0 条，无原文不能把 `notes/FLAGS.md` 改记已解出；
2. **`ycb.py submit` 的 `result:true` 回包**，或平台答案页截图（唯一凭证，口头说法不算）；
3. **一句话解法链路**：是否也走的 `G00=fft(D)` 反 FFT？若非，我方这条线仅作独立归档，不再投入；
4. **提交者与提交时间**（平台 `is_solved=true`，solved_time 10-31 14:56:06）；
5. 容器内做了什么（若起过容器：镜像 `eci_2026qwb_frozen`，题面与附件均为空）。
拿到后：回填 `evidence/submit-log.jsonl` 一条并注明「队友账号提交」，再改 `notes/FLAGS.md`。

## 证据

- `work/frozen/notes.md`（语义 + 关键关系）、`work/frozen/handoff.md`、`handoff2.md`、`handoff3.md`（结论与失败清单）
- `work/frozen/solve.py`（stdin 三行 `pubkey`/`memory`/`flag`）、`dec2.py`（分层 + widening）、`mitm3.py`（分块 MITM）、`bench5.py`（20 实例基准）
- `work/frozen/task.py`（原附件副本）、`fw.py`（无 fpylll 的 stub 加载器）
- `team/frozen/README.md`（叙事）、`team/frozen/EVIDENCE.md` §5
- **`evidence/` 下本题 0 个文件、`submit-log.jsonl` 0 条** —— 全部产物在 `work/`，未上提为 `evidence/`（这是我方的真实缺口，不是遗漏可忽略）
