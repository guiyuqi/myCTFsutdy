# 12083 · Lost_Memory（MISC / 内存-取证）

- **分类 / 分值 / 解出人数**: MISC 取证 / 500 / 我们首解（本队）
- **flag**: `We_wi1l_m3et_ag4in_a7_d4wn` ← **平台匹配的是裸串**（不带 `flag{}` 外壳！）
  - 磁盘里解出的明文写的是 `flag{We_wi1l_m3et_ag4in_a7_d4wn}`，带壳提交 **被拒**（40001），裸串 **解题成功**。
- **提交**: `{"code":"00000"?}` 实测 `message: 解题成功!`，`result: true`（台账 `evidence/submit-log.jsonl`）
- **工具**: ewfinfo / mmls / fls / icat / istat（TSK + libewf）、`sqlite3`、`git`（对象级恢复）、Python(`cryptography`/`PIL`)、自写 E01 偏移映射 `e01map.py`、自写 E01 切片 `rawslice.py`
- **SKILLS**: `ctf-forensics`、`competition-forensic-timeline`
- **SKILLS_USED**:
  - `ctf-forensics` 的"**文件系统定点取证优先于全量导出**"（fls/icat 按 inode 取、`fls -r -d` 列删除项、$OrphanFiles 恢复孤儿 MFT 记录）+ "**git reflog/fsck 恢复被清空仓库**" 两条判据直接落地：全部碎片都是靠这三条拿到的，64GB 镜像从未整盘 ewfexport。
  - `competition-forensic-timeline` 的"**用共享标识符跨源关联、已确认与推断分离**"落实为：用 `chip_id` 把 Chrome History → tracker.html → config.yaml 三处绑定，再用它作为 XOR 密钥打开消息库（碎片 3）。
- **坑**:
  1. **拼装串不是 flag，是钥匙**：`work_notes.txt` 的"核心记忆被锁…拼接+芯片ID 才能**唤醒**"被我漏读，把钥匙当答案提交了 2 次（`after_all_this_time_always_YA20180507` / `…_YA_20180507`）。
  2. **flag 外壳**：`背景故事.txt` 与描述都写 `flag{...}`，但平台按**裸串**比对。带壳 3 次全拒。
  3. **诱饵密集**：`flag{she_was_watching_me}`（git 提交消息 + `notes/decoy_note.txt`）、`core/quote.txt`（银翼杀手）、崩溃日志里《西部世界》台词，《星际穿越》台词——全部自带"不是 flag"声明。**看声明，别信形似**。
  4. **E01 未压缩**（`deflate level = none`）：头部 1623B 后按 32KB chunk + 4B CRC 可线性寻址（p1 `MSDOS5.0`、p3 `NTFS` 两点验证），但**高可压缩区被压缩后偏移会漂移**，p4 尾部用线性映射会读短；完整落盘后一律改走 TSK/libewf。
  5. **压缩包"能列目录≠能解"**：`Linxiao.zip` 是 ZipCrypto，`7z l` 可列名；无需等 20GB 解完即可 `7z e -p… '背景故事.txt'` 单取小文件提前读题。
- **解法**:
  1. `ewfinfo`/`mmls`：60GiB、GPT：EFI / MSR / NTFS 主盘(offset 239616) / 无名 637MB(=WinRE 恢复分区，**不是**芯片固件)。
  2. `fls -o 239616` 根目录 → `aiya_memory.dump`（448B，`Salted__`）+ `Users/LinXiao`(git 仓库) + `Users/Lin_xiao`(CompanyChat 消息库)。
  3. 碎片 1 `after` ← Chrome History 标题 / `temp/tracker.html`；碎片 2 `_all` ← git dangling blob；碎片 3 `_this` ← 消息库 id=89，**XOR 密钥 = 芯片 ID `YA_20180507`**；碎片 4 `_time` ← `Downloads/AIYA_crash_backup.log`（UTF-16LE）；碎片 5 `_always` ← 桌面 `final_memory.png` 的 **RGB bit0 顺序 LSB**。
  4. 芯片硬件编号：`config.yaml chip_monitor: YA_20180507` + `tracker.html`；描述"外壳分段只为读数、固件里连续" → 取连续形 `YA20180507`。
  5. 五片首尾相接（前导 `_` 已在 2~5 片内）→ `after_all_this_time_always`，同分隔符接硬件编号 → 作为**口令**，用 **PBKDF2-HMAC-SHA256(10000)/AES-256-CBC** 解开 dump（PKCS7 合法、UTF-8 可读），明文"雅的信"末尾即 flag。
- **产出**: `scripts/12083-solve.py`、`work/12083_lostmem/`（`decrypt_dump.py`/`e01map.py`/`rawslice.py`/`brute_dump.py`/`aiya_core_memory.txt`/`p3-alloc.txt`/`p3-deleted.txt`）
