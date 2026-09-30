# 35 · signin（Reverse，494 分，31 解出）

- **flag**: `0xGame{0pen_1DA_4nd_start_y0ur_reverse_Engineering!}`
- **提交**: `{"code":200,"msg":"OK","data":{"result":true}}` ✅
- **附件**: `firmware/35_signin/signin.zip` → `signin.exe`
- **模式**: 离线题，无容器
- **成品脚本**: `scripts/35-solve.py`
- **工作目录**: `work/35_signin/`

## 结论

flag 由 PE 中 `reference_data`（VA `0x4040a0`，52 字节）逐字节 `XOR 0x5A` 得到。

## 分析过程

1. `unzip` → 单文件 `signin.exe`。
   `file`: `PE32+ executable for MS Windows 5.02 (console), x86-64, 15 sections`
   （MinGW-w64 编译，带 `.debug_*`，但 debug_info 只覆盖 libgcc，不含题目源码）。
2. `strings` 一眼看到可疑明文：
   `0xGame{0pen_1DA_4nd_start_y0ur_reverse_Engineering!}`，
   紧接着还有一坨 `;7?!j*?4`、`4=34??(34={'%127s` —— 典型的"异或表"特征。
3. `objdump -d -M intel signin.exe > dis.txt`，定位 `<check_input>` @ `0x401550`：

   ```
   401598: cmp    DWORD PTR [rbp-0x4],0x33    ; i <= 0x33  → 52 字节
   40159c: jle    401565
   401565: mov    eax,DWORD PTR [rbp-0x4]
   401568: cdqe
   40156a: mov    rdx,QWORD PTR [rbp+0x10]    ; input buffer
   40156e: add    rax,rdx
   401571: movzx  eax,BYTE PTR [rax]          ; input[i]
   401574: xor    eax,0x5a                    ; ★ 异或 0x5A
   401577: mov    ecx,eax
   40157e: lea    rdx,[rip+0x2b1b]            ; 0x4040a0 <reference_data>
   401585: movzx  eax,BYTE PTR [rax+rdx*1]    ; reference_data[i]
   401589: cmp    cl,al
   40158b: je     401594                     ; 相等 → i++, 全过返回 1
   40158d: mov    eax,0x0                    ; 否则返回 0
   ```
4. `<main>` @ `0x4015a9` 先用 `scanf("%127s", buf)` 读入，
   `strlen(buf) == 0x34`（52）才进 `check_input`，否则打印 `Wrong length!`。
5. 取 `0x4040a0` 起 52 字节，逐字节 `^0x5A`：

   ```
   6a221d3b373f216a2a3f34056b1e1b056e343e05292e3b282e05236a2f2805283f2c3f28293f051f343d33343f3f2833343d7b27
   ```
   → `0xGame{0pen_1DA_4nd_start_y0ur_reverse_Engineering!}`（恰好 52 字符 ✅）

## 关键命令

```bash
source ~/re-tools/fw-env.sh
cd ~/ctf-2026/work/35_signin
unzip -o ../../firmware/35_signin/signin.zip -d .
file signin.exe
strings -n 6 signin.exe | head -90          # 看到异或表 + 明文
objdump -h signin.exe                        # 段表：.rdata off=0x2400 va=0x404000
objdump -d --no-show-raw-insn -M intel signin.exe > dis.txt
grep -n "4040a0\|check_input" dis.txt
python3 ../../scripts/35-solve.py            # XOR 0x5A 还原 flag
```

## 踩坑记录

- `strings` 里那行明文 flag 一开始被当成 decoy（典型签到题会放假 flag），
  但核对 `check_input` 后发现：明文出现在 `0x404060`，而比较表在 `0x4040a0`，
  两者内容等价 —— 这题没做反调试，明文就是真 flag。**仍以异或表为准**，因为它是校验逻辑的真正依据。
- 提交时 `challenge_id` 传 `int(35)` 曾返回
  `400 type mismatch for field "challenge_id"`，重试一次即 `200 OK`（服务端偶发校验抖动，
  同批次其他题的提交也出现过一次同样抖动）。**不是 flag 错误**，不要因此改 flag 重试。

## 证据

- `evidence/35-check_input-disasm.txt` —— `check_input` 反汇编（含异或逻辑）
- `examples/` 无需；`scripts/35-solve.py` 自带 round-trip 断言，可直接复现
