# 49 · ez_flower

- **flag**: `0xGame{WoW_Th3_f1ow3r$_@re_SOo0oo b3@u7ifull!!}`
- **提交结果**: `code=200 msg=OK result=true`（1 次提交成功）
- **分类**: Reverse / 833 分 / 8 人解出 / 离线题
- **附件**: `firmware/49_ez_flower/attachment6.zip` → `flower.exe` (PE32 console, i386, 87552 B, ImageBase `0x400000`)

## 一句话结论

`flower.exe` 里的校验函数被三处**花指令**（junk code）打乱，还原控制流后可见：
程序对输入做**凯撒 +7（仅字母）**，与 `.rdata:0x40f170` 处 47 字节、
`^0x80` 后的常量块比较。把该常量块 `^0x80` 再做凯撒 **−7**，即得 flag。

## 关键步骤

### 1. 识别

```
flower.exe: PE32 executable for MS Windows 6.00 (console), Intel i386, 4 sections
```

`README_player.txt` 直接给了线索：

- 程序里有**三处花指令**，垃圾字节分别是 `11 22 33`、`44 55 66`、`12 34 56`；
- 提示字符串和加密目标**不会直接出现在 `strings` 中**；
- flag 加密是**简单凯撒，字母移动 7 位**。

### 2. 花指令形态（本例很好还原）

三处都是同一模板：**永真条件跳转 + 跳转跨越若干垃圾字节**。

```asm
00401069  33c0            xor  eax, eax      ; ZF=1
0040106b  7403            je   0x401070      ; 恒成立
0040106d  112233          <junk>             ; 11 22 33  被跳过
00401070  fc              cld                ; 真实代码从这里继续
```

所以：

- **线性反汇编（capstone 顺序扫）会在 `0x40106f` 处错位**，把 `33 fc` 解成 `xor edi, esp`
  ——这就是"花"的效果；
- **不需要 patch 二进制**：只要在遇到 `jcc` 时**优先递归进入跳转目标**，
  或在跳转后跳过垃圾字节，控制流即自动恢复（我在脚本里靠手工读跳转目标完成）。

三组垃圾字节的验证（脚本内自动断言）：

```
junk-code groups found: ['112233', '445566', '123456']
  0x40106d `11 22 33`  ← 函数 0x401060（凯撒函数）入口
  0x401110 `44 55 66`  ← 函数 0x401100（主校验）入口
  0x40111a `12 34 56`  ← 同函数第二处
```

### 3. 字符串表：整表 XOR 0x5A（含 0x00 终止符）

`.rdata:0x40f1a0` 起是 XOR 0x5a 的表。**密钥就存在紧邻的前一字节
`0x40f19f`**（`movzx ecx, byte ptr [0x40f19f]` @ `0x401029`，值为 `0x5a`）。
连 NUL 终止符也被 XOR 成 `0x5a`，所以 `strings` 只看到乱码：

解密后：

```
0x40f1a0  "Input flag: "             ; 长度 0x0c
0x40f1ac  "Inpuh Error."             ; 原文如此（"Input" 的 t 被打成 h），长度 0x0b
0x40f1b8  "Correct! The flower has bloomed."   ; 长度 0x20
0x40f1d8  "Wrong flag."              ; 长度 0x0b
```

它们被 `0x401000`（`xor` 后 `printf`）打印，调用点 `0x40112f / 0x401174 / 0x401255 / 0x401272`
——与上面的长度 `0xc / 0xb / 0x20 / 0xb` 完全对应，交叉验证了字符串表解读正确。

### 4. 还原后的校验逻辑（`0x401100`）

```c
printf_obf("Input flag: ");              // 0x401000, XOR 0x5a
fgets(buf, 0x80, stdin);                 // 0x4041ce
for (i = 0; buf[i] && buf[i] != '\r' && buf[i] != '\n'; i++) ;   // 0x401197..0x4011d4
buf[i] = 0;
if (i != 0x2f) goto wrong;               // 0x4011dc: 输入必须恰好 47 字符
                                             // 且长度是最多 0x2f，故无 NUL 截断

caesar_shift(buf, tmp, 0x2f);            // 0x401060 —— 见下
for (i = 0; i < 0x2f; i++)
    want[i] = g_target[i] ^ 0x80;        // 0x4011fe/0x401208, g_target @ 0x40f170
if (!strncmp(tmp, want, 0x2f))           // 0x401dc2
     puts("Correct! The flower has bloomed.");
else puts("Wrong flag.");
```

**凯撒函数 `0x401060` 的方向很容易读反，这里逐字节核过**（`0x4010a8`）：

```asm
movzx eax, byte ptr [ebp-1]      ; c
sub   eax, 0x5a                  ; c - 0x5a == (c - 'a') + 7
cdq ; idiv 26                    ; % 26
add   edx, 0x61                  ; + 'a'
```

即 `(c - 'a' + 7) % 26 + 'a'` → **对输入做 +7**（大写分支 `- 0x3a + 0x41` 同理）。
所以最终判定是：`caesar(input, +7) == target ^ 0x80`，因此

```
flag = caesar(target ^ 0x80, -7)
```

### 5. 解密

```
target  (file 0xe170, 47B) : b0e5cee8f4ecfbc4f6c4dfc1efb3dfedb1f6e4b3f9a4dfc0
                             f9ecdfdad6f6b0f6f6a0e9b3c0e2b7f0ede2f3f3a1a1fd
target ^ 0x80              : 0eNhtl{DvD_Ao3_m1vd3y$_@yl_ZVv0vv i3@b7pmbss!!}
凯撒 -7（仅字母）           : 0xGame{WoW_Th3_f1ow3r$_@re_SOo0oo b3@u7ifull!!}
```

- 长度 47，与 `cmp [ebp-4], 0x2f` 一致；
- `0eNhtl{` 正是 `0xGame{` 的 +7 结果（`x→e` 按字母表回绕），**单向性自检通过**；
- 读起来就是 *"WoW The flower$ are SOo0oo beautiful!!"*（leetspeak，`$`=s、`@`=a、`0`/`O`/`o` 都当 o）。

### 6. 独立验证（不依赖我手读汇编）

用 **unicorn 直接跑程序里真实的 `0x401060` 机器码**：

```python
push 47; push DST; push SRC; call 0x401060   # SRC = 候选 flag
```

结果：

```
emulated caesar(+7) out : 0eNhtl{DvD_Ao3_m1vd3y$_@yl_ZVv0vv i3@b7pmbss!!}
== stored_blob ^ 0x80   : True
```

即**目标程序自己的代码**确认候选 flag 会被判为 `Correct!`。
注意 unicorn 跑这段时 `je` 天然跳过了 `11 22 33`，也算顺带验证了花指令模板。

## 复现

```bash
source ~/re-tools/fw-env.sh
cd ~/ctf-2026
python3 scripts/49-solve.py            # 自动解压 + 解密 + 自检，输出 FLAG
```

## 踩坑记录

- 一开始把 `0x401060` 的凯撒方向读反（`sub 0x5a` 看着像 −7，其实是 +7），
  会得到 `0lUoas{KcK_...}` 这种不可能是 flag 的结果；用 unicorn 跑真实机器码才定死方向。
- `strings` 里那一堆 `4*/.z<6;=`z` 就是 XOR 0x5a 的字符串表，
  `strings -n 6` 会把它们当可见文本吐出来，容易误判成"明文线索"。
- `0x40f170` 的 47 字节**不是**用字符串表的 0x5a 解，而是指令里写死的 `xor 0x80`。
  两者混用会得到乱码（第一版脚本就犯了这个错）。
