# re-Route97 的副歌

- 结果：✅ 解出
- 关联 run：run-63775｜合计 token ≈ 12.9M

## 题面 / 结论 / 可复用资产
**题面**：

```
阿九是 97 号公路上的电台歌姬，寄生在这台车的中控屏里。她的声带是一台定制车机播放器，她的排练室是一个音游。
```

**run-63775 最后事实**：

- radio_channel.wav 自带全部 chunk（含 flgx@0x69c0，BE size=48，纠正"flgx 需自造"）；flgx 置换表取自 abox，pad 为 CBC 式，key16 交替取 SHA256(28B)/MD5(token) 本 Step 实测（自写 python3 直读 wav 字节 + objdump -d route97_rhythm.exe 全量反汇编；不依赖前序 Fact 结论）： A) 纠正"flgx 未在附件中、需自造密文"的旧结论。自写扫描器实测 radio_channel.wav(27128B) chunk 表： fmt(16)@0xc、data(26496)@0x24、abox(BE256)@0x67ac、ach1(BE24)@0x68b4、ach2(BE56)@0x68d4、ach3(BE104)@0x6914、hint(BE51)@0x6984、flgx(BE48)@0x6
- 离线 unicorn harness 可跑 route97_rhythm.exe main（免 wine）；EXPECTX0/EXPECTX1 各 56 dword、音符记录=3 字节×8/16/32、终点判据为 32 字节明文的 FNV-1a64 实测（objdump 全量反汇编 + pefile + unicorn 2.1.4；未取得 flag）： A) 关键常量/布局（直接读 .rdata 与反汇编，修正编号猜测）： - EXPECTX1 @0x406460、EXPECTX0 @0x406540，各 0xE0 字节 = **56 个 dword**；紧接着 0x406620 起是 DFT 用的 3 个 double：0x401921fb54442d18(=2π)、2^-12(=1/4096)、2^-8(=1/256)。故两表索引必须 0..55。 - 组长度表在 rsp+0xd4..0xdc = [8,16,32]，每组起
- wav chunk 解析按 size 向上取偶（hint 51→占 52）才能到 flgx@0x69c0；ach1^0xA7 / ach2 / ach3 三个谱面表已完整解密，DFT16 与 state 初值链可 100% 复现 本 Step 实测（自写 python3 解析 radio_channel.wav 与反汇编 route97_rhythm.exe，未依赖前序 Fact）： 1) chunk 步进规则确定：exe 对命名 chunk 用 **大端** size，且下一 chunk 偏移 = 当前头 + 8 + ((size+1)&~1)（0x401dd9: lea 1(%rsi)…and $0xfffffffe…add 8）。hint 声明 51（奇数），占 52 字节（数据 0x698c..0x69bf，末字节 0x00），故 flgx 头正好在 0x69c0、BE size=0x30、数据到文件尾 0x69f8。按

## 归档说明

- 原始事件流：`evidence/run-logs.tar.gz` 内 `run-63775.jsonl`
- 逐 run 详细摘要：`retrospective/digests/`
- 完整复盘：`retrospective/RETRO-2026-11-08.md`
