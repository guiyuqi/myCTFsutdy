# 25 · 欢迎来到CTF的世界！（Misc, 297 分, 64 解）

- **flag**: `0xGame{welcome_t0_the_w0rld_of_CTF!}`
- **提交结果**: `{"code":200,"msg":"OK","data":{"result":true}}`（一次通过）
- **附件**: `firmware/25_欢迎来到CTF的世界/CTF入门指北.pdf`（PDF 1.7, 929KB, 13 页）
- **类型**: 纯静态 Misc / PDF 文本提取 + Base64

## 思路

环境里没有任何 PDF 工具（无 `pdftotext`/`mutool`/`qpdf`，python 无 `pypdf`/`pdfminer`/`fitz`），
按规则也不能 `pip install`，所以**自己写了一个最小 PDF 文本提取器**：

1. 扫描 `N 0 obj ... endobj` 建立对象表，再解压全部 `/Type/ObjStm` 对象流补全对象（PDF 1.7 有 22 个对象流）。
2. 找 `/Type/Page`，取 `/Resources /Font` 名称→对象映射与 `/Contents` 流。
3. 对每个字体对象取 `/ToUnicode` CMap，解析 `beginbfchar` / `beginbfrange` 建 code→Unicode 映射。
4. 解析内容流的 `Tf`/`Tj`/`TJ` 算子，用当前字体的 CMap 解码十六进制串（中文是子集 CID 字体，必须走 ToUnicode）。

正文第 1 页 misc 段落里直接给了提示句：

> 为了奖励你的认真观看，这⾥有⼀串神秘字符送给你：`MHhHYW1le3dlbGNvbWVfdDBfdGhlX3cwcmxkX29mX0NURiF9`
> 这是什么呢？学会使⽤搜索引擎和AI吧！

Base64 解一次即得 flag：

```bash
python3 -c "import base64;print(base64.b64decode('MHhHYW1le3dlbGNvbWVfdDBfdGhlX3cwcmxkX29mX0NURiF9').decode())"
# 0xGame{welcome_t0_the_w0rld_of_CTF!}
```

## 复现

```bash
cd ~/ctf-2026
python3 scripts/25-solve.py "firmware/25_欢迎来到CTF的世界/CTF入门指北.pdf" | grep -o 'MHhHYW1l[A-Za-z0-9+/=]*'
# → MHhHYW1le3dlbGNvbWVfdDBfdGhlX3cwcmxkX29mX0NURiF9
```

- 成品脚本: `scripts/25-solve.py`（通用 PDF 文本提取器，CMap 解码）
- 草稿: `work/25_welcome/`（`pdftext.py`、`pages.txt` 全文）
- 证据: `evidence/25-flag-extract.txt`、`evidence/25-base64-flag.txt`

## 已排除方向（都为空）

- `/EmbeddedFiles` / `/Filespec` / `/JavaScript` / `/JS` / `/OpenAction` / `/OCProperties`
  / `/Annots` / `/AcroForm` / `/XFA` / `/URI` / `/Encrypt` 全部 0 次出现。
- 1633 个解压流里对 `0xGame` / `flag` / `CTF{` 的明文搜索均 0 命中 → 说明 flag 不在明文流里，
  而是靠正文那句话 + Base64（也验证了必须做 CMap 解码才能看到中文正文）。

## 卡点

无。全程离线，未使用容器。
