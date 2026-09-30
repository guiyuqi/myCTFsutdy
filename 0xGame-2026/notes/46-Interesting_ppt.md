# 46 · Interesting_ppt

- **flag**: `0xGame{pptx_1s_just_a_z1p_4nd_metadata_n3ver_b3tr4ys_y0u}`
- **分类**: Misc / 文档隐写（离线，无容器）
- **分值**: 736 | 13 人解出
- **提交结果**: `{"code": 200, "msg": "OK", "data": {"result": true}}` ✅

## 题目描述
> X1c 的某个师傅为了给战队招新，用 AI 做了一个招新宣传 ppt，在彻底删除 AI 水印之后，他留下了一个小彩蛋。

## 附件
`firmware/46_Interesting_ppt/0xgame.zip` → 内含单个 `0xgame.pptx`（29969 B）。

## 解题思路

pptx 就是 zip，直接解包看 `docProps/` 下的元数据。8 张 slide 全是普通文本，没有
media / notesSlides / 隐藏页（`app.xml` 里 `HiddenSlides=0`、`Notes=0`），
彩蛋完全藏在 **文档属性** 里 —— 呼应题目 "metadata never betrays you"。

### 关键点 1：`docProps/core.xml` 里的裸 base64
```xml
<cp:lastModifiedBy>X1ct34m</cp:lastModifiedBy><cp:revision>1</cp:revision>a2V5PTB4R2FtZV8yMDI2<dcterms:modified .../>
```
`a2V5PTB4R2FtZV8yMDI2` 位于 `</cp:revision>` 与 `<dcterms:modified>` 之间，
是**非法位置的裸文本**，PowerPoint 读取时直接忽略 → 完美藏 key。

```
base64decode("a2V5PTB4R2FtZV8yMDI2") = b"key=0xGame_2026"
```

### 关键点 2：`docProps/custom.xml` 的 "AIGC" 自定义属性
所谓 "AI 水印" 就是 PowerPoint 的 AIGC 标记自定义属性：
```xml
<property ... name="AIGC">fTAvKTQybl5VAXRHHA8JCygHfFZTWGYCIydUDQcBX0pVdkB3AwA3OVBnZAZpLxUJCSIZVFJYeAIiHysLPDV8AFFcYk0kUFRQEnpmCw==<vt:lpwstr></vt:lpwstr></property>
```
注意：密文写在 `<property>` 开始标签与 `<vt:lpwstr>` 之间（同样是**非法位置**），
`<vt:lpwstr>` 是空的 —— 作者把值从正确位置抠出来塞到前面去了。
"彻底删除 AI 水印" 实际上只删了 `vt:lpwstr` 里的值，前面的残留没清掉。

### 关键点 3：解密链
```
AIGC value (base64)  --b64d-->  76 B ciphertext
                     --XOR key=b"0xGame_2026" (repeating)-->
                     MHhHYW1le3BwdHhfMXNfanVzdF9hX3oxcF80bmRfbWV0YWRhdGFfbjN2ZXJfYjN0cjR5c195MHV9
                     --b64d-->  0xGame{...}
```
即 `base64 → 重复密钥 XOR → base64`。

## 复现
```bash
cd ~/ctf-2026
python3 scripts/46-solve.py            # 自动从 firmware/ 里的 zip 取 pptx
# 输出：FLAG: 0xGame{pptx_1s_just_a_z1p_4nd_metadata_n3ver_b3tr4ys_y0u}
```
日志：`evidence/46-solve.log`

## 走过的弯路（已排除）
- `ppt/slides/*.xml` 文本、`slideLayouts`、`slideMaster1.xml`：无异常。
- 无 `ppt/media/`、无 `notesSlides/`、无批注 / 修订（`revision=1`）。
- 无缩略图（`docProps/thumbnail.jpeg` 不存在）。
- `[Content_Types].xml` / `_rels` 无孤儿部件（无 Override 指向缺失文件）。
- `app.xml` 中 `HiddenSlides=0`，确认没有隐藏页。

## 备注（工具 bug，已修）
`scripts/ctfplus.py` 的 `submit` 分支原先把 `challenge_id` 当**字符串**发，
平台返回 `400 type mismatch for field "challenge_id"`。
已按 `cmd_detail` 的写法改为 `int(cid)` 后提交成功（HTTP 400 属于参数类型错误，
不消耗 flag 提交次数）。
