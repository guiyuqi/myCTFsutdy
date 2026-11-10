#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把若干 Markdown 合成一份 PDF（支持中文、代码块、表格、列表）。

为什么自己写：环境里没有 pandoc/wkhtmltopdf/weasyprint，而 fpdf2 + 系统自带的
Droid Sans Fallback（有完整 CJK 字形）够用。只实现 WP 里实际用到的 Markdown 子集：
标题、段落、列表、代码围栏、表格、引用、行内 `code`/加粗/链接。

用法：
  PYTHONPATH=.tmp/pylibs python3 tools/md2pdf.py out.pdf a.md b.md --cover ...
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from fpdf import FPDF

CJK = "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf"
LATIN = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
LATIN_B = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
GREY = (110, 118, 135)
CODE_BG = (245, 246, 248)


class Doc(FPDF):
    def __init__(self, title: str):
        super().__init__(format="A4")
        self.doc_title = title
        self.set_auto_page_break(True, margin=16)
        self.set_margins(18, 16, 18)
        # Droid Sans Fallback 只有 CJK 字形（实测 A/2 都不在 cmap 里），
        # 所以正文用 DejaVu（拉丁）+ 把 cjk 设成兜底字体。
        self.add_font("latin", "", LATIN)
        self.add_font("latin", "B", LATIN_B)
        self.add_font("mono", "", MONO)
        self.add_font("cjk", "", CJK)
        self.set_font("latin", "", 10.5)
        self.set_fallback_fonts(["cjk"])
        self._toc: list[tuple[int, str, int]] = []

    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("latin", "", 7.5)
        self.set_text_color(*GREY)
        self.cell(0, 6, f"{self.doc_title}  ·  {self.page_no()}", align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0)
        self.set_draw_color(220, 224, 230)
        self.line(18, 22, self.w - 18, 22)

    def head(self, level: int, text: str):
        size = {1: 17, 2: 13.5, 3: 11.5}.get(level, 11)
        self.ln(3 if level > 1 else 0)
        if level <= 2:
            self._toc.append((level, text, self.page_no()))
        self.set_font("latin", "", size)
        self.multi_cell(0, size * 0.55, text, wrapmode="CHAR", new_x="LMARGIN", new_y="NEXT")
        self.set_font("latin", "", 10.5)
        if level == 2:
            self.set_draw_color(210, 214, 222)
            self.line(18, self.get_y() + 0.6, self.w - 18, self.get_y() + 0.6)
            self.ln(1.6)

    def par(self, text: str, size: float = 10.5, indent: float = 0):
        self.set_font("latin", "", size)
        self.set_x(18 + indent)
        self.multi_cell(self.w - 36 - indent, size * 0.62, text, wrapmode="CHAR",
                        new_x="LMARGIN", new_y="NEXT")
        self.ln(0.8)

    def bul(self, text: str, indent: float = 5, marker: str = "•"):
        self.set_font("latin", "", 10.4)
        y = self.get_y()
        self.set_x(18 + indent)
        self.cell(4, 5.4, marker)
        self.set_x(18 + indent + 4.5)
        self.multi_cell(self.w - 36 - indent - 4.5, 5.4, text, wrapmode="CHAR",
                        new_x="LMARGIN", new_y="NEXT")
        if self.get_y() - y < 1:
            self.ln(1)

    def cblock(self, text: str):
        lines = text.splitlines() or [""]
        self.set_font("mono", "", 8.0)
        h = 4.4
        for line in lines:
            if self.get_y() > self.h - 28:
                self.add_page()
                self.set_font("mono", "", 8.0)
            self.set_fill_color(*CODE_BG)
            label = line if len(line) <= 175 else line[:172] + "…"
            self.set_x(18)
            self.cell(self.w - 36, h, " " + label, fill=True, new_x="LMARGIN", new_y="NEXT")
        self.set_font("latin", "", 10.5)
        self.ln(1.2)


def inline(text: str) -> str:
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r"\1", text)
    text = text.replace("\\|", "|")
    return text


def render(pdf: Doc, md: str):
    lines = md.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        s = line.strip()
        if not s:
            i += 1
            continue
        if s.startswith("```"):
            i += 1
            buf = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1
            pdf.cblock("\n".join(buf))
            continue
        m = re.match(r"^(#{1,4})\s+(.*)$", s)
        if m:
            pdf.head(len(m.group(1)), inline(m.group(2)))
            i += 1
            continue
        if s.startswith(">"):
            pdf.par(inline(s.lstrip("> ").strip()), size=9.6)
            i += 1
            continue
        if s.startswith("|") and s.endswith("|"):
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                row = [inline(c.strip()) for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-{2,}:?", c or "-") for c in row):
                    rows.append(row)
                i += 1
            width = max(len(r) for r in rows) if rows else 0
            for r in rows:
                r += [""] * (width - len(r))
                pdf.par("   ".join(x for x in r), size=9.2, indent=2)
            pdf.ln(0.6)
            continue
        m = re.match(r"^([-*+]|\d+[.)])\s+(.*)$", s)
        if m:
            marker = "•" if m.group(1) in "-*+" else m.group(1)
            pdf.bul(inline(m.group(2)), marker=marker if marker == "•" else marker + " ")
            i += 1
            continue
        if s.startswith("---") and set(s) <= {"-"}:
            pdf.set_draw_color(220, 224, 230)
            pdf.line(18, pdf.get_y() + 2, pdf.w - 18, pdf.get_y() + 2)
            pdf.ln(3.5)
            i += 1
            continue
        pdf.par(inline(s))
        i += 1


def main(argv: list[str]) -> int:
    out = argv[0]
    files = [Path(a) for a in argv[1:]]
    title = files[0].stem if files else "CTF Write-up"
    pdf = Doc("2026 强网杯 · 车联网专项赛 Write-up")
    # 封面：**中英分开画**（混排 + fallback + align=C 会丢拉丁字形，实测掉过）
    def centered(segs, size, gap=2.0):
        widths = []
        for text, font in segs:
            pdf.set_font(font, "", size)
            widths.append(pdf.get_string_width(text))
        total = sum(widths) + gap * max(0, len(segs) - 1)
        y = pdf.get_y()
        pdf.set_x(26)
        for (text, font), w in zip(segs, widths):
            pdf.set_font(font, "", size)
            pdf.set_xy(pdf.get_x(), y)
            pdf.cell(w, size * 0.75, text)
            pdf.set_x(pdf.get_x() + w + gap)
        pdf.set_xy(26, y + size * 0.95)

    pdf.add_page()
    pdf.ln(30)
    centered([("2026", "latin")], 12)
    centered([("第十届强网杯", "cjk")], 22)
    centered([("车联网安全专项赛 · 遴选赛", "cjk")], 15)
    pdf.ln(6)
    centered([("Write-up", "latin")], 19)
    centered([("合集", "cjk")], 14)
    pdf.ln(12)
    centered([("队伍", "cjk"), ("<team>", "latin")], 12)
    centered([("总得分", "cjk"), ("630 PT", "latin"), ("排名", "cjk"), ("第 48 名", "cjk")], 10.5)
    centered([("解出", "cjk"), ("3", "latin"), ("道", "cjk"), ("一血", "cjk"), ("1", "latin")], 10.5)
    centered([("2026-11-08 09:00-12:00", "latin")], 10)
    pdf.ln(10)
    for segs in (
        [("AI 对话与过程材料：见随附对话包（网盘链接见第 2.1 节）", "cjk")],
        [("本 PDF 内嵌附件：WP-INDEX.md、PACKAGE-MANIFEST.json", "cjk")],
        [("标【需确认】处为推断，未作为结论；结论均可在对话包事件流中复核", "cjk")],
    ):
        centered(segs, 8.6)

    for f in files:
        pdf.add_page()
        render(pdf, f.read_text(encoding="utf-8"))
    pdf.output(out)
    print(f"wrote {out} ({Path(out).stat().st_size/1024:.0f} KB, {pdf.page_no()} pages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
