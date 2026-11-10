#!/usr/bin/env python3
"""把 wp.md 渲染成可提交的 PDF（中文用系统 CJK 字体 DroidSansFallbackFull）。

用法:
    work/12084e/venv/bin/python scripts/md2pdf.py wp.md YCB2026-WP.pdf
    # 校验: pdftotext -layout out.pdf - | head -40
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, PageTemplate,
                                Paragraph, Preformatted, Spacer, Table, TableStyle)
from reportlab.platypus import Image as RLImage

CJK_PATH = "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf"
LATIN_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT = "CJK"
MONO = "Courier"


def register_fonts() -> None:
    pdfmetrics.registerFont(TTFont(FONT, CJK_PATH))
    pdfmetrics.registerFont(TTFont("Latin", LATIN_PATH))
    pdfmetrics.registerFontFamily(FONT, normal=FONT, bold=FONT, italic=FONT, boldItalic=FONT)


def esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def inline(s: str) -> str:
    """行内 markdown → reportlab 标记。"""
    s = esc(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    def _code(m):
        inner = m.group(1)
        if len(inner) >= 60:          # 超长 token（如 96 字符的 flag）缩字号，避免被折行切断
            return f'<font size="7"><i>{inner}</i></font>'
        return f"<i>{inner}</i>"
    s = re.sub(r"`([^`]+)`", _code, s)
    s = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)", r'<link href="\2" color="blue">\1</link>', s)
    return s




def _is_cjk(ch: str) -> bool:
    o = ord(ch)
    return (0x3400 <= o <= 0x4DBF) or (0x4E00 <= o <= 0x9FFF) or (0xF900 <= o <= 0xFAFF) \
        or (0xFF00 <= o <= 0xFFEF) or (0x3000 <= o <= 0x303F)


def _wrap_ascii(markup: str) -> str:
    """非 CJK 段用 DejaVuSans（Droid Sans Fallback 不含 ASCII/西文标点，会整段丢失）。"""
    out: list[str] = []
    depth = 0
    i, n = 0, len(markup)
    while i < n:
        if markup[i] == "<":
            j = markup.find(">", i)
            if j < 0:
                out.append(markup[i:]); break
            tag = markup[i:j + 1]
            if tag.startswith("<font") and "face=" in tag:
                depth += 1
            elif tag.startswith("</font"):
                depth = max(0, depth - 1)
            out.append(tag)
            i = j + 1
            continue
        j = markup.find("<", i)
        if j < 0:
            j = n
        chunk = markup[i:j]
        if depth > 0:
            out.append(chunk)
        else:
            buf: list[str] = []
            for ch in chunk:
                if _is_cjk(ch):
                    if buf:
                        out.append(f'<font face="Latin">{"".join(buf)}</font>')
                        buf = []
                    out.append(ch)
                else:
                    buf.append(ch)
            if buf:
                out.append(f'<font face="Latin">{"".join(buf)}</font>')
        i = j
    return "".join(out)


def styles() -> dict[str, ParagraphStyle]:
    base = dict(fontName=FONT, wordWrap="CJK", alignment=TA_LEFT)
    return {
        "title": ParagraphStyle("title", fontSize=20, leading=26, spaceAfter=10, **base),
        "h1": ParagraphStyle("h1", fontSize=15, leading=20, spaceBefore=10, spaceAfter=6,
                             textColor=colors.HexColor("#123"), **base),
        "h2": ParagraphStyle("h2", fontSize=12.5, leading=17, spaceBefore=9, spaceAfter=4,
                             textColor=colors.HexColor("#1a3d6d"), **base),
        "body": ParagraphStyle("body", fontSize=9.2, leading=13.6, spaceAfter=3, **base),
        "quote": ParagraphStyle("quote", fontSize=9, leading=13.2, leftIndent=8, textColor=colors.HexColor("#444"),
                                spaceAfter=2, **base),
        "cell": ParagraphStyle("cell", fontSize=8, leading=11, **base),
        "cap": ParagraphStyle("cap", fontName=FONT, fontSize=8, leading=11, alignment=1,
                              textColor=colors.HexColor("#555"), spaceBefore=2, spaceAfter=8),
        "ph": ParagraphStyle("ph", fontName=FONT, fontSize=8, leading=11, alignment=1,
                             textColor=colors.HexColor("#a33"), spaceBefore=4, spaceAfter=8),
        "code": ParagraphStyle("code", fontName=MONO, fontSize=7.4, leading=9.6,
                               leftIndent=6, backColor=colors.HexColor("#f4f4f4"),
                               borderPadding=3, spaceBefore=3, spaceAfter=5),
    }


def parse_table(lines: list[str], st: dict) -> Table:
    rows = []
    for ln in lines:
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
            continue
        rows.append([Paragraph(_wrap_ascii(inline(c)), st["cell"]) for c in cells])
    ncol = max(len(r) for r in rows)
    rows = [r + [Paragraph("", st["cell"])] * (ncol - len(r)) for r in rows]
    widths = [None] * ncol
    t = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bbb")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f7")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return t


def build(md_path: Path, out_path: Path) -> None:
    register_fonts()
    st = styles()
    lines = md_path.read_text(encoding="utf-8").splitlines()
    story: list = []
    i = 0
    buf_table: list[str] = []

    def flush_table() -> None:
        nonlocal buf_table
        if buf_table:
            story.append(Spacer(1, 2))
            story.append(parse_table(buf_table, st))
            story.append(Spacer(1, 4))
            buf_table = []

    while i < len(lines):
        ln = lines[i]
        s = ln.rstrip()

        if s.startswith("|"):
            buf_table.append(s)
            i += 1
            continue
        flush_table()

        m_img = re.match(r"^!\[(.*?)\]\((.+?)\)\s*$", s)
        if m_img:
            cap, rel = m_img.group(1), m_img.group(2)
            path = Path(rel)
            if not path.is_absolute():
                path = (md_path.parent / rel).resolve()
            if path.exists():
                try:
                    from PIL import Image as PILImage
                    w, h = PILImage.open(path).size
                    maxw = 150 * mm
                    ww, hh = maxw, maxw * h / w
                    if hh > 110 * mm:
                        hh = 110 * mm
                        ww = hh * w / h
                    story.append(RLImage(str(path), width=ww, height=hh))
                    story.append(Paragraph(_wrap_ascii(inline(cap)), st["cap"]))
                except Exception as e:
                    story.append(Paragraph("【图片渲染失败：%s（%s）】" % (cap, e), st["ph"]))
            else:
                story.append(Paragraph("【待补图：%s —— %s】" % (cap, rel), st["ph"]))
            i += 1
            continue

        if s.startswith("```"):
            i += 1
            code: list[str] = []
            while i < len(lines) and not lines[i].startswith("```"):
                code.append(lines[i])
                i += 1
            i += 1
            story.append(Preformatted("\n".join(code), st["code"]))
            continue
        if not s.strip():
            i += 1
            continue
        m = re.match(r"^(#{1,4})\s+(.*)$", s)
        if m:
            lvl = len(m.group(1))
            txt = _wrap_ascii(inline(m.group(2)))
            key = "title" if lvl == 1 else ("h1" if lvl == 2 else "h2")
            if lvl >= 3:
                story.append(KeepTogether([Spacer(1, 5), Paragraph(txt, st["h2"])]))
            else:
                story.append(Paragraph(txt, st[key]))
            i += 1
            continue
        if s.startswith(">"):
            story.append(Paragraph(_wrap_ascii(inline(s.lstrip("> ").strip())), st["quote"]))
            i += 1
            continue
        if re.match(r"^\s*[-*]\s+", s):
            txt = re.sub(r"^\s*[-*]\s+", "", s)
            story.append(Paragraph("•  " + _wrap_ascii(inline(txt)), st["body"]))
            i += 1
            continue
        if re.match(r"^\s*\d+\.\s+", s):
            story.append(Paragraph(_wrap_ascii(inline(s.strip())), st["body"]))
            i += 1
            continue
        story.append(Paragraph(_wrap_ascii(inline(s.strip())), st["body"]))
        i += 1
    flush_table()

    doc = BaseDocTemplate(str(out_path), pagesize=A4,
                          leftMargin=16 * mm, rightMargin=16 * mm,
                          topMargin=15 * mm, bottomMargin=15 * mm,
                          title="2026 羊城杯 Writeup", author="ctf-2026")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="f")

    def footer(canv, d):
        canv.saveState()
        canv.setFont("Latin", 8)
        canv.setFillColor(colors.HexColor("#666"))
        canv.drawString(doc.leftMargin, 9 * mm, "2026 YCB Cup (DASCTF - match 1750) - Writeup")
        canv.drawRightString(A4[0] - doc.rightMargin, 9 * mm, f"Page {canv.getPageNumber()}")
        canv.restoreState()

    doc.addPageTemplates([PageTemplate(id="all", frames=[frame], onPage=footer)])
    doc.build(story)
    print(f"[+] {out_path} ({out_path.stat().st_size} bytes)")


if __name__ == "__main__":
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "wp.md")
    dst = Path(sys.argv[2] if len(sys.argv) > 2 else "YCB2026-WP.pdf")
    build(src, dst)
