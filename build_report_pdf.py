"""ReportLab PDF Builder for the Trustworthy AI Guardrails Evaluation Report.

Format Specifications:
- Title: Trustworthy AI Guardrails: Evaluation Report
- Subtitle: Tisha Manandhar
- Font: Arial (TrueType Arial & Arial-Bold from Windows fonts, fallback to Helvetica)
- Body Font Size: 12 pt (Clean 19 pt line leading, 12 pt paragraph spacing)
- Text Alignment: Clean left-aligned (TA_LEFT) to avoid cluttered word gaps
- Text Color: Strictly 100% black (#000000) throughout
- Hierarchy: Clearly defined headings (Title: 22pt Bold, H1: 16pt Bold, H2: 13.5pt Bold, Body: 12pt Regular)
- No Italics: All italic formatting removed; clean regular and bold typography only
- No Headers, Footers, Watermarks, or Line Separators
- Metadata block removed per user specification

Author: Tisha Manandhar
Assignment: Trustworthy AI - Input and Output Guardrails
"""

import os
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.pdfmetrics import registerFontFamily
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

BASE_DIR = Path(__file__).parent
SOURCE_MARKDOWN = BASE_DIR / "report.md"
TARGET_PDFS = [BASE_DIR / "report.pdf", BASE_DIR / "evaluation_report.pdf"]

# ---------------------------------------------------------------------------
# Font Registration (Arial - Clean Regular & Bold)
# ---------------------------------------------------------------------------
font_dir = r"C:\Windows\Fonts"
arial_regular = os.path.join(font_dir, "arial.ttf")
arial_bold = os.path.join(font_dir, "arialbd.ttf")

if os.path.exists(arial_regular) and os.path.exists(arial_bold):
    pdfmetrics.registerFont(TTFont("Arial", arial_regular))
    pdfmetrics.registerFont(TTFont("Arial-Bold", arial_bold))
    registerFontFamily(
        "Arial",
        normal="Arial",
        bold="Arial-Bold",
        italic="Arial",  # map italic to regular to strictly avoid italics
        boldItalic="Arial-Bold",
    )
    FONT_NORMAL = "Arial"
    FONT_BOLD = "Arial-Bold"
else:
    FONT_NORMAL = "Helvetica"
    FONT_BOLD = "Helvetica-Bold"


def clean_markdown_inline(text: str) -> str:
    """Escapes XML entities, removes all italics, and converts bold markup to ReportLab XML tags."""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("`", "")  # strip raw backticks

    # Convert bold **text** to <b>text</b>
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)

    # Remove all italics *text* -> text (strip asterisks, no <i> tags)
    text = re.sub(r"\*(.+?)\*", r"\1", text)

    # Clean out any leftover HTML italic or emphasis tags
    text = text.replace("<i>", "").replace("</i>", "")
    text = text.replace("<em>", "").replace("</em>", "")

    # Links rendered in clean black with underline
    text = re.sub(r"\[([^\]]+)\]\((https?://[^\)]+)\)", r'<link href="\2" color="#000000"><u>\1</u></link>', text)

    return text


def generate_story(markdown_lines: list[str]) -> list:
    """Builds clean flowable document elements with generous line spacing and proper hierarchy."""
    styles = getSampleStyleSheet()

    # --- Typography Hierarchy with Enhanced Line Spacing ---
    title_style = ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        fontName=FONT_BOLD,
        fontSize=22,
        leading=28,
        textColor=colors.black,
        alignment=TA_CENTER,
        spaceBefore=10,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        name="ReportSubtitle",
        parent=styles["Normal"],
        fontName=FONT_BOLD,
        fontSize=13,
        leading=18,
        textColor=colors.black,
        alignment=TA_CENTER,
        spaceAfter=26,
    )

    h1_style = ParagraphStyle(
        name="SectionHeader",
        parent=styles["Heading1"],
        fontName=FONT_BOLD,
        fontSize=16,
        leading=22,
        textColor=colors.black,
        spaceBefore=22,
        spaceAfter=10,
        keepWithNext=True,
    )

    h2_style = ParagraphStyle(
        name="SubSectionHeader",
        parent=styles["Heading2"],
        fontName=FONT_BOLD,
        fontSize=13.5,
        leading=18,
        textColor=colors.black,
        spaceBefore=16,
        spaceAfter=8,
        keepWithNext=True,
    )

    # Body: 12pt Arial with 19pt leading and 12pt paragraph separation (TA_LEFT for natural reading)
    body_style = ParagraphStyle(
        name="ReportBody",
        parent=styles["BodyText"],
        fontName=FONT_NORMAL,
        fontSize=12,
        leading=19,
        textColor=colors.black,
        alignment=TA_LEFT,
        spaceAfter=12,
    )

    bullet_style = ParagraphStyle(
        name="ReportBullet",
        parent=body_style,
        fontName=FONT_NORMAL,
        fontSize=12,
        leading=19,
        textColor=colors.black,
        leftIndent=20,
        firstLineIndent=-12,
        spaceAfter=8,
    )

    table_cell_style = ParagraphStyle(
        name="TableCell",
        parent=styles["Normal"],
        fontName=FONT_NORMAL,
        fontSize=10.5,
        leading=15.5,
        textColor=colors.black,
    )

    table_header_style = ParagraphStyle(
        name="TableHeader",
        parent=table_cell_style,
        fontName=FONT_BOLD,
        fontSize=11,
        leading=16,
        textColor=colors.black,
    )

    # Title and Subtitle: Only "Tisha Manandhar" below the header
    story = [
        Spacer(1, 0.2 * inch),
        Paragraph("Trustworthy AI Guardrails: Evaluation Report", title_style),
        Paragraph("Tisha Manandhar", subtitle_style),
    ]

    i = 0
    in_code_block = False

    while i < len(markdown_lines):
        line = markdown_lines[i].strip()

        if not line:
            i += 1
            continue

        # Skip markdown title
        if line.startswith("# "):
            i += 1
            continue

        # Skip any metadata lines before the first section
        if (
            line.startswith("Student Assignment Submission")
            or line.startswith("**Student Assignment Submission**")
            or line.startswith("Course / Context:")
            or line.startswith("**Course / Context:**")
            or line.startswith("Application Domain:")
            or line.startswith("**Application Domain:**")
            or line.startswith("Repository Reference:")
            or line.startswith("**Repository Reference:**")
            or line.startswith("Author:")
            or line.startswith("**Author:**")
        ):
            i += 1
            continue

        # Code or diagram blocks
        if line.startswith("```"):
            in_code_block = not in_code_block
            if in_code_block:
                story.append(
                    Paragraph(
                        "[Architecture Flowchart: Please refer to architecture.md or architecture.svg]",
                        body_style,
                    )
                )
            i += 1
            continue

        if in_code_block:
            i += 1
            continue

        # Lined separator replacement: clean whitespace spacer (NO LINES)
        if line == "---":
            story.append(Spacer(1, 16))
            i += 1
            continue

        # Heading 1
        if line.startswith("## "):
            story.append(Paragraph(clean_markdown_inline(line[3:]), h1_style))
            i += 1
            continue

        # Heading 2
        if line.startswith("### "):
            story.append(Paragraph(clean_markdown_inline(line[4:]), h2_style))
            i += 1
            continue

        # Tables: Clean presentation, black text, light neutral shading, NO border/grid lines
        if line.startswith("|"):
            raw_table_lines = []
            while i < len(markdown_lines) and markdown_lines[i].strip().startswith("|"):
                raw_table_lines.append(markdown_lines[i].strip())
                i += 1

            table_rows = []
            for row_idx, raw_row in enumerate(raw_table_lines):
                cells = [c.strip() for c in raw_row.strip("|").split("|")]
                if all(re.fullmatch(r":?-{2,}:?", c) for c in cells):
                    continue

                formatted_cells = []
                for cell in cells:
                    cell_style = table_header_style if row_idx == 0 else table_cell_style
                    formatted_cells.append(Paragraph(clean_markdown_inline(cell), cell_style))
                table_rows.append(formatted_cells)

            if table_rows:
                # 7.0 inch total width for letter page with 0.75 margin
                table = Table(table_rows, colWidths=[1.8 * inch, 1.2 * inch, 4.0 * inch], repeatRows=1, hAlign="LEFT")
                table.setStyle(
                    TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5e7eb")),
                        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f9fafb")]),
                        ("LEFTPADDING", (0, 0), (-1, -1), 10),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ])
                )
                story.extend([Spacer(1, 10), table, Spacer(1, 14)])
            continue

        # Bullet list
        if line.startswith("- ") or line.startswith("* "):
            formatted_bullet = clean_markdown_inline(f"• {line[2:]}")
            story.append(Paragraph(formatted_bullet, bullet_style))
            i += 1
            continue

        # Numbered list
        if re.match(r"^\d+\.\s+", line):
            formatted_num = clean_markdown_inline(line)
            story.append(Paragraph(formatted_num, bullet_style))
            i += 1
            continue

        # Standard body paragraph (Arial 12pt, 19pt leading, Black, No Italics)
        story.append(Paragraph(clean_markdown_inline(line), body_style))
        i += 1

    return story


def empty_page_decoration(canvas, doc):
    """No-op callback to ensure completely empty headers, footers, and watermarks."""
    pass


def build_all_pdfs():
    """Generates clean PDF reports with no headers, footers, watermarks, or lines."""
    if not SOURCE_MARKDOWN.exists():
        raise FileNotFoundError(f"Source file {SOURCE_MARKDOWN} not found.")

    markdown_lines = SOURCE_MARKDOWN.read_text(encoding="utf-8").splitlines()

    for pdf_path in TARGET_PDFS:
        story = generate_story(markdown_lines)
        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=letter,
            leftMargin=0.75 * inch,
            rightMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
            title="Trustworthy AI Guardrails - Evaluation Report",
            author="Tisha Manandhar",
        )
        doc.build(story, onFirstPage=empty_page_decoration, onLaterPages=empty_page_decoration)
        print(f"Successfully generated clean report: {pdf_path.name}")


if __name__ == "__main__":
    build_all_pdfs()
