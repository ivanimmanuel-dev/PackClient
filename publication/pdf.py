"""Print-first typesetting of the publication's shared research content."""
from pathlib import Path
import copy
import datetime as dt
import html
import json
import os
import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin

import markdown
from reportlab.graphics import renderPDF
from reportlab.lib.colors import HexColor, white
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Flowable, Frame, KeepInFrame, KeepTogether,
    NextPageTemplate, PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

from model import *
from diagrams import DIAGRAMS

PW, PH = A4
LEFT = RIGHT = 49
TOP, BOTTOM = 58, 51
CW = PW - LEFT - RIGHT
INK = HexColor('#182a36')
MUTED = HexColor('#596873')
TEAL = HexColor('#087e83')
LINE = HexColor('#d5dedf')
PALE = HexColor('#edf4f3')
FONTDIR = Path(os.environ.get('PACKCLIENT_FONT_DIR', '/usr/share/fonts/truetype/dejavu'))
for name, filename in [
    ('Body', 'DejaVuSerif.ttf'), ('Body-Bold', 'DejaVuSerif-Bold.ttf'),
    ('Body-Italic', 'DejaVuSerif-Italic.ttf'), ('Sans', 'DejaVuSans.ttf'),
    ('Sans-Bold', 'DejaVuSans-Bold.ttf'), ('Sans-Italic', 'DejaVuSans-Oblique.ttf'),
    ('Mono', 'DejaVuSansMono.ttf'),
]:
    path = FONTDIR / filename
    if not path.exists():
        raise SystemExit('Install fonts-dejavu-core or set PACKCLIENT_FONT_DIR to the DejaVu font directory.')
    pdfmetrics.registerFont(TTFont(name, str(path)))
pdfmetrics.registerFontFamily('Body', normal='Body', bold='Body-Bold', italic='Body-Italic', boldItalic='Body-Bold')
pdfmetrics.registerFontFamily('Sans', normal='Sans', bold='Sans-Bold', italic='Sans-Italic', boldItalic='Sans-Bold')

S = {
    'body': ParagraphStyle('Body', fontName='Body', fontSize=10, leading=15.1,
        textColor=INK, spaceAfter=10.5, allowWidows=0, allowOrphans=0),
    'deck': ParagraphStyle('Deck', fontName='Sans', fontSize=10.25, leading=15.1,
        textColor=MUTED, spaceAfter=17, keepWithNext=True),
    'h1': ParagraphStyle('Chapter', fontName='Sans-Bold', fontSize=21, leading=26,
        textColor=INK, spaceAfter=12, keepWithNext=True),
    'h2': ParagraphStyle('Section', fontName='Sans-Bold', fontSize=12.1, leading=17,
        textColor=INK, spaceBefore=14, spaceAfter=9, keepWithNext=True),
    'kicker': ParagraphStyle('Kicker', fontName='Sans-Bold', fontSize=7.5, leading=11,
        textColor=TEAL, spaceAfter=8, keepWithNext=True),
    'caption': ParagraphStyle('Caption', fontName='Sans', fontSize=8.2, leading=11.8,
        textColor=MUTED, spaceAfter=7, allowWidows=0, allowOrphans=0),
    'figtitle': ParagraphStyle('FigureTitle', fontName='Sans-Bold', fontSize=9.1, leading=12.8,
        textColor=INK, spaceAfter=7, keepWithNext=True),
    'source': ParagraphStyle('Source', fontName='Sans', fontSize=7.2, leading=10.5,
        textColor=TEAL, spaceAfter=10),
    'cell': ParagraphStyle('Cell', fontName='Sans', fontSize=8, leading=11.3,
        textColor=INK, spaceAfter=0, allowWidows=1, allowOrphans=1),
    'headcell': ParagraphStyle('HeaderCell', fontName='Sans-Bold', fontSize=7.8, leading=11,
        textColor=INK, spaceAfter=0),
    'small': ParagraphStyle('Small', fontName='Sans', fontSize=8.3, leading=12.3,
        textColor=MUTED, spaceAfter=10),
    'toc': ParagraphStyle('Toc', fontName='Sans', fontSize=9.4, leading=14.1,
        textColor=INK, spaceBefore=8, leftIndent=0, rightIndent=25),
    'hash': ParagraphStyle('Hash', fontName='Mono', fontSize=7.6, leading=11.5,
        textColor=INK, spaceAfter=0),
    'reference': ParagraphStyle('Reference', fontName='Sans', fontSize=8.6, leading=12.6,
        textColor=INK, spaceAfter=3),
    'url': ParagraphStyle('URL', fontName='Mono', fontSize=6.8, leading=10,
        textColor=MUTED, spaceAfter=10, splitLongWords=True),
}


def esc(value):
    return html.escape(str(value), quote=True)


def absolute(link):
    return urljoin(SITE + '/', link)


def date_text(value):
    return dt.date.fromisoformat(value).strftime('%d %B %Y').lstrip('0')


# A print bibliography makes the article's existing citations useful off-screen.
REFERENCES = {}
for _section in SECTIONS:
    for _block in _section['blocks']:
        if _block['type'] != 'md':
            continue
        _root = ET.fromstring('<root>' + markdown.markdown(_block['text'], extensions=['tables', 'fenced_code']) + '</root>')
        for _a in _root.iter('a'):
            _url = absolute(_a.get('href', ''))
            if _url not in REFERENCES:
                REFERENCES[_url] = (len(REFERENCES) + 1, ''.join(_a.itertext()))


def inline(element):
    out = esc(element.text or '')
    for child in element:
        value = inline(child)
        if child.tag in ('strong', 'b'):
            out += '<b>' + value + '</b>'
        elif child.tag in ('em', 'i'):
            out += '<i>' + value + '</i>'
        elif child.tag == 'code':
            out += '<font name="Mono" size="8.1">' + value + '</font>'
        elif child.tag == 'a':
            url = absolute(child.get('href', ''))
            out += f'<link href="{esc(url)}" color="#087e83">{value}</link>'
            if url in REFERENCES:
                out += f'<super><font name="Sans" size="6.2">[{REFERENCES[url][0]}]</font></super>'
        elif child.tag == 'br':
            out += '<br/>'
        else:
            out += value
        out += esc(child.tail or '')
    return out


def table(rows, header=True, widths=None, compact=False):
    count = len(rows[0])
    if widths is None:
        labels = [re.sub('<[^>]+>', '', str(c)).lower() for c in rows[0]]
        if labels[:2] == ['offset', 'bytes']:
            proportions = [.14, .13, .73]
        elif labels[0] == 'type':
            proportions = [.09, .21, .23, .47]
        elif count == 2:
            proportions = [.30, .70]
        elif count == 3:
            proportions = [.24, .36, .40]
        elif count == 4:
            proportions = [.20, .22, .23, .35]
        else:
            proportions = [1 / count] * count
        widths = [CW * part for part in proportions]
    cell_style = ParagraphStyle('CompactCell', parent=S['cell'], fontSize=7.6, leading=10.5) if compact else S['cell']
    data = [[Paragraph(str(cell), S['headcell'] if header and row == 0 else cell_style)
        for cell in cells] for row, cells in enumerate(rows)]
    result = Table(data, colWidths=widths, repeatRows=1 if header else 0,
        hAlign='LEFT', splitByRow=1, spaceBefore=4, spaceAfter=15)
    commands = [
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 7),
        ('RIGHTPADDING', (0, 0), (-1, -1), 7),
        ('TOPPADDING', (0, 0), (-1, -1), 6 if compact else 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7 if compact else 9),
        ('LINEBELOW', (0, 0), (-1, -1), .45, LINE),
    ]
    if header:
        commands.extend([
            ('BACKGROUND', (0, 0), (-1, 0), PALE),
            ('LINEABOVE', (0, 0), (-1, 0), .9, TEAL),
        ])
    result.setStyle(TableStyle(commands))
    return [result]


class CodeBlock(Flowable):
    """Literal, selectable code with a bounded type size and print-safe measure."""
    def __init__(self, value):
        super().__init__()
        self.lines = value.rstrip().splitlines()
        widest = max((pdfmetrics.stringWidth(line, 'Mono', 8.1) for line in self.lines), default=1)
        self.size = min(8.1, 8.1 * (CW - 25) / max(widest, 1))
        self.leading = self.size * 1.55
        self.width = CW
        self.height = len(self.lines) * self.leading + 23
        self.spaceBefore = 5
        self.spaceAfter = 15

    def draw(self):
        canvas = self.canv
        canvas.setFillColor(PALE)
        canvas.rect(0, 0, self.width, self.height, fill=1, stroke=0)
        canvas.setFillColor(TEAL)
        canvas.rect(0, 0, 2, self.height, fill=1, stroke=0)
        canvas.setFillColor(INK)
        canvas.setFont('Mono', self.size)
        for index, line in enumerate(self.lines):
            canvas.drawString(12, self.height - 15 - index * self.leading, line)


def markdown_flows(text):
    rendered = markdown.markdown(text, extensions=['tables', 'fenced_code'])
    root = ET.fromstring('<root>' + rendered + '</root>')
    flows = []
    for element in root:
        if element.tag == 'p':
            flows.append(Paragraph(inline(element), S['body']))
        elif element.tag in ('h2', 'h3', 'h4'):
            flows.append(Paragraph(inline(element), S['h2']))
        elif element.tag == 'table':
            rows = [[inline(cell) for cell in row] for row in element.findall('.//tr')]
            table_parts = table(rows, compact=rows[0][0] == 'Documented gap')
            flows += [KeepTogether(table_parts)] if len(rows) <= 5 else table_parts
        elif element.tag == 'pre':
            flows.append(CodeBlock(''.join(element.itertext())))
        elif element.tag in ('ul', 'ol'):
            for index, item in enumerate(element.findall('li'), 1):
                style = ParagraphStyle('ListItem', parent=S['body'], leftIndent=14, firstLineIndent=-12)
                flows.append(Paragraph(('• ' if element.tag == 'ul' else str(index) + '. ') + inline(item), style))
        elif element.tag == 'blockquote':
            style = ParagraphStyle('Quote', parent=S['body'], leftIndent=13,
                borderColor=TEAL, borderWidth=.65, borderPadding=9, backColor=PALE)
            flows.append(Paragraph(inline(element), style))
    return flows


class Rule(Flowable):
    def __init__(self, width=CW):
        super().__init__()
        self.width, self.height = width, 9

    def draw(self):
        self.canv.setStrokeColor(LINE)
        self.canv.setLineWidth(.6)
        self.canv.line(0, 4, self.width, 4)


class FigureBlock(KeepInFrame):
    """Keep a figure and caption together at their original readable scale."""
    def __init__(self, content):
        super().__init__(CW, PH - TOP - BOTTOM, content, mode='error')

    def wrap(self, available_width, available_height):
        # Measure at full page height. The frame moves the whole block when
        # the remaining space is insufficient; the evidence is never shrunk.
        return super().wrap(available_width, PH - TOP - BOTTOM)

    def drawOn(self, canvas, x, y, _sW=0):
        if canvas.getPageNumber() in canvas._doctemplate.figure_only_pages:
            y = BOTTOM + (PH - TOP - BOTTOM - self.height) / 2
        super().drawOn(canvas, x, y, _sW=_sW)


def print_drawing(drawing):
    """Recolor the same vector geometry for paper; no semantic changes."""
    drawing = copy.deepcopy(drawing)
    palette = {
        '#101923': '#ffffff', '#0d1720': '#ffffff',
        '#16332f': '#edf5f2', '#352c1c': '#faf3e7', '#182634': '#f3f6f7',
        '#e3eaf0': '#182a36', '#a7b9c8': '#566873', '#83e1cd': '#087e83',
        '#385064': '#b7c7cc', '#efc582': '#956d25',
        '#233b5a': '#e4edf5', '#204335': '#e7f0e7', '#513031': '#f4e8e8', '#303844': '#eceff2',
    }
    def visit(node):
        for attr in ('fillColor', 'strokeColor'):
            color = getattr(node, attr, None)
            if color is not None and hasattr(color, 'hexval'):
                key = '#' + color.hexval()[2:].lower()
                if key in palette:
                    setattr(node, attr, HexColor(palette[key]))
        for child in getattr(node, 'contents', []):
            visit(child)
    visit(drawing)
    return drawing


class Vector(Flowable):
    def __init__(self, drawing):
        super().__init__()
        self.drawing = print_drawing(drawing)
        self.scale = CW / drawing.width
        self.width, self.height = CW, drawing.height * self.scale

    def draw(self):
        self.canv.saveState()
        self.canv.scale(self.scale, self.scale)
        renderPDF.draw(self.drawing, self.canv, 0, 0)
        self.canv.restoreState()


class EvidencePanel(Flowable):
    """Place original pixels at column width, clipping only at a page continuation."""
    def __init__(self, figure, start=0, end=1, width=CW):
        super().__init__()
        self.figure = figure
        self.start, self.end = start, end
        self.width = width
        self.full_height = width * figure['height'] / figure['width']
        self.height = self.full_height * (end - start)

    def draw(self):
        canvas = self.canv
        canvas.saveState()
        path = canvas.beginPath()
        path.rect(0, 0, self.width, self.height)
        canvas.clipPath(path, stroke=0)
        canvas.drawImage(str(ROOT / self.figure['asset']), 0,
            self.height - self.full_height * (1 - self.start),
            width=self.width, height=self.full_height, mask='auto')
        canvas.restoreState()


class EvidenceRegion(Flowable):
    """Place a detail from the retained source figure without resampling it."""
    def __init__(self, figure, bounds, width=CW):
        super().__init__()
        self.figure = figure
        self.left, self.top, right, bottom = bounds
        self.scale = width / (right - self.left)
        self.width, self.height = width, (bottom - self.top) * self.scale

    def draw(self):
        canvas = self.canv
        canvas.saveState()
        path = canvas.beginPath()
        path.rect(0, 0, self.width, self.height)
        canvas.clipPath(path, stroke=0)
        canvas.drawImage(str(ROOT / self.figure['asset']), -self.left * self.scale,
            self.height - (self.figure['height'] - self.top) * self.scale,
            width=self.figure['width'] * self.scale,
            height=self.figure['height'] * self.scale, mask='auto')
        canvas.restoreState()


def process_chain_flows(figure, number):
    # A portrait detail keeps the process rows close to their landscape scale.
    # The long schtasks command continues below at the same scale with overlap;
    # the other three command lines fit completely in the first detail.
    return [FigureBlock([
        Spacer(1,5), Paragraph(f'FIGURE {number:02d} · {grade_label(figure["grade"]).upper()}', S['kicker']),
        Paragraph(esc(figure['title']), S['figtitle']),
        Paragraph('A / Creating process, PID, operation and result', S['figtitle']),
        EvidenceRegion(figure, (118, 181, 1489, 327)), Spacer(1,15),
        Paragraph('B / Corresponding child PIDs and command lines', S['figtitle']),
        EvidenceRegion(figure, (118, 524, 1138, 668)), Spacer(1,7),
        Paragraph('PID 4600 command, continued (path segment repeated):', S['caption']),
        EvidenceRegion(figure, (898, 613, 1768, 641), width=CW * 870 / 1020),
        Spacer(1,12), Paragraph(esc(figure['caption']), S['caption']),
        Paragraph(
            f'<link href="{SITE}/evidence.html#runtime-process-chain">Source and analysis</link> · '
            f'<link href="{SITE}/{figure["asset_url"]}">Full-resolution figure</link>', S['source']),
    ]), Spacer(1,8)]


def evidence_flows(fid):
    figure = FM[fid]
    number = NUMBERS[fid]
    if fid == 'runtime-process-chain':
        return process_chain_flows(figure, number)
    # The tall worker-failure plate continues between its evidence panels.
    breaks = {'worker-failure': (0, 700 / 1812, 1)}
    stops = breaks.get(fid, (0, 1))
    flows = []
    for part, (start, end) in enumerate(zip(stops, stops[1:])):
        suffix = ' / CONTINUED' if part else ''
        title = f'FIGURE {number:02d}{suffix}'
        label = grade_label(figure['grade']).upper()
        panel = [Spacer(1,5), Paragraph(title + ' · ' + label, S['kicker'])]
        if not part:
            panel.append(Paragraph(esc(figure['title']), S['figtitle']))
        panel.extend([EvidencePanel(figure, start, end), Spacer(1,9)])
        if part == len(stops) - 2:
            panel.append(Paragraph(esc(figure['caption']), S['caption']))
            panel.append(Paragraph(
                f'<link href="{SITE}/evidence.html#{fid}">Source and analysis</link> · '
                f'<link href="{SITE}/{figure["asset_url"]}">Full-resolution figure</link>', S['source']))
        else:
            panel.append(Paragraph('Figure continues with the remaining evidence panels.', S['source']))
        flows.append(FigureBlock(panel))
    return flows + [Spacer(1,8)]


def diagram_flows(fid):
    title, make = DIAGRAMS[fid]
    scope = ('Native-event correlation; process times rounded to microseconds.'
        if fid == 'process-tree' else 'Static reconstruction; not a captured exchange.')
    return [FigureBlock([
        Spacer(1,5), Paragraph(f'FIGURE {NUMBERS[fid]:02d} · TECHNICAL DIAGRAM', S['kicker']),
        Vector(make()), Spacer(1,7),
        Paragraph('<b>' + esc(title) + '</b> ' + scope, S['caption']), Spacer(1,10),
    ])]


def cover(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(white)
    canvas.rect(0, 0, PW, PH, fill=1, stroke=0)
    canvas.setFillColor(TEAL)
    canvas.rect(LEFT, PH - 63, 42, 3, fill=1, stroke=0)
    canvas.setFont('Sans-Bold', 7.7)
    canvas.drawString(LEFT + 55, PH - 64, 'MALWARE ANALYSIS / REVERSE ENGINEERING')
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(.6)
    canvas.line(LEFT, BOTTOM + 59, PW - RIGHT, BOTTOM + 59)
    canvas.setFont('Sans-Bold', 8)
    canvas.setFillColor(INK)
    canvas.drawString(LEFT, BOTTOM + 37, AUTHOR)
    canvas.setFont('Sans', 8)
    canvas.setFillColor(MUTED)
    canvas.drawString(LEFT, BOTTOM + 17, 'Published: ' + date_text(DATA['date']))
    canvas.drawString(LEFT, BOTTOM, 'Research cutoff: ' + date_text(DATA.get('research_cutoff', '2026-09-05')) + ' (UTC)')
    canvas.restoreState()


def body_end(canvas, doc):
    canvas.saveState()
    page_width, page_height = canvas._pagesize
    measure = page_width - LEFT - RIGHT
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(.55)
    canvas.line(LEFT, page_height - 38, page_width - RIGHT, page_height - 38)
    canvas.line(LEFT, 37, page_width - RIGHT, 37)
    canvas.setFillColor(MUTED)
    canvas.setFont('Sans', 6.6)
    canvas.drawString(LEFT, page_height - 29, 'PACKCLIENT / TECHNICAL REPORT')
    title = doc.page_running.upper()
    while pdfmetrics.stringWidth(title, 'Sans', 6.6) > measure - 159:
        title = title[:-2]
    canvas.drawRightString(page_width - RIGHT, page_height - 29, title)
    canvas.drawString(LEFT, 24, AUTHOR.upper())
    canvas.setFont('Sans-Bold', 7.2)
    canvas.drawRightString(page_width - RIGHT, 24, str(doc.page))
    canvas.restoreState()


class PublicationDoc(BaseDocTemplate):
    def beforeDocument(self):
        # multiBuild repeats pagination; reset the running title each pass.
        self.running = 'Contents'
        self.page_running = 'Contents'
        self.figure_only_pages = getattr(self, 'next_figure_only_pages', set())
        self.next_figure_only_pages = set()

    def beforePage(self):
        self.page_running = self.running
        self.page_has_content = False
        self.page_has_prose = False
        self.page_figures = []

    def afterPage(self):
        if len(self.page_figures) == 1 and not self.page_has_prose:
            self.next_figure_only_pages.add(self.page)

    def _allSatisfied(self):
        # Final drawing uses the stable pagination pass, as does the contents.
        return super()._allSatisfied() and self.figure_only_pages == self.next_figure_only_pages

    def afterFlowable(self, flowable):
        if hasattr(flowable, 'section_key'):
            key, title = flowable.section_key, flowable.section_title
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(title, key, 0, False)
            self.notify('TOCEntry', (0, title, self.page, key))
            self.running = flowable.running_title
            if not self.page_has_content:
                self.page_running = self.running
        if isinstance(flowable, FigureBlock):
            self.page_has_content = True
            self.page_figures.append(flowable)
        elif isinstance(flowable, (Table, EvidencePanel, EvidenceRegion, Vector, CodeBlock)) or (
            isinstance(flowable, Paragraph) and flowable.style.name != 'Kicker'
        ):
            self.page_has_content = True
            self.page_has_prose = True


def heading(title, key, toc_title, label):
    result = Paragraph(esc(title), S['h1'])
    result.section_key, result.section_title = key, toc_title
    result.running_title = title
    return [Paragraph(label, S['kicker']), result]


def print_blocks(section):
    """Keep figure context beside large plates without changing shared text."""
    blocks = list(section['blocks'])
    if section['id'] == 'screenshot-ipc':
        # Introduce the state diagram before its large plate. The header-layout
        # paragraph remains immediately before the following layout diagram.
        for index, block in enumerate(blocks[:-1]):
            if block.get('id') == 'worker-state' and blocks[index + 1]['type'] == 'md':
                before, separator, after = blocks[index + 1]['text'].partition('\n\nThe header')
                if separator:
                    blocks[index:index + 2] = [
                        {'type': 'md', 'text': before}, block,
                        {'type': 'md', 'text': 'The header' + after},
                    ]
                break
    elif section['id'] == 'connectivity':
        # The attribution table introduces the socket plate in the print report.
        # The separate late-capture discussion follows that plate.
        for index, block in enumerate(blocks[:-1]):
            if block.get('id') == 'socket-observations' and blocks[index + 1]['type'] == 'md':
                before, separator, after = blocks[index + 1]['text'].partition('\n\n### ')
                if separator:
                    blocks[index:index + 2] = [
                        {'type': 'md', 'text': before}, block,
                        {'type': 'md', 'text': '### ' + after},
                    ]
                break
    elif section['id'] == 'runtime-chain':
        # Keep the process relationship beside its diagram; the source details
        # then lead into the separate installation evidence.
        for index, block in enumerate(blocks[:-1]):
            if block.get('id') == 'runtime-process-chain' and blocks[index + 1]['type'] == 'md':
                before, separator, after = blocks[index + 1]['text'].partition('\n\n')
                if separator:
                    blocks[index:index + 2] = [
                        {'type': 'md', 'text': before}, block,
                        {'type': 'md', 'text': after},
                    ]
                break
        # The dump/package comparison is separate from the process-properties
        # screenshot. Place it after the plate to avoid a text-only spill page.
        for index, block in enumerate(blocks[1:], 1):
            if block.get('id') == 'surrogate-process' and blocks[index - 1]['type'] == 'md':
                before, separator, after = blocks[index - 1]['text'].partition('\n\n')
                if separator:
                    blocks[index - 1:index + 1] = [
                        {'type': 'md', 'text': before}, block,
                        {'type': 'md', 'text': after},
                    ]
                break
    return blocks


def make_pdf():
    output = DIST / 'PackClient.pdf'
    DIST.mkdir(parents=True, exist_ok=True)
    document = PublicationDoc(str(output), pagesize=A4, leftMargin=LEFT,
        rightMargin=RIGHT, topMargin=TOP, bottomMargin=BOTTOM,
        title=f'{TITLE}: {SUBTITLE}',
        author=AUTHOR, subject=SUBTITLE, pageCompression=1, invariant=1)
    frame = Frame(LEFT, BOTTOM, CW, PH - TOP - BOTTOM, leftPadding=0,
        bottomPadding=0, rightPadding=0, topPadding=0, id='article')
    document.addPageTemplates([
        PageTemplate(id='Cover', frames=[frame], onPage=cover, pagesize=A4),
        PageTemplate(id='Body', frames=[frame], onPageEnd=body_end, pagesize=A4),
    ])
    cover_title = ParagraphStyle('CoverTitle', fontName='Sans-Bold', fontSize=43,
        leading=49, textColor=INK, spaceAfter=16)
    cover_subtitle = ParagraphStyle('CoverSubtitle', fontName='Body', fontSize=23,
        leading=31, textColor=INK, spaceAfter=32)
    cover_abstract = ParagraphStyle('CoverAbstract', fontName='Body', fontSize=10.3,
        leading=16.3, textColor=MUTED, spaceAfter=18)
    abstract = DATA.get('abstract',
        'This report examines a recovered PackClientLauncher build: its 1RCP screenshot interface, '
        'authentication and delivery path, and correspondence with two runtime evidence sets. '
        'The recovered worker contract specifies a 20-byte header and raw top-down BGRX frames. '
        'Runtime evidence establishes launcher residence and attempted connectivity; '
        'Core and the external screenshot peer remain unrecovered.')
    story = [
        Spacer(1,71), Paragraph(esc(TITLE), cover_title),
        Paragraph('Reverse Engineering a<br/>Modular RAT Framework', cover_subtitle),
        Paragraph('ABSTRACT', S['kicker']), Paragraph(esc(abstract), cover_abstract),
        Paragraph('<b>Analysis scope</b> — ' + esc(DATA.get('status', 'PackClientLauncher code and runtime evidence')), S['small']),
        NextPageTemplate('Body'), PageBreak(),
        Paragraph('CONTENTS', S['kicker']), Paragraph('The research', S['h1']),
        Paragraph('PackClientLauncher: reconstructed interfaces, runtime evidence and the limits of the recovered build.', S['deck']),
    ]
    toc = TableOfContents()
    toc.levelStyles = [S['toc']]
    toc.dotsMinLevel = 0
    story.append(toc)
    story += [Spacer(1,20), Rule(), Spacer(1,8),
        Paragraph(f'<link href="{SITE}">Online article and full-resolution figures</link> · '
            f'<link href="{SITE}/references.html">Technical references and tooling</link>', S['source']),
        PageBreak()]
    for index, section in enumerate(SECTIONS, 1):
        if index > 1:
            story.append(PageBreak())
        story += heading(section['title'], section['id'], f'{index:02d}  {section["title"]}',
            f'{index:02d} / ' + ('TECHNICAL SUMMARY' if index == 1 else 'RESEARCH'))
        story.append(Paragraph(esc(section['deck']), S['deck']))
        for block in print_blocks(section):
            if block['type'] == 'md':
                story += markdown_flows(block['text'])
            elif block['type'] == 'figure':
                story += evidence_flows(block['id'])
            else:
                story += diagram_flows(block['id'])

    story += [PageBreak()]
    story += heading('Recorded identities', 'appendix-identities', 'Appendix A  Recorded identities', 'APPENDIX A')
    story.append(Paragraph('Complete SHA-256 values for the artifacts cited in the research. Short identifiers in the article are reading aids.', S['deck']))
    for name, size, digest in IDENTITIES:
        chunks = ' '.join(digest[start:start+16] for start in range(0,64,16))
        story.append(KeepTogether([
            Paragraph(esc(name) + ' <font name="Sans" color="#596873">/ ' + esc(size) + '</font>', S['figtitle']),
            Paragraph(chunks, S['hash']), Spacer(1,10), Rule(), Spacer(1,8),
        ]))
    story += [Paragraph('Source access', S['h2']), Paragraph(
        'Raw malware, virtual-machine disks, dumps and captures are not redistributed. '
        'The technical references preserve artifact identities and the limits of the available evidence. '
        'The repository contains the research, selected figures, inspection tools and the optional synthetic IPC kit with its tests.', S['body'])]

    story += [PageBreak()]
    story += heading('Figure index', 'appendix-figures', 'Appendix B  Figure index', 'APPENDIX B')
    rows = [['Figure', 'Material', 'Title']]
    for fid, number in sorted(NUMBERS.items(), key=lambda item: item[1]):
        title = FM[fid]['title'] if fid in FM else DIAGRAMS[fid][0]
        kind = 'Screenshot' if fid in FM else 'Diagram'
        link = f'{SITE}/evidence.html#{fid}' if fid in FM else f'{SITE}/assets/diagrams/{fid}.svg'
        rows.append([str(number), kind, f'<link href="{link}">{esc(title)}</link>'])
    story += table(rows, widths=[CW*.09, CW*.18, CW*.73], compact=True)

    story += [PageBreak()]
    story += heading('References', 'appendix-references', 'Appendix C  References', 'APPENDIX C')
    story.append(Paragraph('Numbered references correspond to the citations in the article. Technical references provide the focused supporting analysis; external sources establish prior work and API contracts.', S['deck']))
    for url, (number, title) in REFERENCES.items():
        story.append(KeepTogether([
            Paragraph(f'<b>[{number}]</b> <link href="{esc(url)}">{esc(title)}</link>', S['reference']),
            Paragraph(esc(url), S['url']),
        ]))
    document.multiBuild(story)
    print(json.dumps({'pdf': str(output), 'pages': document.page, 'bytes': output.stat().st_size}))


if __name__ == '__main__':
    make_pdf()
