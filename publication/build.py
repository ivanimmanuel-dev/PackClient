"""Build the standalone static publication from curated, local inputs only."""
from pathlib import Path
import hashlib, html, json, posixpath, re, shutil
from urllib.parse import unquote, urlsplit
import markdown
from PIL import Image
from reportlab.graphics import renderSVG
from model import *
from diagrams import DIAGRAMS

# Version presentation assets so an updated article cannot retain cached styling.
STYLE_FILE = "style-" + hashlib.sha256((ROOT / "publication/site.css").read_bytes()).hexdigest()[:12] + ".css"
SCRIPT_FILE = "script-" + hashlib.sha256((ROOT / "publication/site.js").read_bytes()).hexdigest()[:12] + ".js"
# Change download URLs with report inputs so browsers request the updated PDF.
_pdf_inputs = [ROOT / 'CITATION.cff', *(ROOT / 'publication' / name for name in
    ('pdf.py', 'article.json', 'figures.json', 'diagrams.py', 'model.py')),
    *(ROOT / figure['asset'] for figure in FIGURES)]
PDF_FILE = 'PackClient.pdf?v=' + hashlib.sha256(b''.join(path.read_bytes() for path in _pdf_inputs)).hexdigest()[:12]


def esc(value): return html.escape(str(value), quote=True)

def md(text):
    result = markdown.markdown(text, extensions=['tables', 'fenced_code', 'toc'])
    return re.sub(r'(<table>.*?</table>)', r'<div class="table-scroll" role="region" aria-label="Scrollable data table" tabindex="0">\1</div>', result, flags=re.S)


def published_date():
    from datetime import date
    return date.fromisoformat(DATA['date']).strftime('%d %B %Y')


def shell(title, body, prefix='', kind='article', description=SUBTITLE, page='index.html'):
    canonical = SITE + '/' + ('' if page == 'index.html' else page)
    image_url = SITE + '/' + SOCIAL_IMAGE
    with Image.open(ROOT / SOCIAL_IMAGE) as social_image:
        image_width, image_height = social_image.size
    is_article = page == 'index.html'
    metadata = {
        'og:title': title, 'og:description': description, 'og:url': canonical,
        'og:type': 'article' if is_article else 'website', 'og:site_name': TITLE,
        'og:image': image_url, 'og:image:type': 'image/png',
        'og:image:width': image_width, 'og:image:height': image_height,
        'og:image:alt': SOCIAL_ALT,
    }
    if is_article: metadata['article:published_time'] = DATA['date']
    sharing = '\n'.join(f'<meta property="{key}" content="{esc(value)}">' for key, value in metadata.items())
    twitter = {'twitter:card': 'summary_large_image', 'twitter:title': title,
               'twitter:description': description, 'twitter:image': image_url, 'twitter:image:alt': SOCIAL_ALT}
    sharing += '\n' + '\n'.join(f'<meta name="{key}" content="{esc(value)}">' for key, value in twitter.items())
    if is_article:
        article = {'@context': 'https://schema.org', '@type': 'ScholarlyArticle',
                   'headline': REPORT_TITLE, 'description': description, 'url': canonical,
                   'mainEntityOfPage': canonical, 'image': image_url,
                   'author': {'@type': 'Person', 'name': AUTHOR},
                   'datePublished': DATA['date'], 'version': VERSION, 'inLanguage': 'en',
                   'encoding': {'@type': 'MediaObject', 'contentUrl': SITE + '/PackClient.pdf', 'encodingFormat': 'application/pdf'}}
        # Keep JSON data from accidentally terminating the script element.
        structured = json.dumps(article, ensure_ascii=False).replace('<', '\\u003c')
        sharing += '\n<script type="application/ld+json">' + structured + '</script>'
    nav=' '.join(f'<a href="{prefix}{link}"'+(' aria-current="page"' if kind==key else '')+f'>{label}</a>' for key,link,label in [('article','index.html','Article'),('evidence','evidence.html','Evidence'),('references','references.html','References')])
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="{esc(description)}"><meta name="author" content="{esc(AUTHOR)}"><meta name="theme-color" content="#10161e"><meta name="color-scheme" content="dark"><title>{esc(title)} · {esc(AUTHOR)}</title><link rel="canonical" href="{esc(canonical)}">
{sharing}
<link rel="stylesheet" href="{prefix}{STYLE_FILE}"><link rel="icon" href="{prefix}assets/favicon.svg" type="image/svg+xml"></head>
<body class="{kind}"><a class="skip" href="#main">Skip to content</a><header class="site-header"><div class="nav-shell"><a class="wordmark" href="{prefix}index.html">PackClient</a><nav aria-label="Main navigation">{nav} <a class="nav-pdf" href="{prefix}{PDF_FILE}">PDF <span aria-hidden="true">↗</span></a></nav></div></header>{body}
<footer class="site-footer"><div><strong>{esc(AUTHOR)}</strong> <p>PackClient research · {published_date()}</p> <p><a href="{prefix}references.html#citation">Citation · Version {esc(VERSION)}</a></p></div><nav aria-label="Publication resources"><a href="{prefix}references/tooling.html">Tools</a> <a href="{prefix}references/prior-work.html">Prior work</a> <a href="{REPO}">GitHub <span aria-hidden="true">↗</span></a></nav><a href="{prefix}{PDF_FILE}">Download the technical report <span aria-hidden="true">↗</span></a></footer>
<dialog id="figure-dialog" aria-labelledby="dialog-title"><div class="dialog-top"><h2 id="dialog-title">Figure</h2><div class="dialog-actions"><button id="figure-scale" type="button" aria-pressed="false">Native size</button><button class="close-dialog" type="button" aria-label="Close enlarged figure">Close ×</button></div></div><div class="dialog-scroll"><img id="dialog-image" alt="Enlarged figure"></div><p id="dialog-caption"></p><a id="dialog-original" href="#" target="_blank" rel="noopener">Open figure at full resolution ↗</a></dialog><script src="{prefix}{SCRIPT_FILE}" defer></script></body></html>'''


def figure(fid):
    f=FM[fid]; n=NUMBERS[fid]
    grade=grade_label(f['grade'])
    return f'''<figure class="evidence-figure" id="fig-{fid}"><div class="figure-top"><span class="eyebrow">Figure {n:02d} / {esc(grade)}</span> <a class="zoom-figure" href="{f['asset_url']}" data-title="{esc(f['title'])}" data-caption="{esc(f['caption'])}" aria-label="Enlarge figure {n}: {esc(f['title'])}">Enlarge ↗</a></div><a class="zoom-figure figure-image" href="{f['asset_url']}" data-title="{esc(f['title'])}" data-caption="{esc(f['caption'])}" aria-label="Enlarge figure {n}: {esc(f['title'])}"><img loading="lazy" decoding="async" width="{f['width']}" height="{f['height']}" src="{f['asset_url']}" alt="{esc(f['title'])}"></a><figcaption><strong>{esc(f['title'])}</strong> {esc(f['caption'])} <span class="figure-refs"><a href="evidence.html#{fid}">Source and context ↗</a></span></figcaption></figure>'''


def diagram(fid):
    title,fn=DIAGRAMS[fid]; d=fn(); n=NUMBERS[fid]
    captions = {
        'architecture': 'Reconstructed from the signed host, carrier, embedded package, Launcher, and historical PLK1 traffic.',
        'worker-state': 'Reconstructed from the screenshot worker’s capture loop and command dispatch.',
        'worker-layout': 'Reconstructed from the worker’s five-DWORD request and response structures.',
        'envelope': 'Reconstructed from the Launcher’s authenticated receive path.',
        'cache': 'Reconstructed from the Launcher’s PLK1 verification and cache-control flow.',
        'process-tree': 'Built from recorded process-creation events; process lifetimes separate reused PIDs.',
    }
    caption = captions[fid]
    asset=f'assets/diagrams/{fid}.svg'
    asset += '?v=' + hashlib.sha256((DIST / asset).read_bytes()).hexdigest()[:12]
    return f'''<figure class="diagram-figure" id="fig-{fid}"><div class="figure-top"><span class="eyebrow">Figure {n:02d} / reconstructed flow</span> <a class="zoom-figure" href="{asset}" data-title="{esc(title)}" data-caption="{esc(caption)}" aria-label="Enlarge figure {n}: {esc(title)}">Enlarge ↗</a></div><a class="zoom-figure figure-image" href="{asset}" data-title="{esc(title)}" data-caption="{esc(caption)}" aria-label="Enlarge figure {n}: {esc(title)}"><img loading="lazy" width="{d.width}" height="{d.height}" src="{asset}" alt="{esc(title)}"></a><figcaption><strong>{esc(title)}</strong> {caption}</figcaption></figure>'''


def build_article():
    toc=''.join(f'<li><a href="#{s["id"]}"><span>{i:02d}</span> {esc(s.get("nav_title", s["title"]))}</a></li>' for i,s in enumerate(SECTIONS,1))
    chapters=[]
    for i,s in enumerate(SECTIONS,1):
        blocks=''.join(md(b['text']) if b['type']=='md' else figure(b['id']) if b['type']=='figure' else diagram(b['id']) for b in s['blocks'])
        chapters.append(f'<section class="chapter" id="{s["id"]}"><div class="chapter-heading"><span class="chapter-number" aria-hidden="true">{i:02d}</span> <h2>{esc(s["title"])}</h2></div><p class="deck">{esc(s["deck"])}</p>{blocks}</section>')
    cutoff = DATA.get('research_cutoff', DATA['date'])
    from datetime import date
    try: cutoff = date.fromisoformat(cutoff).strftime('%d %B %Y')
    except ValueError: pass
    abstract = DATA.get('abstract', 'This report reconstructs the PackClient Launcher and independently recovers its Core from historical PLK1 transfers while preserving the remaining plugin and screenshot-peer boundaries.')
    status = DATA.get('status', 'PackClient Launcher, recovered Core and historical transport evidence')
    key_findings = DATA.get('key_findings', [
        'Eight verified PLK1 transfers reconstruct one canonical <code>PackClientCore.dll</code>.',
        'Historical captures preserve successful Launcher delivery and post-Core traffic.',
        'Plugin binaries and the external <code>1RCP</code> peer remain unrecovered.'
    ])
    findings = ''.join(f'<li>{item}</li>' for item in key_findings)
    opening=f'''<header class="report-head" id="report"><p class="eyebrow">Malware analysis / reverse engineering</p><h1>{esc(TITLE)}</h1><p class="report-subtitle">{esc(SUBTITLE)}</p><p class="report-author">{esc(AUTHOR)}</p><dl class="report-meta"><div><dt>Published</dt> <dd><time datetime="{esc(DATA['date'])}">{published_date()}</time></dd></div> <div><dt>Research cutoff</dt> <dd>{esc(cutoff)} (UTC)</dd></div> <div class="research-status"><dt>Analysis scope</dt> <dd>{esc(status)}</dd></div></dl><div class="abstract"><h2>Abstract</h2>{md(abstract)}</div><div class="key-findings"><h2>Key findings</h2><ul>{findings}</ul></div></header>'''
    navigation=f'<ol>{toc}</ol>'
    body=f'''<main id="main" tabindex="-1"><details class="mobile-toc"><summary>In this report</summary><nav aria-label="Mobile report contents">{navigation}</nav></details><div class="reading-layout"><aside class="contents"><a class="contents-title" href="#report">In this report</a><nav aria-label="Report contents">{navigation}</nav><div class="contents-extra"><a href="evidence.html#identities">Sample hashes</a><a href="references.html">Technical notes</a><a href="{PDF_FILE}">Download PDF ↗</a></div></aside><article class="prose">{opening}{''.join(chapters)}<section class="report-resources" aria-labelledby="resources-heading"><h2 id="resources-heading">Continue reading</h2><p>Browse the <a href="references.html">technical notes</a> for the complete protocol, runtime, and tooling write-ups, or open <a href="evidence.html">samples and source figures</a> for hashes and figure provenance.</p></section></article></div></main>'''
    (DIST/'index.html').write_text(shell(REPORT_TITLE,body,description=abstract), encoding='utf-8')


GROUPS=[
('Launcher and Core','Component reconstruction, protocol behavior, screenshot paths, and session handoff.', [('launcher-architecture','Launcher architecture'),('core-analysis','PackClient Core'),('screenshot-ipc','Screenshot worker'),('launcher-protocol','Launcher protocol'),('active-session-handoff','Active-session handoff')]),
('Runtime and provenance','Process, memory, persistence, sample identity, limitations, and prior reporting.', [('runtime-analysis','Runtime analysis'),('evidence','Samples and provenance'),('limitations','Scope and limitations'),('prior-work','Prior work and contributions')]),
('Tools and detections','Offline decoders, screenshot test harnesses, Wireshark support, and detection guidance.', [('tooling','Analysis tools'),('screenshot-ipc-validation','Screenshot worker test harness'),('detection-guide','Detection guide')])]


def build_references():
    out=DIST/'references';out.mkdir(parents=True,exist_ok=True)
    for p in sorted((ROOT/'docs').glob('*.md')):
        source=p.read_text(encoding='utf-8')
        title=re.search(r'^#\s+(.+)$',source,re.M).group(1).replace('`','')
        content=md(source)
        def rewrite(m):
            attr,url=m.group(1),html.unescape(m.group(2)); parts=urlsplit(url)
            if parts.scheme or parts.netloc or url.startswith('#'): return m.group(0)
            target=(p.parent/unquote(parts.path)).resolve()
            rel=target.relative_to(ROOT)
            if target.suffix=='.md' and target.parent==ROOT/'docs': new=target.stem+'.html'
            elif rel.parts[0]=='assets': new='../'+rel.as_posix()
            else: new=REPO+('/tree/main/' if target.is_dir() else '/blob/main/')+rel.as_posix()
            if parts.fragment: new+='#'+parts.fragment
            return f'{attr}="{esc(new)}"'
        content=re.sub(r'(href|src)="([^"]+)"',rewrite,content)
        body=f'<main id="main" class="source-page" tabindex="-1"><div class="source-bar"><a href="../references.html">← Technical notes</a><a href="{REPO}/blob/main/docs/{p.name}">View source on GitHub ↗</a></div><article class="prose source-prose">{content}</article></main>'
        (out/(p.stem+'.html')).write_text(shell(title,body,'../',kind='references',description=f'{title}. {SUBTITLE}.',page=f'references/{p.stem}.html'), encoding='utf-8')
    groups=[]
    for title,desc,items in GROUPS:
        links=''.join(f'<li><a href="references/{slug}.html"><span>{esc(label)}</span> <span>↗</span></a></li>' for slug,label in items)
        groups.append(f'<section class="resource-group"><div><h2>{title}</h2><p>{desc}</p></div><ul>{links}</ul></section>')
    citation=f'<section class="resource-group" id="citation"><div><h2>Citation</h2><p>Version {esc(VERSION)} · {published_date()}</p></div><div><p>{esc(AUTHOR)}. ({DATA["date"][:4]}). <cite>{esc(REPORT_TITLE)}</cite> (Version {esc(VERSION)}). <a href="{SITE}/">{SITE}/</a></p><p><a href="CITATION.cff" download>Download CITATION.cff</a></p></div></section>'
    body=f'<main id="main" tabindex="-1"><div class="page-hero"><p class="eyebrow">Supporting research</p><h1>Technical notes</h1><p>Detailed write-ups for the Launcher, Core, network protocol, runtime behavior, and detection tooling.</p></div><div class="companion-body">{"".join(groups)}{citation}</div></main>'
    (DIST/'references.html').write_text(shell('Technical notes',body,kind='references',description='Detailed PackClient notes covering the Launcher, recovered Core, runtime behavior, protocol, tools, and detections.',page='references.html'), encoding='utf-8')


def build_evidence():
    rows=''.join(f'<tr><th scope="row">{esc(name)} <small>{esc(size)}</small></th><td><code class="hash">{digest}</code></td></tr>' for name,size,digest in IDENTITIES)
    entries=[]
    for fid,n in NUMBERS.items():
        if fid not in FM: continue
        f=FM[fid]
        entries.append(f'''<section class="ledger-entry" id="{fid}"><a class="ledger-thumb zoom-figure" href="{f['asset_url']}" data-title="{esc(f['title'])}" data-caption="{esc(f['caption'])}" aria-label="Enlarge figure {n}: {esc(f['title'])}"><img loading="lazy" decoding="async" width="{f['width']}" height="{f['height']}" src="{f['asset_url']}" alt="{esc(f['title'])}"></a><div><p class="eyebrow">Figure {n:02d} / {esc(grade_label(f['grade']))}</p> <h3>{esc(f['title'])}</h3> <p>{esc(f['caption'])}</p><p><strong>Source:</strong> {esc(f['source'])}</p><p><a href="{f['reference']}">Technical note ↗</a> · <a href="index.html#fig-{fid}">View in article ↗</a></p></div></section>''')
    body=f'''<main id="main" tabindex="-1"><div class="page-hero"><p class="eyebrow">Malware identities / source figures</p><h1>Samples and source figures</h1><p>Hashes for the analyzed files, followed by the screenshots used throughout the article.</p></div><div class="evidence-body"><section class="prose" id="identities"><h2>Sample hashes</h2><div class="table-scroll" role="region" aria-label="Sample and object hashes" tabindex="0"><table class="identity-table"><thead><tr><th>Sample or object</th><th>SHA-256</th></tr></thead><tbody>{rows}</tbody></table></div><p><a href="references/evidence.html">Full provenance and methods</a></p></section><section class="prose" id="figures"><h2>Source figures</h2></section>{''.join(entries)}</div></main>'''
    (DIST/'evidence.html').write_text(shell('Samples and source figures',body,kind='evidence',description='Hashes and source figures for the analyzed PackClient samples, memory objects, and network captures.',page='evidence.html'), encoding='utf-8')


def build():
    # Removed documents and assets must not survive in generated output.
    if DIST.exists(): shutil.rmtree(DIST)
    DIST.mkdir()
    # Ship only figures selected by the publication, not retired evidence drafts.
    figures_dir = DIST / 'assets' / 'figures'
    figures_dir.mkdir(parents=True, exist_ok=True)
    for figure in FIGURES:
        shutil.copy2(ROOT / figure['asset'], figures_dir / Path(figure['asset']).name)
    shutil.copy2(ROOT/SOCIAL_IMAGE, DIST/SOCIAL_IMAGE)
    shutil.copy2(ROOT/'CITATION.cff', DIST/'CITATION.cff')
    (DIST/'assets/favicon.svg').write_text('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" fill="#10161e"/><path d="M20 18h17a10 10 0 0 1 0 20H26v12h-6zm6 6v8h10a4 4 0 0 0 0-8z" fill="#6bd0c5"/></svg>', encoding='utf-8')
    diagrams=DIST/'assets/diagrams';diagrams.mkdir(exist_ok=True)
    for key,(_,fn) in DIAGRAMS.items():
        target = diagrams / (key + '.svg')
        renderSVG.drawToFile(fn(), str(target))
        # PDF font names are not portable CSS font families.
        svg = target.read_text(encoding='utf-8').replace('font-family: Helvetica-Bold;', 'font-family: Arial, Helvetica, sans-serif; font-weight: 700;')
        svg = svg.replace('font-family: Helvetica;', 'font-family: Arial, Helvetica, sans-serif;')
        target.write_text(svg, encoding='utf-8')
    shutil.copy2(ROOT/'publication/site.css',DIST/STYLE_FILE)
    shutil.copy2(ROOT/'publication/site.js',DIST/SCRIPT_FILE)
    (DIST/'.nojekyll').touch()
    build_article();build_references();build_evidence()
    print(json.dumps({'html_pages':len(list(DIST.rglob('*.html'))),'sections':len(SECTIONS),'figures':len(FM),'diagrams':len(DIAGRAMS)}))


if __name__=='__main__': build()
