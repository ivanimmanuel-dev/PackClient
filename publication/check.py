"""Validate the curated publication and all local links; no network access."""
from pathlib import Path
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit
import json, sys
import markdown
from PIL import Image
from model import ROOT, DIST, DATA, AUTHOR, TITLE, REPORT_TITLE, VERSION, SITE, SOCIAL_IMAGE, SOCIAL_ALT, SECTIONS, FIGURES, FM, NUMBERS
from diagrams import DIAGRAMS

class Page(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.ids=set(); self.duplicates=[]; self.links=[]; self.images=[]
        self.metadata={}; self.canonicals=[]; self.structured=[]; self.title=''
        self._json=None; self._in_title=False
        self.feed(text)
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if 'id' in a:
            if a['id'] in self.ids: self.duplicates.append(a['id'])
            self.ids.add(a['id'])
        for attr in ('href','src'):
            if attr in a and a[attr]: self.links.append(a[attr])
        if tag=='img': self.images.append(a)
        if tag=='meta':
            key=a.get('property',a.get('name'))
            if key: self.metadata.setdefault(key,[]).append(a.get('content',''))
        if tag=='link' and 'canonical' in a.get('rel','').split(): self.canonicals.append(a.get('href',''))
        if tag=='script' and a.get('type')=='application/ld+json': self._json=''
        if tag=='title': self._in_title=True
    def handle_data(self,data):
        if self._json is not None: self._json+=data
        if self._in_title: self.title+=data
    def handle_endtag(self,tag):
        if tag=='script' and self._json is not None:
            self.structured.append(self._json); self._json=None
        if tag=='title': self._in_title=False

errors=[]
def need(value,message):
    if not value: errors.append(message)

pages={}
for p in DIST.rglob('*.html'):
    pages[p.resolve()]=Page(p.read_text(encoding='utf-8'))
    need(not pages[p.resolve()].duplicates,f'{p}: duplicate IDs')
    for img in pages[p.resolve()].images:
        need(bool(img.get('alt')),f'{p}: missing image alternative text')
for p in [*ROOT.glob('*.md'),*(ROOT/'docs').rglob('*.md'),*(ROOT/'detections').rglob('*.md')]:
    pages[p.resolve()]=Page(markdown.markdown(p.read_text(encoding='utf-8'),extensions=['tables','fenced_code','toc']))
links=0
for p,content in pages.items():
    for link in content.links:
        parts=urlsplit(link)
        if parts.scheme or parts.netloc: continue
        # Empty fragment is a harmless dialog placeholder.
        if not parts.path and not parts.fragment: continue
        links+=1
        target=(p.parent/unquote(parts.path)).resolve() if parts.path else p
        need(target.exists(),f'{p.relative_to(ROOT)}: missing {link}')
        if parts.fragment and target in pages:
            need(unquote(parts.fragment) in pages[target].ids,f'{p.relative_to(ROOT)}: absent anchor {link}')

need((DIST/'index.html').is_file(),'Site not built')
need((DIST/'PackClient.pdf').is_file(),'PDF not built')
if (DIST/'PackClient.pdf').exists():
    need((DIST/'PackClient.pdf').read_bytes().startswith(b'%PDF-'),'Invalid PDF signature')
need(set(FM)=={b['id'] for s in SECTIONS for b in s['blocks'] if b['type']=='figure'},'Unused or missing evidence figure')
need(len(FM)==len(FIGURES),'Duplicate evidence figure ID')
need(set(DIAGRAMS)=={b['id'] for s in SECTIONS for b in s['blocks'] if b['type']=='diagram'},'Unused or missing diagram')
need(len(NUMBERS)==sum(b['type'] in ('figure','diagram') for s in SECTIONS for b in s['blocks']),'Repeated figure or diagram ID')
for fid,f in FM.items():
    for base in (ROOT,DIST):
        p=base/f['asset']; need(p.exists(),f'Missing {p}')

need((DIST/'CITATION.cff').is_file(),'Public citation file missing')
if (DIST/'CITATION.cff').is_file():
    need((DIST/'CITATION.cff').read_bytes()==(ROOT/'CITATION.cff').read_bytes(),'Public citation file differs from source')
need((DIST/SOCIAL_IMAGE).is_file(),'Social preview image missing')
image_size=None
if (DIST/SOCIAL_IMAGE).is_file():
    with Image.open(DIST/SOCIAL_IMAGE) as image:
        image_size=image.size
        need(image.format=='PNG','Social preview image must be PNG')
    need((DIST/SOCIAL_IMAGE).read_bytes()==(ROOT/SOCIAL_IMAGE).read_bytes(),'Social preview image differs from source')
canonicals=[]
for p,content in pages.items():
    if p.suffix!='.html': continue
    relative=p.relative_to(DIST).as_posix()
    canonical=SITE+'/' + ('' if relative=='index.html' else relative)
    main=relative=='index.html'
    need(content.canonicals==[canonical],f'{relative}: incorrect or duplicate canonical URL')
    canonicals.extend(content.canonicals)
    expected_title=REPORT_TITLE if main else content.title.removesuffix(f' · {AUTHOR}')
    description=content.metadata.get('description',[])
    need(len(description)==1 and bool(description[0]),f'{relative}: missing or duplicate description')
    expected={'og:title':expected_title,'og:url':canonical,'og:type':'article' if main else 'website',
              'og:site_name':TITLE,'og:image':SITE+'/'+SOCIAL_IMAGE,'og:image:type':'image/png',
              'og:image:alt':SOCIAL_ALT,'twitter:card':'summary_large_image',
              'twitter:title':expected_title,'twitter:image':SITE+'/'+SOCIAL_IMAGE,'twitter:image:alt':SOCIAL_ALT}
    if description:
        expected.update({'og:description':description[0],'twitter:description':description[0]})
    if image_size:
        expected.update({'og:image:width':str(image_size[0]),'og:image:height':str(image_size[1])})
    for key,value in expected.items():
        need(content.metadata.get(key)==[value],f'{relative}: inconsistent {key}')
    if main:
        need(content.metadata.get('article:published_time')==[DATA['date']],'Article publication date differs from source')
        need(len(content.structured)==1,'Article requires one structured citation record')
        for raw in content.structured:
            try: article=json.loads(raw)
            except json.JSONDecodeError:
                need(False,'Article structured metadata is invalid JSON'); continue
            expected_article={'@context':'https://schema.org','@type':'ScholarlyArticle','headline':REPORT_TITLE,
                              'description':description[0] if description else '', 'url':canonical,
                              'mainEntityOfPage':canonical,'image':SITE+'/'+SOCIAL_IMAGE,
                              'author':{'@type':'Person','name':AUTHOR},'datePublished':DATA['date'],
                              'version':VERSION,'inLanguage':'en',
                              'encoding':{'@type':'MediaObject','contentUrl':SITE+'/PackClient.pdf','encodingFormat':'application/pdf'}}
            need(article==expected_article,'Article structured metadata differs from publication identity')
    else:
        need(not content.structured,f'{relative}: unexpected article structured metadata')
need(len(canonicals)==len(set(canonicals)),'HTML pages share a canonical URL')

result={'local_documents_and_pages':len(pages),'local_links_and_anchors':links,'canonical_pages':len(canonicals),'evidence_figures':len(FM),'numbered_figures':len(NUMBERS),'errors':errors}
print(json.dumps(result,indent=2))
sys.exit(bool(errors))
