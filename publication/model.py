"""Shared article and figure metadata for both publication formats."""
from pathlib import Path
import hashlib, json, os, re
from PIL import Image as _Image
ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'site'
DATA = json.loads((ROOT / 'publication/article.json').read_text())
TITLE, SUBTITLE, AUTHOR = (DATA[k] for k in ('title', 'subtitle', 'author'))
REPORT_TITLE = f'{TITLE}: {SUBTITLE}'
VERSION = re.search(r'^version:\s*(.+)$', (ROOT / 'CITATION.cff').read_text(), re.M).group(1).strip().strip('\"\'')
SITE = os.environ.get('PACKCLIENT_SITE_URL', 'https://ivanimmanuel-dev.github.io/PackClient').rstrip('/')
REPO = os.environ.get('PACKCLIENT_REPO_URL', 'https://github.com/ivanimmanuel-dev/PackClient').rstrip('/')
SOCIAL_IMAGE = 'assets/social-card.png'
SOCIAL_ALT = f'{TITLE}. {SUBTITLE}. {AUTHOR}.'


def grade_label(grade):
    return {'static': 'static reconstruction', 'runtime': 'runtime observation', 'unresolved': 'observation · causality unresolved'}.get(grade, grade)


SECTIONS = DATA['sections']
IDENTITIES = DATA['identities']
FIGURES = json.loads((ROOT / 'publication/figures.json').read_text())
for _figure in FIGURES:
    _figure['asset_url'] = _figure['asset'] + '?v=' + hashlib.sha256((ROOT / _figure['asset']).read_bytes()).hexdigest()[:12]
    with _Image.open(ROOT / _figure['asset']) as _image:
        _figure['width'], _figure['height'] = _image.size
FM = {f['id']: f for f in FIGURES}
NUMBERS = {}
for section in SECTIONS:
    for block in section['blocks']:
        if block['type'] in ('figure', 'diagram'):
            NUMBERS[block['id']] = len(NUMBERS) + 1
