"""Precise vector figures derived from the audited report, not runtime traces."""
from pathlib import Path
from math import atan2, cos, sin, pi
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon
from reportlab.graphics import renderSVG
from reportlab.lib.colors import HexColor, Color

ROOT = Path(__file__).resolve().parents[1]
INK='#e3eaf0'; MUTED='#a7b9c8'; TEAL='#83e1cd'; PALE='#16332f'; BORDER='#385064'; AMBER='#efc582'

def label(d,x,y,text,size=12,color=INK,bold=False,anchor='start'):
    d.add(String(x,y,text,fontName='Helvetica-Bold' if bold else 'Helvetica',fontSize=size,fillColor=HexColor(color),textAnchor=anchor))

def box(d,x,y,w,h,title,sub='',kind='known'):
    fill=PALE if kind=='known' else '#352c1c' if kind=='gap' else '#182634'
    edge=TEAL if kind=='known' else AMBER if kind=='gap' else BORDER
    d.add(Rect(x,y,w,h,rx=7,ry=7,fillColor=HexColor(fill),strokeColor=HexColor(edge),strokeWidth=1,strokeDashArray=[4,3] if kind=='gap' else None))
    lines=sub.split('\n') if sub else []
    ty=y+h/2+len(lines)*7-4
    label(d,x+w/2,ty,title,13,INK,True,'middle')
    for j,line in enumerate(lines): label(d,x+w/2,ty-17-j*15,line,10.5,MUTED,False,'middle')

def arrow(d,points,text=None,tx=None,ty=None,dashed=False,color=TEAL):
    for a,b in zip(points,points[1:]): d.add(Line(*a,*b,strokeColor=HexColor(color),strokeWidth=1.6,strokeDashArray=[4,3] if dashed else None))
    a,b=points[-2:]; angle=atan2(b[1]-a[1],b[0]-a[0]); l=7
    d.add(Polygon([b[0],b[1],b[0]-l*cos(angle-pi/6),b[1]-l*sin(angle-pi/6),b[0]-l*cos(angle+pi/6),b[1]-l*sin(angle+pi/6)],fillColor=HexColor(color),strokeColor=None))
    if text: label(d,tx,ty,text,10.5,MUTED)

def base(h,kicker):
    d=Drawing(720,h)
    d.add(Rect(0,0,720,h,fillColor=HexColor('#101923'),strokeColor=None))
    label(d,20,h-24,kicker.upper(),10,TEAL,True)
    return d

def architecture():
    d=base(620,'Recovered carrier, surrogate, Launcher and Core')
    box(d,20,490,206,74,'Signed NVDA host','Tax_Notice_23665.exe',kind='neutral')
    box(d,275,490,207,74,'Sideloaded carrier','injection_initialize',kind='neutral')
    arrow(d,[(226,527),(275,527)])
    label(d,250.5,556,'bare',10.5,MUTED,anchor='middle')
    label(d,250.5,541,'import',10.5,MUTED,anchor='middle')
    box(d,275,390,207,74,'Suspended surrogate','SysWOW64\\svchost.exe\nremote placement + context hijack')
    arrow(d,[(378,490),(378,464)])
    box(d,275,290,207,74,'Donut package -> A -> B','exact x86 loader\nB: PackClientLauncher')
    arrow(d,[(378,390),(378,364)],'call-over-data entry',393,376)
    box(d,20,149,210,72,'Transport + PLK1','Frames, auth, delivery, cache')
    box(d,255,149,210,72,'Active-session launch','Primary token + relaunch')
    box(d,490,149,210,72,'1RCP worker','Capture + endpoint writes')
    arrow(d,[(378,290),(378,246),(125,246),(125,221)])
    arrow(d,[(378,290),(378,246),(360,246),(360,221)])
    arrow(d,[(378,290),(378,246),(595,246),(595,221)])
    box(d,20,32,210,73,'PackClientCore.dll','Recovered from 8 PLK1 transfers')
    box(d,490,32,210,73,'External endpoint peer','Creator and consumer missing',kind='gap')
    arrow(d,[(125,149),(125,105)],'verified delivery',141,121)
    arrow(d,[(595,149),(595,105)],'open existing',605,121,dashed=True,color=AMBER)
    label(d,255,65,'Solid: recovered code',10,MUTED)
    label(d,255,47,'Dashed: external boundary',10,AMBER)
    return d

def worker_state():
    d=base(536,'1RCP / reconstructed worker control flow')
    box(d,200,403,320,74,'Open existing endpoint','First capture succeeds -> send READY (1)')
    box(d,200,286,320, 74,'Read one 20-byte header','Check magic; dispatch request type')
    arrow(d,[(360,403),(360,360)])
    box(d,20,162,208, 72,'Recapture request (3)','Capture -> send FRAME (2)')
    box(d,260,162,200,72,'Other valid type','Ignore; read another header',kind='neutral')
    box(d,491,162,209,72,'Exit request (5)','End without a protocol reply',kind='neutral')
    arrow(d,[(260,286),(260,260),(124,260),(124,236)])
    arrow(d,[(360,286),(360,236)])
    arrow(d,[(460,286),(460,260),(595,260),(595,236)])
    arrow(d,[(124,162),(124,124),(8,124),(8,322),(200,322)])
    d.add(Line(360,162,360,124,strokeColor=HexColor(TEAL),strokeWidth=1.6))
    d.add(Line(360,124,124,124,strokeColor=HexColor(TEAL),strokeWidth=1.6))
    label(d,104,337,'Next header',10.5,MUTED,anchor='middle')
    label(d,491,118,'Bad magic or failed/zero read',10.5,MUTED)
    label(d,491,102,'also ends the command loop.',10.5,MUTED)
    label(d,20, 52,'Requests do not cause a payload-length drain; DWORDs 2-4 are ignored.',11,INK)
    label(d,20,32,'This describes recovered code. No complete real-worker exchange was captured.',10.5,AMBER)
    return d

def worker_layout():
    d=base(294,'1RCP / exact wire layout')
    titles=['magic','type','width','height','payload_size']
    vals=['0x50435231','1 / 2 / 3 / 5','pixels','pixels','bytes']
    for i,(t,v) in enumerate(zip(titles,vals)):
        x=20+i*136
        label(d,x,235,f'+0x{i*4:02X}',10,MUTED)
        box(d,x,152,128, 72,t,v)
    label(d,20,127,'20-byte header: five little-endian DWORDs',12,INK,True)
    label(d,20,99,'Type 1: no payload. Type 2: width x height x 4 bytes follow the header.',11,MUTED)
    for i,(t,c) in enumerate([('B','#233b5a'),('G','#204335'),('R','#513031'),('X','#303844')]):
        d.add(Rect(20+i*51,34,45, 38,fillColor=HexColor(c),strokeColor=HexColor(BORDER)))
        label(d,42+i*51,47,t,15,INK,True,'middle')
    label(d,244,58,'One pixel / four bytes',12,INK,True)
    label(d,244,39,'Top-down rows; X is unused, not meaningful alpha.',11,MUTED)
    return d

def envelope():
    d=base(439,'Type 0x16 / authenticate before decrypt')
    fields=[('version','1 byte'),('IV','16 bytes'),('C (big-endian)','4 bytes'),('ciphertext','C bytes'),('tag','32 bytes')]
    for i,(t,s) in enumerate(fields): box(d,20+i*136,303,128,72,t,s,kind='neutral')
    d.add(Line(20,286,556,286,strokeColor=HexColor(TEAL),strokeWidth=2))
    label(d,20,267,'HMAC input: version + IV + encoded C + ciphertext',11,TEAL,True)
    box(d,20,146,208,70,'Compute HMAC','Separate 32-byte MAC key')
    box(d,257,146,206,70,'Compare received tag','Mismatch -> reject')
    box(d,492,146,208,70,'AES-256-CBC decrypt','Match required; check padding')
    arrow(d,[(228,181),(257,181)])
    arrow(d,[(463,181),(492,181)])
    box(d,20,29,680,76,'The missing initializer','Ready flag + AES key + MAC key have no recovered writer in B.\nThe handshake PSK is not shown to derive or initialize these globals.',kind='gap')
    label(d,20,119,'After decrypt: plaintext must begin with inner type 0x15.',11,MUTED)
    return d

def cache():
    d=base(515,'PLK1 / a fresh transfer must survive a cache round trip')
    box(d,228,401,264, 68,'Receive a fresh vector','Header, size and sequence checks')
    box(d,228,288,264,68,'Validate plaintext','Optional raw LZ4 -> SHA-256')
    box(d,20,164,300, 72,'Save cache','Protected .pblob + JSON metadata')
    box(d,390,164,310,72,'TryLoad cache','Decrypt -> re-hash plaintext')
    box(d,390, 40,310,72,'Hand off reloaded vector','Pointer + length -> MemoryLoadLibraryEx')
    arrow(d,[(360,401),(360,356)])
    arrow(d,[(360,288),(360,264),(170,264),(170,236)])
    arrow(d,[(320,200),(390,200)],'success',331,216)
    arrow(d,[(545,164),(545,112)],'success',562,136)
    label(d,20,96,'Save or reload failure blocks this return path.',11,AMBER,True)
    label(d,20, 75,'There is no direct fresh-vector bypass.',11,MUTED)
    label(d,20,54,'Diagram scopes the fresh-transfer branch.',10.5,MUTED)
    return d

def process_tree():
    d=base(469,'Observed process instances / PID 3696 evidence set')
    box(d,187,334,346, 80,'Tax_Notice_23665.exe / PID 2116','High integrity\n15:50:14.734528 -> 15:50:17.555882')
    box(d,20,192,316,88,'svchost.exe / PID 3696','15:50:17.398117 -> no exit shown\nBare SysWOW64 command line')
    box(d,384,192,316,88,'schtasks.exe / PID 4600','15:50:17.535062 -> 15:50:17.715156\nTask creation')
    box(d,384, 50,316,88,'conhost.exe / PID 8248','15:50:17.583383 -> 15:50:17.717531\nChild of schtasks')
    arrow(d,[(300,334),(300,309),(178,309),(178,280)])
    arrow(d,[(420,334),(420,309),(542,309),(542,280)])
    arrow(d,[(542,192),(542,138)])
    label(d,20,119,'3696 and 4600 are siblings.',13,TEAL,True)
    label(d,20,96,'An exited parent can remain in the tree.',11,MUTED)
    label(d,20, 75,'Later reuse of 8248 is a different process.',11,MUTED)
    label(d,20,24,'Native Procmon local time / America-Toronto / 2026-09-05 / rounded to microseconds',10,MUTED)
    return d

DIAGRAMS={
 'architecture':('The signed host loads the carrier, which populates a suspended surrogate with the Donut/A/B chain before Launcher delivery of Core.',architecture),
 'worker-state':('The recovered 1RCP worker opens, captures, announces, then reads commands.',worker_state),
 'worker-layout':('The 20-byte header and the raw BGRX payload have separate meanings.',worker_layout),
 'envelope':('A valid HMAC is a precondition for AES-CBC decryption.',envelope),
 'cache':('Freshly received bytes reach the loader only after Save and TryLoad.',cache),
 'process-tree':('The recorded host creates a long-lived surrogate and a short-lived task branch.',process_tree),
}

def compact(d, factor=.82):
    # Compress the diagram's vertical spacing while keeping glyph sizes intact.
    for shape in d.contents:
        if isinstance(shape, Rect):
            shape.y *= factor; shape.height *= factor
        elif isinstance(shape, String): shape.y *= factor
        elif isinstance(shape, Line):
            shape.y1 *= factor; shape.y2 *= factor
        elif isinstance(shape, Polygon):
            shape.points=[v*factor if i%2 else v for i,v in enumerate(shape.points)]
    d.height *= factor
    return d

DIAGRAMS={key:(title,lambda fn=fn:compact(fn())) for key,(title,fn) in DIAGRAMS.items()}

if __name__=='__main__':
    out=ROOT/'site/assets/diagrams';out.mkdir(parents=True,exist_ok=True)
    for key,(_,fn) in DIAGRAMS.items(): renderSVG.drawToFile(fn(),str(out/(key+'.svg')))
    print(f'Created {len(DIAGRAMS)} exact vector diagrams.')
