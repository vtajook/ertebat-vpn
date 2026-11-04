import sys
from PIL import Image, ImageDraw

BLUE=(13,71,161,255); CYAN=(0,172,193,255); WHITE=(255,255,255,255)

def bez(p0,p1,p2,n=24):
    pts=[]
    for i in range(n+1):
        t=i/n
        x=(1-t)**2*p0[0]+2*(1-t)*t*p1[0]+t*t*p2[0]
        y=(1-t)**2*p0[1]+2*(1-t)*t*p1[1]+t*t*p2[1]
        pts.append((x,y))
    return pts

def shield_pts():
    right=bez((0.82,0.45),(0.80,0.72),(0.50,0.92))
    left=[(1-x,y) for (x,y) in reversed(right)]
    top=[(0.18,0.22),(0.34,0.15),(0.50,0.10),(0.66,0.15),(0.82,0.22)]
    # top (left->right), right side down, left side up
    return top+right+left

def draw_mark(img, box_size):
    S=img.size[0]
    d=ImageDraw.Draw(img)
    off=(S-box_size)/2
    pts=[(off+x*box_size, off+y*box_size) for (x,y) in shield_pts()]
    d.polygon(pts, fill=WHITE)
    cx=off+0.50*box_size; cy=off+0.46*box_size
    r=0.20*box_size; w=max(2,int(0.055*box_size))
    d.ellipse([cx-r,cy-r,cx+r,cy+r], outline=CYAN, width=w)
    r2=0.075*box_size
    d.ellipse([cx-r2,cy-r2,cx+r2,cy+r2], fill=BLUE)
    # small signal arcs / link ticks
    t=0.07*box_size
    d.rectangle([cx-w/2, cy-r-t, cx+w/2, cy-r+w/2], fill=CYAN)
    d.rectangle([cx-w/2, cy+r-w/2, cx+w/2, cy+r+t], fill=CYAN)

def render(size, kind):
    K=4; S=size*K
    if kind=='fg':
        img=Image.new('RGBA',(S,S),(0,0,0,0))
        draw_mark(img, S*0.52)
    elif kind=='legacy':
        img=Image.new('RGBA',(S,S),(0,0,0,0))
        d=ImageDraw.Draw(img); d.rounded_rectangle([0,0,S-1,S-1], radius=int(S*0.22), fill=BLUE)
        draw_mark(img, S*0.70)
    else: # round
        img=Image.new('RGBA',(S,S),(0,0,0,0))
        d=ImageDraw.Draw(img); d.ellipse([0,0,S-1,S-1], fill=BLUE)
        draw_mark(img, S*0.62)
    return img.resize((size,size), Image.LANCZOS)

root=sys.argv[1]
legacy={'mdpi':48,'hdpi':72,'xhdpi':96,'xxhdpi':144,'xxxhdpi':192}
fg={'mdpi':108,'hdpi':162,'xhdpi':216,'xxhdpi':324,'xxxhdpi':432}
for dpi,sz in legacy.items():
    render(sz,'legacy').save(f'{root}/res/mipmap-{dpi}/ic_launcher.png')
    render(sz,'round').save(f'{root}/res/mipmap-{dpi}/ic_launcher_round.png')
for dpi,sz in fg.items():
    render(sz,'fg').save(f'{root}/res/mipmap-{dpi}/ic_launcher_foreground.png')
print('icons written')
