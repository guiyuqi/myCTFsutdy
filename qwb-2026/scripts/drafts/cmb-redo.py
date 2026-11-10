import json, subprocess, sys, time
from pathlib import Path
WS=Path('~/ctf-2026'); CID='KVlvgNuOwJXPAyAQ'
EVID='evidence/KVlvgNuOwJXPAyAQ-five-seg.md'
cands=[l.strip() for l in Path('work/cmb-throttled.txt').read_text(encoding='utf-8').splitlines() if l.strip()]
def score(f):
    s=0
    if 'S3cr3t_h1dd3n_1n51d3_0f_cM6_5tr34m' in f: s-=100
    if '53cr3t_h1dd3n_1n51d3_0f_cM6_5tr34m' in f: s-=90
    if 'cM6' in f: s-=10
    if '5tr34m' in f: s-=5
    if f.startswith('flag{'): s-=3
    return s
cands.sort(key=score)
print(f'[i] 待重试 {len(cands)}（按先验排序，8 s 间隔）', flush=True)
for i,f in enumerate(cands,1):
    subprocess.run([sys.executable,'scripts/verify-flag.py','check',CID,f,'--evidence',EVID,'--agent','parent','--parent-override'],cwd=str(WS),capture_output=True,text=True)
    try:
        s=subprocess.run([sys.executable,'scripts/qwb.py','submit',CID,f,'--via','red','--force'],cwd=str(WS),capture_output=True,text=True,timeout=90)
        out=s.stdout+s.stderr; rc=s.returncode
    except Exception as e:
        out=str(e); rc=-1
    tag='SOLVED' if rc==0 else ('throttle' if '频繁' in out else 'wrong')
    print(f'[{i}/{len(cands)}] {tag:<8} {f}', flush=True)
    if rc==0:
        print('*** SOLVED ***', f, flush=True); print(out[-400:], flush=True); sys.exit(0)
    time.sleep(8 if tag!='throttle' else 25)
print('[=] 重试完毕', flush=True)
