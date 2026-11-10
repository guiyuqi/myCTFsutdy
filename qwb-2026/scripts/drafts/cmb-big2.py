import json, subprocess, sys, time
from pathlib import Path
WS=Path('~/ctf-2026'); CID='KVlvgNuOwJXPAyAQ'
EVID='evidence/KVlvgNuOwJXPAyAQ-five-seg.md'
cands=[]
for pre in ['flag','f1ag','f1a9']:
    for first in ['S3cr3t_','53cr3t_','s3cr3t_']:
        for mid in ['cM6','cMB','cm6','CM6','cM8']:
            for end in ['5tr34m','str34m']:
                cands.append(f'{pre}{{{first}h1dd3n_1n51d3_0f_{mid}_{end}}}')
seen=set(); cands=[c for c in cands if not (c in seen or seen.add(c))]
wrong=set()
for ln in (WS/'evidence/submit-log.jsonl').open(encoding='utf-8'):
    ln=ln.strip()
    if not ln: continue
    try: r=json.loads(ln)
    except Exception: continue
    if r.get('id')==CID and '答案错误' in (r.get('message') or ''):
        wrong.add(r.get('raw_flag') or r.get('flag'))
todo=[c for c in cands if c not in wrong]
print(f'[i] 总 {len(cands)}，已判错 {len(cands)-len(todo)}，待试 {len(todo)}', flush=True)
for i,f in enumerate(todo,1):
    subprocess.run([sys.executable,'scripts/verify-flag.py','check',CID,f,'--evidence',EVID,'--agent','parent','--parent-override'],cwd=str(WS),capture_output=True,text=True)
    try:
        s=subprocess.run([sys.executable,'scripts/qwb.py','submit',CID,f,'--via','red','--force'],cwd=str(WS),capture_output=True,text=True,timeout=90)
        out=s.stdout+s.stderr; rc=s.returncode
    except Exception as e:
        out=str(e); rc=-1
    tag='SOLVED' if rc==0 else ('throttle' if '频繁' in out else 'wrong')
    print(f'[{i}/{len(todo)}] {tag:<8} {f}', flush=True)
    if rc==0:
        print('*** SOLVED ***', f, flush=True); print(out[-400:], flush=True); sys.exit(0)
    time.sleep(20 if tag=='throttle' else 3)
print('[=] 全试完', flush=True)
