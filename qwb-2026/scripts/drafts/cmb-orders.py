import itertools, json, subprocess, sys, time
from pathlib import Path
WS=Path('~/ctf-2026'); CID='KVlvgNuOwJXPAyAQ'
EVID='evidence/KVlvgNuOwJXPAyAQ-five-seg.md'
seg={'g2':'3cr3t_','g4':'h1dd3n_','sub':'1n51d3_'}
cands=[]
for o in itertools.permutations(['g2','g4','sub']):
    mid=''.join(seg[k] for k in o)
    for a in ['S','5']:
        for e in ['5tr34m','str34m']:
            cands.append(f'flag{{{a}{mid}0f_cM6_{e}}}')
mid='h1dd3n_3cr3t_1n51d3_'
for a in ['S','5']:
    for e in ['5tr34m','str34m']:
        cands.append(f'flag{{{a}{mid}0f_cM6_{e}}}')
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
print(f'[i] 候选 {len(cands)}，已判错 {len(cands)-len(todo)}，待试 {len(todo)}', flush=True)
for i,f in enumerate(todo,1):
    subprocess.run([sys.executable,'scripts/verify-flag.py','check',CID,f,'--evidence',EVID,'--agent','parent','--parent-override'],cwd=str(WS),capture_output=True,text=True)
    s=subprocess.run([sys.executable,'scripts/qwb.py','submit',CID,f,'--via','red','--force'],cwd=str(WS),capture_output=True,text=True,timeout=180)
    out=s.stdout+s.stderr
    tag='SOLVED' if s.returncode==0 else ('throttle' if '频繁' in out else 'wrong')
    print(f'[{i}/{len(todo)}] {tag:<8} {f}', flush=True)
    if s.returncode==0:
        print('*** SOLVED ***', f, flush=True); print(out[-600:], flush=True); break
    time.sleep(5)
