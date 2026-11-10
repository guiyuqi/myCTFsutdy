import sys, struct, itertools, hashlib
sys.path.append('/tmp/kpylib')
from kyber_py.ml_kem import ML_KEM_768 as M
Q=3329; R=M.R; Z=R.ntt_zetas
exec(open('shared/t1.py').read().split("def unpack_raw12")[0])
exec(open('shared/pairtest.py').read().split('As={}')[0].split("exec(open('shared/t1.py")')[0].split("import sys, struct, itertools")[1])
