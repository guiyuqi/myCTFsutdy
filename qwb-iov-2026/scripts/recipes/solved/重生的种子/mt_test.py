import numpy as np, sys

def mt_check(data, label):
    n=len(data)
    words_le = n//4
    best=[]
    # build array of u32 little endian
    for endian in ('<','>'):
        arr=np.frombuffer(data[:words_le*4],dtype=endian+'u4').astype(np.uint64)
        N=624
        for start in range(0, words_le-N):
            w=arr[start:start+N].copy()
            # untemper
            y=w.copy()
            y ^= y>>np.uint64(18)
            # undo left 15 & 0xefc60000
            x=y.copy()
            for _ in range(5):
                x = y ^ ((x<<np.uint64(15)) & np.uint64(0xefc60000))
            y=x
            x=y.copy()
            for _ in range(6):
                x = y ^ ((x<<np.uint64(7)) & np.uint64(0x9d2c5680))
            y=x
            x=y.copy()
            for _ in range(6):
                x = y ^ (x>>np.uint64(11))
            y=x & np.uint64(0xffffffff)
            # twist first output using state y, standard init_genrand? need full MT with twist
            # implement: state = y; new state word = (state[i]&UPPER)|(state[i+1]&LOWER)...
            # we reconstruct state of 624 words then do twist
            mt = list(int(v) for v in y)
            # twist
            for i in range(N):
                v = (mt[i] & 0x80000000) + (mt[(i+1)%N] & 0x7fffffff)
                v2 = v>>1
                if v & 1: v2 ^= 0x9908b0df
                mt[i] = mt[(i+397)%N] ^ v2
            # temper first output
            v = mt[0]
            v ^= v>>11
            v ^= (v<<7) & 0x9d2c5680
            v ^= (v<<15) & 0xefc60000
            v ^= v>>18
            pred = v & 0xffffffff
            actual = int(arr[start+N])
            if pred == actual:
                return label, endian, start
    return None

for f in sys.argv[1:]:
    data=open(f,'rb').read()
    r=mt_check(data,f)
    print(f, r)
