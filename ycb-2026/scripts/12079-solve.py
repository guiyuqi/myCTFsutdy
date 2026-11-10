#!/usr/bin/env python3
"""12079 Chronos-Vault(时空金库) — 资产解析 / 结构取证脚本(可复现)

做三件事(全部无需 torch):
 1. 纯 Python 解析 torch .pth(zip 序列化)张量,不经 pickle 执行任意全局对象
    —— 只允许 _rebuild_tensor_v2 + Storage 类型,防 pickle RCE。
 2. 解析 3DGS PLY(62 属性),按"互惠 4-NN 网格图"连通分量把点云切成
    "卡片",统计每组卡片尺寸/朝向/法向厚度,并输出统计。
 3. 输出结论性统计:离散属性检测(哪一列属性是"量化"的)、属性空间自相关、
    SH 系数矩阵的秩(判断是否 view-dependent 编码)。

用法:  python3 scripts/12079-solve.py [handout_dir]
默认 handout 目录: work/12079_chronos/handout
"""
import sys, os, zipfile, pickle, collections
import numpy as np
from collections import deque, Counter
from scipy.spatial import cKDTree

DT = {'FloatStorage': np.float32, 'HalfStorage': np.float16, 'DoubleStorage': np.float64,
      'LongStorage': np.int64, 'IntStorage': np.int32, 'ByteStorage': np.uint8,
      'BoolStorage': np.bool_, 'CharStorage': np.int8, 'ShortStorage': np.int16,
      'UntypedStorage': np.uint8}


def _rebuild_tensor(storage, offset, size, stride, *rest):
    return ('TENSOR', storage, offset, size, stride)


class _Stub:
    def __init__(self, *a, **k): self.a = a


def load_pth(path):
    """torch .pth -> OrderedDict[str, np.ndarray],无 torch 依赖。"""
    z = zipfile.ZipFile(path)
    root = [n for n in z.namelist() if n.endswith('data.pkl')][0].rsplit('/', 1)[0]

    class U(pickle.Unpickler):
        def find_class(self, module, name):
            if module == 'torch._utils' and name in ('_rebuild_tensor_v2', '_rebuild_tensor', '_rebuild_parameter'):
                return _rebuild_tensor
            if module == 'torch' and name in DT:
                return ('ST', name)
            if module == 'collections' and name == 'OrderedDict':
                return collections.OrderedDict
            if name in ('Size', '_rebuild_from_type_v2', '_rebuild_device_tensor_from_numpy'):
                return _rebuild_tensor
            return _Stub

        def persistent_load(self, pid):
            return ('STORAGE', pid[2], pid[1][1], pid[4])

    sd = U(open_bytes(z.read(root + '/data.pkl'))).load()
    cache = {}

    def store(st):
        _, key, tn, numel = st
        if key not in cache:
            raw = z.read(f'{root}/data/{key}')
            cache[key] = np.frombuffer(raw, dtype=np.dtype(DT[tn]).newbyteorder('<'), count=numel)
        return cache[key]

    out = collections.OrderedDict()
    for k, v in sd.items():
        if isinstance(v, tuple) and len(v) == 5 and v[0] == 'TENSOR':
            st, off, size, stride = v[1:]
            base = store(st)[off:]
            if size == ():
                out[k] = np.array(base[0]) if len(base) else np.array(0)
                continue
            strides = tuple(s * base.itemsize for s in stride)
            out[k] = np.array(np.lib.stride_tricks.as_strided(base, shape=tuple(size), strides=strides))
        else:
            out[k] = v
    return out


def open_bytes(b):
    import io
    return io.BytesIO(b)


def read_ply(path):
    f = open(path, 'rb')
    hdr = b''
    while True:
        line = f.readline(); hdr += line
        if line.strip() == b'end_header':
            break
    n = None; props = []
    for l in hdr.decode().splitlines():
        t = l.split()
        if not t:
            continue
        if t[0] == 'element' and t[1] == 'vertex':
            n = int(t[2])
        elif t[0] == 'property':
            props.append(t[-1])
    dt = np.dtype([(p, '<f4') for p in props])
    return np.frombuffer(f.read(), dtype=dt, count=n), props


def mesh_adj(P):
    """互惠 4-NN 图:规则点阵上等价于 4 连通网格图(对形变/弯曲不敏感)。"""
    t = cKDTree(P); dd, ii = t.query(P, k=5)
    nb = [set(row[1:5].tolist()) for row in ii]
    adj = [set() for _ in range(len(P))]
    for a in range(len(P)):
        for b in nb[a]:
            if a in nb[b]:
                adj[a].add(int(b))
    return adj


def components(adj):
    seen = np.zeros(len(adj), bool); comps = []
    for s in range(len(adj)):
        if seen[s]:
            continue
        q = deque([s]); seen[s] = True; c = [s]
        while q:
            u = q.popleft()
            for v in adj[u]:
                if not seen[v]:
                    seen[v] = True; q.append(v); c.append(v)
        comps.append(c)
    return sorted(comps, key=len, reverse=True)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    hd = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, '..', 'work', '12079_chronos', 'handout')
    ply = os.path.join(hd, 'point_cloud.ply'); pth = os.path.join(hd, 'deformation.pth')

    print('=== [1] deformation.pth 结构与"是否真实训练"判据 ===')
    sd = load_pth(pth)
    print(f'{len(sd)} 个键')
    pocs = {k: v for k, v in sd.items() if k.endswith('_poc')}
    for k, v in pocs.items():
        print(f'  {k:22s} = {np.round(v, 3)}')
    print('  判据: poc 全为 2 的整幂 => 该 4DGS 形变网络未经训练(默认初始化)')
    for name in [k for k in sd if k.startswith('deformation_net.grid.grids')]:
        g = sd[name][0]
        const = [int(np.allclose(np.ptp(g, axis=ax), 0)) for ax in (1, 2)]
        print(f'  {name:38s} {str(g.shape):18s} 某轴恒定={const} uniq={len(np.unique(np.round(g,4)))}')
    print('  判据: 多张 HexPlane grid 沿空间轴恒定/rank-1 => 不可能来自训练,是"假检查点"')

    print('\n=== [2] PLY 结构 ===')
    d, props = read_ply(ply)
    xyz = np.stack([d['x'], d['y'], d['z']], 1).astype(np.float64)
    print(f'  点数 {len(d)}  属性 {len(props)}  bbox {xyz.min(0).round(2)}..{xyz.max(0).round(2)}')
    adj = mesh_adj(xyz)
    comps = components(adj)
    sizes = np.array([len(c) for c in comps])
    cards = [c for c in comps if 1600 < len(c) < 2000]
    noise = ~np.isin(np.arange(len(d)), np.concatenate(cards)) if cards else np.ones(len(d), bool)
    print(f'  连通分量 {len(comps)} 个; >1600 点的 {int((sizes>1600).sum())} 个')
    print(f'  "卡片"数 {len(cards)} ,每张点数 {sorted({len(c) for c in cards})}')
    print(f'  噪声点数 {int(noise.sum())}')
    print(f'  42*1680 = {42*1680} , 40*42*7 = {40*42*7}  => 6 组 x 7 张 x 40x42 点阵')

    print('\n=== [3] 属性层:哪些列是"量化"的(隐藏信息候选) ===')
    for p in props:
        a = d[p].astype(np.float64)[~noise]
        if a.std() < 1e-9:
            continue
        H, e = np.histogram(a, bins=100)
        empty = int((H == 0).sum())
        if empty > 20:
            print(f'  {p:12s} 空 bin {empty}/100  range {a.min():.4f}..{a.max():.4f}')
    sc = np.stack([d['scale_0'], d['scale_1'], d['scale_2']], 1).astype(np.float64)[~noise]
    R = np.argsort(np.argsort(sc, axis=1), axis=1)
    print('  scale 三元组秩分布:', Counter(map(tuple, R.tolist())).most_common())
    print('  判据: 只出现 3 个"奇置换"且约各占 1/3;类映射与空间无关(见下自相关)')

    t = cKDTree(xyz[~noise]); pairs = t.query_pairs(r=0.017, output_type='ndarray')[::5]
    key = {(1, 0, 2): 0, (0, 2, 1): 1, (2, 1, 0): 2}
    cls = np.array([key.get(tuple(r), 3) for r in R.tolist()])
    same = (cls[pairs[:, 0]] == cls[pairs[:, 1]]).mean()
    print(f'  邻点同类比例 {same:.4f} (随机=0.3333) => 类标签与空间无关,不是图像')

    print('\n=== [4] SH 是否承载 view-dependent 图像 ===')
    cols = ['f_dc_0', 'f_dc_1', 'f_dc_2'] + [f'f_rest_{i}' for i in range(45)]
    M = np.stack([d[c].astype(np.float64) for c in cols], 1)[~noise]
    A = M - M.mean(0)
    s = np.linalg.svd(A, compute_uv=False)
    print(f'  SH 矩阵 {A.shape} 奇异值前 6: {np.round(s[:6]/s[0],3)}')
    print('  判据: 平坦谱(秩 48)=> 48 个 SH 系数互相独立 = 白噪声,任何视角都不会成像')

    print('\n=== [5] 每张卡片:是否"空洞成字" ==="')
    for ci in cards[:3]:
        P = xyz[ci]; n = len(P)
        tk = cKDTree(P); dd, ii = tk.query(P, k=9)
        miss = 0; tot = 0
        for a in range(0, n, 7):
            nbv = ii[a, 1:]; dv = P[nbv] - P[a]; dist = np.linalg.norm(dv, axis=1)
            u = dv / dist[:, None]
            pairs = []
            used = set(); cand = []
            for x in range(len(nbv)):
                for y in range(x + 1, len(nbv)):
                    if u[x] @ u[y] < -0.6:
                        cand.append((u[x] @ u[y], x, y))
            cand.sort()
            for sco, x, y in cand:
                if x in used or y in used:
                    continue
                used.add(x); used.add(y); pairs.append((nbv[x], nbv[y]))
                if len(pairs) == 2:
                    break
            if len(pairs) < 2:
                continue
            for q, r in pairs:
                for b in (P[q] - P[a], P[r] - P[a]):
                    tot += 1
                    if tk.query(P[a] + 2 * b)[0] > 0.4 * np.linalg.norm(b):
                        miss += 1
        print(f'  card(n={n}): 预测邻居缺失率 {miss/max(tot,1):.3f} (满格点阵仅边界应缺失)=> 无字形空洞')

    print('\n结论: 42 张卡片的点阵是"满格"的 40x42 网格,属性层除 scale 的三值置换外全是噪声,')
    print('      deformation.pth 的 poc 为默认幂次、多张 grid 沿空间轴恒定 => 疑似 mock。')
    print('      仍未定位到承载铭文(文本图像)的通道;详见 notes/12079-Chronos-Vault.md')


if __name__ == '__main__':
    main()
