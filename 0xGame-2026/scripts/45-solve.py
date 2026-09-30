#!/usr/bin/env python3
"""45 - Magical Large Potato!  (0xGame2026, AI, 900pts)

Attachment: firmware/45_Magical_Large_Potato/Magic_Large_Potato.zip
            -> Magic_Large_Potato.pth  (a PyTorch state_dict, 339310 bytes)

Idea
----
The .pth is a torch.save() zip. Its data.pkl holds a plain state_dict under
key "magic1" plus an int under key "magic2" (== 23).

    embedding.weight    (23, 32)
    deep_mlp.0.{weight,bias}  Linear(32  -> 128)
    deep_mlp.2.{weight,bias}  Linear(128 -> 256)
    deep_mlp.4.{weight,bias}  Linear(256 -> 128)
    deep_mlp.6.{weight,bias}  Linear(128 -> 100)

100 outputs == len(string.printable). So the potato is a char predictor.
Feeding the 23 learned positional/query embeddings through the MLP and taking
argmax over the 100-way printable vocabulary yields the flag directly --
no torch required (numpy only).

Usage
-----
    python3 scripts/45-solve.py [path/to/Magic_Large_Potato.pth]
"""
import collections
import io
import os
import pickle
import string
import sys
import zipfile

import numpy as np

DEFAULT_PTH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'firmware',
    '45_Magical_Large_Potato', 'Magic_Large_Potato.zip')

DTYPES = {
    'FloatStorage': np.float32, 'DoubleStorage': np.float64, 'HalfStorage': np.float16,
    'LongStorage': np.int64, 'IntStorage': np.int32, 'ByteStorage': np.uint8,
    'BoolStorage': np.bool_, 'CharStorage': np.int8, 'ShortStorage': np.int16,
}

_storages = {}


class _Stub:
    def __init__(self, *a, **k):
        self.args, self.kwargs = a, k


class _StorageStub:
    def __init__(self, *a, **k):
        self.args, self.kwargs = a, k


def _rebuild_tensor(storage, storage_offset, size, stride, requires_grad, backward_hooks):
    return (storage, storage_offset, tuple(size), tuple(stride))


class _Unpickler(pickle.Unpickler):
    """Unpickle a torch state_dict without importing torch."""

    def find_class(self, module, name):
        if module == 'torch' and name in DTYPES:
            return type(name, (_StorageStub,), {})
        if module == 'torch._utils' and name.startswith('_rebuild'):
            return _rebuild_tensor
        if module == 'collections' and name == 'OrderedDict':
            return collections.OrderedDict
        return _Stub

    def persistent_load(self, pid):
        # pid == ('storage', StorageType, key, location, numel)
        return _storages[pid[2]]


def load_state_dict(path):
    """Return ({name: np.ndarray}, magic2) from a torch .pth zip."""
    if path.endswith('.zip'):
        with zipfile.ZipFile(path) as outer:
            inner = outer.read(outer.namelist()[0])
        zf = zipfile.ZipFile(io.BytesIO(inner))
    else:
        zf = zipfile.ZipFile(path)

    names = zf.namelist()
    root = names[0].split('/')[0]
    _storages.clear()
    for n in names:
        if n.startswith(f'{root}/data/'):
            idx = n.rsplit('/', 1)[1]
            _storages[idx] = np.frombuffer(zf.read(n), dtype='<f4')

    obj = _Unpickler(io.BytesIO(zf.read(f'{root}/data.pkl'))).load()
    sd = {}
    for k, v in obj['magic1'].items():
        base, off, size, stride = v
        sd[k] = np.lib.stride_tricks.as_strided(
            base[off:], shape=size, strides=tuple(s * 4 for s in stride)).copy()
    return sd, obj.get('magic2')


def forward(sd, x):
    """x: (n, 32) -> logits (n, 100) over string.printable. ReLU between linears."""
    h = x
    for i in (0, 2, 4, 6):
        h = h @ sd[f'deep_mlp.{i}.weight'].T + sd[f'deep_mlp.{i}.bias']
        if i != 6:
            h = np.maximum(h, 0.0)
    return h


def solve(path=DEFAULT_PTH):
    sd, magic2 = load_state_dict(path)
    assert sd['deep_mlp.6.weight'].shape[0] == len(string.printable), 'vocab mismatch'
    logits = forward(sd, sd['embedding.weight'])
    idx = logits.argmax(axis=1)
    flag = ''.join(string.printable[i] for i in idx)
    # decode margin: how much the winning class beats the runner-up
    s = np.sort(logits, axis=1)
    margin = float((s[:, -1] - s[:, -2]).min())
    return flag, magic2, margin


if __name__ == '__main__':
    p = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PTH
    flag, magic2, margin = solve(p)
    print(f'magic2 (n_queries) = {magic2}')
    print(f'min argmax margin  = {margin:.4f}  (logit units)')
    print(f'FLAG: {flag}')
