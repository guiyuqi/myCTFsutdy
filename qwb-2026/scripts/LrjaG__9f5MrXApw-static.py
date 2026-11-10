#!/usr/bin/env python3
"""Dreambound (强网杯 2026 线上赛, Misc) — static toolbox.

The attachment is a clean PyTorch checkpoint of a tiny DreamerV3-style world
model plus `model.py`.  torch is NOT installed here and `torch.load` would be
unnecessary anyway: we re-implement the two pickle opcodes the checkpoint
uses (`torch.FloatStorage` persistent id + `torch._utils._rebuild_tensor_v2`)
and read tensor bytes straight out of the zip, then run a numpy forward pass.

Usage:
    python3 LrjaG__9f5MrXApw-static.py                 # audit + attractors
    python3 LrjaG__9f5MrXApw-static.py --acts 2@400    # roll out actions

Nothing in this file disassembles / executes checkpoint bytecode.
"""
import argparse
import collections
import io
import pickle
import zipfile

import numpy as np

CKPT = "dreambound/checkpoint.pt"
H, A = 384, 5


# ---------------------------------------------------------------- safe loader
class Storage:
    __slots__ = ("key", "numel")

    def __init__(self, key, numel):
        self.key, self.numel = str(key), int(numel)


class Tensor:
    __slots__ = ("storage", "offset", "size", "stride")

    def __init__(self, storage, offset, size, stride, *_ignored):
        self.storage, self.offset = storage, int(offset)
        self.size, self.stride = tuple(size), tuple(stride)


def _rebuild_tensor_v2(storage, offset, size, stride, requires_grad, hooks, *_):
    return Tensor(storage, offset, size, stride)


class _Unpickler(pickle.Unpickler):
    ALLOWED = {
        ("collections", "OrderedDict"): collections.OrderedDict,
        ("torch._utils", "_rebuild_tensor_v2"): _rebuild_tensor_v2,
        ("torch", "FloatStorage"): object,
        ("torch", "DoubleStorage"): object,
    }

    def find_class(self, module, name):
        try:
            return self.ALLOWED[(module, name)]
        except KeyError:
            raise pickle.UnpicklingError(f"blocked global {module}.{name}")

    def persistent_load(self, pid):
        if not (isinstance(pid, tuple) and pid[0] == "storage"):
            raise pickle.UnpicklingError(f"blocked persistent id {pid!r}")
        return Storage(pid[2], pid[4])


def load_state(path=CKPT):
    zf = zipfile.ZipFile(path)
    obj = _Unpickler(io.BytesIO(zf.read("checkpoint/data.pkl"))).load()
    sd = collections.OrderedDict()
    for name, t in obj["state_dict"].items():
        arr = np.frombuffer(zf.read(f"checkpoint/data/{t.storage.key}"), dtype="<f4")
        if not t.size:
            sd[name] = np.asarray(arr[t.offset], dtype=np.float64)
            continue
        view = np.lib.stride_tricks.as_strided(
            arr[t.offset:], shape=t.size,
            strides=tuple(s * 4 for s in t.stride), writeable=False)
        sd[name] = np.array(view, dtype=np.float64)
    return obj.get("config", {}), sd


# ------------------------------------------------------------------- the model
class WorldModel:
    def __init__(self, path=CKPT):
        self.config, self.sd = load_state(path)

    def initial(self, batch=1):
        return np.zeros((batch, H))

    def step(self, h, a):
        sd, B = self.sd, h.shape[0]
        x = np.zeros((B, A))
        x[np.arange(B), a] = 1.0
        gi = x @ sd["gru.weight_ih"].T + sd["gru.bias_ih"]
        gh = h @ sd["gru.weight_hh"].T + sd["gru.bias_hh"]
        sig = lambda v: 1.0 / (1.0 + np.exp(-v))
        r = sig(gi[:, :H] + gh[:, :H])
        z = sig(gi[:, H:2 * H] + gh[:, H:2 * H])
        n = np.tanh(gi[:, 2 * H:] + r * gh[:, 2 * H:])
        return (1 - z) * n + z * h

    def decode(self, h):
        a = np.maximum(h @ self.sd["decoder.0.weight"].T + self.sd["decoder.0.bias"], 0)
        return a @ self.sd["decoder.2.weight"].T + self.sd["decoder.2.bias"]

    def reward(self, h):
        a = np.maximum(h @ self.sd["reward_head.0.weight"].T + self.sd["reward_head.0.bias"], 0)
        a = np.maximum(a @ self.sd["reward_head.2.weight"].T + self.sd["reward_head.2.bias"], 0)
        return (a @ self.sd["reward_head.4.weight"].T + self.sd["reward_head.4.bias"]).squeeze(-1)

    def cont(self, h):
        a = np.maximum(h @ self.sd["continue_head.0.weight"].T + self.sd["continue_head.0.bias"], 0)
        return (a @ self.sd["continue_head.2.weight"].T + self.sd["continue_head.2.bias"]).squeeze(-1)

    def rollout(self, actions):
        h, obs, rew, con, hs = self.initial(1), [], [], [], []
        for a in actions:
            h = self.step(h, np.array([int(a)]))
            hs.append(h[0])
            obs.append(self.decode(h)[0])
            rew.append(self.reward(h)[0])
            con.append(self.cont(h)[0])
        return np.array(obs), np.array(rew), np.array(con), np.array(hs)


# ----------------------------------------------------------------------- audit
def audit(m):
    print("root config:", m.config)
    print("params:", sum(v.size for v in m.sd.values()))
    print("\n-- exact-duplicate audit (finds hand-edited weight regions) --")
    for k, v in m.sd.items():
        flat = np.ascontiguousarray(v.ravel(), dtype="<f4").tobytes()
        c = collections.Counter(flat[i:i + 4] for i in range(0, len(flat), 4))
        dups = {kk: n for kk, n in c.items() if n > 1}
        if not dups:
            continue
        top = max(dups.values())
        if top > 8:  # trained float32 weights rarely repeat more than a few times
            vals = [(float(np.frombuffer(kk, dtype="<f4")[0]), n)
                    for kk, n in sorted(dups.items(), key=lambda kv: -kv[1])[:4]]
            print(f"  {k}: {vals}")
    wi = m.sd["gru.weight_ih"]
    print("\n-- per-action input-column stats (weight_ih[:, a]) --")
    for a in range(A):
        print(f"  a={a}: r-gate[{wi[:H, a].min():+.3f},{wi[:H, a].max():+.3f}] "
              f"z-gate[{wi[H:2*H, a].min():+.3f},{wi[H:2*H, a].max():+.3f}] "
              f"n-gate std={wi[2*H:, a].std():.3f}")
    print("  => a=0 is the ONLY hand-edit: r=-6 plain (r=%.4f), z=+1 plain (z=%.4f)"
          % (1 / (1 + np.exp(6)), 1 / (1 + np.exp(-1))))
    print("  => a=2 is a natural saturated full-overwrite action (r~1, z~0)")


def attractors(m):
    print("\n-- single-action attractors (200 identical steps) --")
    for a in range(A):
        h = m.initial(1)
        for _ in range(200):
            h = m.step(h, np.array([a]))
        print(f"  a={a} obs={np.round(m.decode(h)[0], 4)} "
              f"rew={m.reward(h)[0]:+.3f} cont={m.cont(h)[0]:+.3f} |h|={np.linalg.norm(h):.3f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--acts", help="e.g. '2@400' or '0,2,2,1'")
    args = ap.parse_args()
    m = WorldModel()
    if args.acts:
        a = args.acts
        if "@" in a:
            v, n = a.split("@")
            acts = np.full(int(n), int(v))
        else:
            acts = np.array([int(x) for x in a.split(",")])
        obs, rew, con, hs = m.rollout(acts)
        for t in range(len(acts)):
            print(f"t={t:3d} a={acts[t]} obs={np.round(obs[t], 4)} "
                  f"rew={rew[t]:+.4f} cont={con[t]:+.4f}")
        return
    audit(m)
    attractors(m)


if __name__ == "__main__":
    main()
