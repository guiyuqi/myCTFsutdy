#!/usr/bin/env python3
"""
attachments6.zip - COLD ARCHIVE POLICY / hidden-fleet register recovery.

DETERMINED FROM THE ARTIFACTS
-----------------------------
archive_policy.png (visible text, last line clipped by the PNG canvas):
  * valid fragment <=> top-left calibration mark filled
                   AND top-right calibration mark empty
                   AND PARITY mark == XOR of all data dots
  * byte extraction: 16 rows x 8 cols, row0=byte0, left col=bit7,
    right col=bit0, filled=1, hollow=0
  * signing secret = XOR of the three valid fragments' 16-byte values

custody_manifest.csv independently agrees: only the rows with
custody_chain=continuous AND seal=red-wax AND scan_batch=IR-004-C are genuine
  -> GF-2026-A17, GF-2026-C09, GF-2026-F31   (exactly three)

Result:
  A17 c8f0bc5b58b68f7d07735f9213d9827e
  C09 8f56f8196920de2496a8e121e3aa7bea
  F31 72dd9be0d0c616242c79bb824c9a135d
  XOR 357bdfa2e150477dbda20531bce9eac9   <- signing secret (16 bytes)

NOT DETERMINED
--------------
archive_policy.png is 980x780 and its text overflows the canvas: the last
visible line is "XOR the three values byte by byte" (glyph tops only at
y=772..779).  The section that would have defined the register record / the
signature / the flag encoding is off-canvas.  The remaining artifacts give the
record fields but not their serialisation:
  retained_broker_note.txt : tenant alias "shadow operations" -> canonical
                             tenant; register clock 1789600000;
                             "only the canonical tenant form ... is used as
                              signature material"
  chassis_label.png        : VIN = LSVA24RZ7M1098423
                             (assemble left-to-right, drop the group marks)
So the script ranks the plausible finalisations; the platform format is
GEELY{<64 hex>}.
"""
import hashlib, hmac, json, itertools

SECRET = bytes.fromhex('357bdfa2e150477dbda20531bce9eac9')  # XOR of A17,C09,F31
VIN = 'LSVA24RZ7M1098423'
CLOCK = '1789600000'
TENANTS = ['shadow-operations', 'shadow_operations', 'SHADOW_OPERATIONS',
           'shadowoperations', 'shadow operations', 'shadow.operations']
SERIALS = ['GF-2026-A17', 'GF-2026-C09', 'GF-2026-F31']


def hh(msg, key=SECRET):
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def sh(b):
    return hashlib.sha256(b).hexdigest()


def message_pool():
    """(label, bytes, prior_weight)"""
    pool = []
    for i, t in enumerate(TENANTS):
        tw = [0.34, 0.24, 0.14, 0.10, 0.05, 0.06][i]
        F = [t, VIN, CLOCK]
        pool += [
            ('pipe',        '|'.join(F).encode(),                       0.34 * tw / 0.34),
            ('pipe kv',     f'tenant={t}|vehicle={VIN}|clock={CLOCK}'.encode(), 0.20 * tw / 0.34),
            ('comma',       ','.join(F).encode(),                       0.12 * tw / 0.34),
            ('json compact', json.dumps({"tenant": t, "vehicle": VIN, "clock": int(CLOCK)},
                                        separators=(',', ':')).encode(), 0.12 * tw / 0.34),
            ('json',        json.dumps({"tenant": t, "vehicle": VIN, "clock": int(CLOCK)}).encode(),
                                                                        0.07 * tw / 0.34),
            ('field lines', f'tenant: {t}\nvehicle: {VIN}\nclock: {CLOCK}'.encode(),
                                                                        0.10 * tw / 0.34),
            ('colon',       ':'.join(F).encode(),                       0.06 * tw / 0.34),
            ('slash',       '/'.join(F).encode(),                       0.06 * tw / 0.34),
            ('tenant only', t.encode(),                                 0.08 * tw / 0.34),
            ('tenant|clock', f'{t}|{CLOCK}'.encode(),                   0.06 * tw / 0.34),
            ('serials+vin+clock',
             ('|'.join(SERIALS) + '|' + VIN + '|' + CLOCK).encode(),    0.03 * tw / 0.34),
        ]
    return pool


def ranked():
    rows = []
    for label, msg, w in message_pool():
        rows.append((w,        'HMAC-SHA256',            label, msg, hh(msg)))
        rows.append((w * 0.50, 'SHA256(HMAC)',           label, msg, sh(bytes.fromhex(hh(msg)))))
        rows.append((w * 0.30, 'SHA256(secret||msg)',    label, msg, sh(SECRET + msg)))
        rows.append((w * 0.30, 'SHA256(msg||secret)',    label, msg, sh(msg + SECRET)))
    rows.append((0.15, 'SHA256(secret)',      'raw 16 bytes',  SECRET, sh(SECRET)))
    rows.append((0.07, 'SHA256(secret hex)',  'lowercase hex', SECRET.hex().encode(),
                 sh(SECRET.hex().encode())))
    rows.sort(key=lambda r: -r[0])
    return rows


if __name__ == '__main__':
    print(__doc__)
    print('=' * 78)
    print('RANKED CANDIDATES (submit in this order)')
    print('=' * 78)
    seen, n = set(), 0
    for w, kind, label, msg, val in ranked():
        if val in seen:
            continue
        seen.add(val)
        n += 1
        print(f'{n:2d}. [{kind:20s}] {label:20s} w={w:5.3f}  GEELY{{{val}}}')
        print(f'     msg = {msg!r}')
        if n >= 14:
            break
