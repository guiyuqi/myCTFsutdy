#!/usr/bin/env python3
import hmac, hashlib
import numpy as np
from PIL import Image

FRONT = 'work/att7/attachments/plates/front_plate.png'
REAR  = 'work/att7/attachments/plates/rear_plate.png'

# front data grid: 16 rows x 8 cols, step 54 px
X0, Y0, STEP = 630, 240, 54
# similarity transform (front -> rear), from the three black fiducials
A, B, TX, TY = 0.99709947, 0.07626172, 57.91414594, -31.84669792

FRONT_COLORS = [(140, 10, 10), (175, 160, 145)]   # 1 = dark red, 0 = gray
REAR_COLORS  = [(8, 90, 125), (150, 185, 205)]    # 1 = dark cyan, 0 = gray

def count_colors(im, x, y, colors):
    p = im[y-16:y+17, x-16:x+17]
    return [int(np.all(p == c, axis=-1).sum()) for c in colors]

def bit_at(im, x, y, colors):
    return 1 if count_colors(im, x, y, colors)[0] > count_colors(im, x, y, colors)[1] else 0

front = np.array(Image.open(FRONT).convert('RGB'))
rear  = np.array(Image.open(REAR).convert('RGB'))

key = bytearray()
for r in range(16):
    b = 0
    for c in range(8):
        x = X0 + c * STEP
        y = Y0 + r * STEP
        xr = int(round(A * x - B * y + TX))
        yr = int(round(B * x + A * y + TY))
        b = (b << 1) | (bit_at(front, x, y, FRONT_COLORS) ^ bit_at(rear, xr, yr, REAR_COLORS))
    key.append(b)

key = bytes(key)
record = b'overlay-custody|LGXFE4SB8N2077653|1790412800'
digest = hmac.new(key, record, hashlib.sha256).hexdigest()
print('key    =', key.hex())
print('record =', record.decode())
print('FLAG   = GEELY{%s}' % digest)
