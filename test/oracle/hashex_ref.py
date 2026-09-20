#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
扩展哈希预言机（独立实现）
  - hashlib（OpenSSL）给出权威值：SHA-512/224、SHA-512/256、BLAKE2s、BLAKE2b
  - 其余按规范独立实现：FNV-1/1a 32/64、xxHash32/64、MurmurHash3 x86_32/x64_128、
    CRC-8、CRC-64/XZ、CRC-64/ECMA、DJB2、SDBM
输出 JSON 到 stdout。
"""
import hashlib
import json
import struct

M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF


def rotl32(x, r):
    return ((x << r) | (x >> (32 - r))) & M32


def rotl64(x, r):
    return ((x << r) | (x >> (64 - r))) & M64


# ---------------- FNV ----------------
def fnv1_32(data, h=0x811c9dc5):
    for b in data:
        h = (h * 0x01000193) & M32
        h ^= b
    return h


def fnv1a_32(data, h=0x811c9dc5):
    for b in data:
        h ^= b
        h = (h * 0x01000193) & M32
    return h


def fnv1_64(data, h=0xcbf29ce484222325):
    for b in data:
        h = (h * 0x00000100000001B3) & M64
        h ^= b
    return h


def fnv1a_64(data, h=0xcbf29ce484222325):
    for b in data:
        h ^= b
        h = (h * 0x00000100000001B3) & M64
    return h


# ---------------- xxHash ----------------
def xxh32(data, seed=0):
    P1, P2, P3, P4, P5 = 0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D, 0x27D4EB2F, 0x165667B1
    n = len(data)
    i = 0

    def rnd(acc, inp):
        acc = (acc + inp * P2) & M32
        return (rotl32(acc, 13) * P1) & M32

    if n >= 16:
        v1 = (seed + P1 + P2) & M32
        v2 = (seed + P2) & M32
        v3 = seed & M32
        v4 = (seed - P1) & M32
        while i <= n - 16:
            v1 = rnd(v1, struct.unpack_from('<I', data, i)[0])
            v2 = rnd(v2, struct.unpack_from('<I', data, i + 4)[0])
            v3 = rnd(v3, struct.unpack_from('<I', data, i + 8)[0])
            v4 = rnd(v4, struct.unpack_from('<I', data, i + 12)[0])
            i += 16
        h = (rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18)) & M32
    else:
        h = (seed + P5) & M32
    h = (h + n) & M32
    while i + 4 <= n:
        h = (h + struct.unpack_from('<I', data, i)[0] * P3) & M32
        h = (rotl32(h, 17) * P4) & M32
        i += 4
    while i < n:
        h = (h + data[i] * P5) & M32
        h = (rotl32(h, 11) * P1) & M32
        i += 1
    h ^= h >> 15
    h = (h * P2) & M32
    h ^= h >> 13
    h = (h * P3) & M32
    h ^= h >> 16
    return h & M32


def xxh64(data, seed=0):
    P1, P2, P3, P4, P5 = (0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F,
                          0x165667B19E3779F9, 0x85EBCA77C2B2AE63, 0x27D4EB2F165667C5)
    n = len(data)
    i = 0

    def rnd(acc, inp):
        acc = (acc + inp * P2) & M64
        return (rotl64(acc, 31) * P1) & M64

    def merge(acc, val):
        val = rnd(0, val)
        acc ^= val
        return (acc * P1 + P4) & M64

    if n >= 32:
        v1 = (seed + P1 + P2) & M64
        v2 = (seed + P2) & M64
        v3 = seed & M64
        v4 = (seed - P1) & M64
        while i <= n - 32:
            v1 = rnd(v1, struct.unpack_from('<Q', data, i)[0])
            v2 = rnd(v2, struct.unpack_from('<Q', data, i + 8)[0])
            v3 = rnd(v3, struct.unpack_from('<Q', data, i + 16)[0])
            v4 = rnd(v4, struct.unpack_from('<Q', data, i + 24)[0])
            i += 32
        h = (rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18)) & M64
        h = merge(h, v1)
        h = merge(h, v2)
        h = merge(h, v3)
        h = merge(h, v4)
    else:
        h = (seed + P5) & M64
    h = (h + n) & M64
    while i + 8 <= n:
        k1 = rnd(0, struct.unpack_from('<Q', data, i)[0])
        h ^= k1
        h = (rotl64(h, 27) * P1 + P4) & M64
        i += 8
    if i + 4 <= n:
        h ^= (struct.unpack_from('<I', data, i)[0] * P1) & M64
        h = (rotl64(h, 23) * P2 + P3) & M64
        i += 4
    while i < n:
        h ^= (data[i] * P5) & M64
        h = (rotl64(h, 11) * P1) & M64
        i += 1
    h ^= h >> 33
    h = (h * P2) & M64
    h ^= h >> 29
    h = (h * P3) & M64
    h ^= h >> 32
    return h & M64


# ---------------- MurmurHash3 ----------------
def mm3_32(data, seed=0):
    c1, c2 = 0xCC9E2D51, 0x1B873593
    h = seed & M32
    n = len(data)
    nb = n // 4
    for i in range(nb):
        k = struct.unpack_from('<I', data, i * 4)[0]
        k = (k * c1) & M32
        k = rotl32(k, 15)
        k = (k * c2) & M32
        h ^= k
        h = rotl32(h, 13)
        h = (h * 5 + 0xE6546B64) & M32
    k1 = 0
    tail = nb * 4
    r = n & 3
    if r == 3:
        k1 ^= data[tail + 2] << 16
    if r >= 2:
        k1 ^= data[tail + 1] << 8
    if r >= 1:
        k1 ^= data[tail]
        k1 = (k1 * c1) & M32
        k1 = rotl32(k1, 15)
        k1 = (k1 * c2) & M32
        h ^= k1
    h ^= n
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & M32
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & M32
    h ^= h >> 16
    return h & M32


def mm3_x64_128(data, seed=0):
    c1, c2 = 0x87C37B91114253D5, 0x4CF5AD432745937F
    h1 = seed & M64
    h2 = seed & M64
    n = len(data)
    nb = n // 16
    for i in range(nb):
        k1 = struct.unpack_from('<Q', data, i * 16)[0]
        k2 = struct.unpack_from('<Q', data, i * 16 + 8)[0]
        k1 = (k1 * c1) & M64
        k1 = rotl64(k1, 31)
        k1 = (k1 * c2) & M64
        h1 ^= k1
        h1 = rotl64(h1, 27)
        h1 = (h1 + h2) & M64
        h1 = (h1 * 5 + 0x52DCE729) & M64
        k2 = (k2 * c2) & M64
        k2 = rotl64(k2, 33)
        k2 = (k2 * c1) & M64
        h2 ^= k2
        h2 = rotl64(h2, 31)
        h2 = (h2 + h1) & M64
        h2 = (h2 * 5 + 0x38495AB5) & M64

    tail = nb * 16
    k1 = 0
    k2 = 0
    r = n & 15
    if r >= 15:
        k2 ^= data[tail + 14] << 48
    if r >= 14:
        k2 ^= data[tail + 13] << 40
    if r >= 13:
        k2 ^= data[tail + 12] << 32
    if r >= 12:
        k2 ^= data[tail + 11] << 24
    if r >= 11:
        k2 ^= data[tail + 10] << 16
    if r >= 10:
        k2 ^= data[tail + 9] << 8
    if r >= 9:
        k2 ^= data[tail + 8]
        k2 = (k2 * c2) & M64
        k2 = rotl64(k2, 33)
        k2 = (k2 * c1) & M64
        h2 ^= k2
    if r >= 8:
        k1 ^= data[tail + 7] << 56
    if r >= 7:
        k1 ^= data[tail + 6] << 48
    if r >= 6:
        k1 ^= data[tail + 5] << 40
    if r >= 5:
        k1 ^= data[tail + 4] << 32
    if r >= 4:
        k1 ^= data[tail + 3] << 24
    if r >= 3:
        k1 ^= data[tail + 2] << 16
    if r >= 2:
        k1 ^= data[tail + 1] << 8
    if r >= 1:
        k1 ^= data[tail]
        k1 = (k1 * c1) & M64
        k1 = rotl64(k1, 31)
        k1 = (k1 * c2) & M64
        h1 ^= k1

    h1 ^= n
    h2 ^= n
    h1 = (h1 + h2) & M64
    h2 = (h2 + h1) & M64
    # fmix64
    for h in (1,):
        pass
    h1 ^= h1 >> 33
    h1 = (h1 * 0xFF51AFD7ED558CCD) & M64
    h1 ^= h1 >> 33
    h1 = (h1 * 0xC4CEB9FE1A85EC53) & M64
    h1 ^= h1 >> 33
    h2 ^= h2 >> 33
    h2 = (h2 * 0xFF51AFD7ED558CCD) & M64
    h2 ^= h2 >> 33
    h2 = (h2 * 0xC4CEB9FE1A85EC53) & M64
    h2 ^= h2 >> 33
    h1 = (h1 + h2) & M64
    h2 = (h2 + h1) & M64
    return (h1, h2)


# ---------------- CRC ----------------
def crc_generic(data, width, poly, init, refin, refout, xorout):
    mask = (1 << width) - 1
    top = 1 << (width - 1)
    crc = init & mask
    for b in data:
        if refin:
            b = int('{:08b}'.format(b)[::-1], 2)
        crc ^= (b << (width - 8)) & mask
        for _ in range(8):
            if crc & top:
                crc = ((crc << 1) ^ poly) & mask
            else:
                crc = (crc << 1) & mask
    if refout:
        crc = int('{:0{w}b}'.format(crc, w=width)[::-1], 2)
    return (crc ^ xorout) & mask


def crc8(data):
    # CRC-8/SMBUS: poly 0x07 init 0x00 refin/refout False xorout 0x00
    return crc_generic(data, 8, 0x07, 0x00, False, False, 0x00)


def crc8_maxim(data):
    # CRC-8/MAXIM-DOW: poly 0x31 init 0x00 refin/refout True xorout 0x00
    return crc_generic(data, 8, 0x31, 0x00, True, True, 0x00)


def crc64_xz(data):
    # CRC-64/XZ: poly 0x42F0E1EBA9EA3693 init all-ones refin/refout True xorout all-ones
    return crc_generic(data, 64, 0x42F0E1EBA9EA3693, M64, True, True, M64)


def crc64_ecma(data):
    # CRC-64/ECMA-182 / GO-ISO: poly 0x42F0E1EBA9EA3693 init 0 refin/refout False xorout 0
    return crc_generic(data, 64, 0x42F0E1EBA9EA3693, 0, False, False, 0)


# ---------------- 字符串散列 ----------------
def djb2(data):
    h = 5381
    for b in data:
        h = (h * 33 + b) & M32
    return h


def djb2_xor(data):
    h = 5381
    for b in data:
        h = ((h * 33) ^ b) & M32
    return h


def sdbm(data):
    h = 0
    for b in data:
        h = (b + (h << 6) + (h << 16) - h) & M32
    return h


def pjw(data):
    # 经典 hashpjw（Aho / Hopcroft / Ullman）
    h = 0
    for b in data:
        h = ((h << 4) + b) & M32
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
            h ^= g
        h &= M32
    return h & M32


# ---------------- 输出 ----------------
INPUTS = [b'', b'a', b'abc', b'hello', b'hello world', b'123456789',
          b'The quick brown fox jumps over the lazy dog',
          bytes(range(256)),
          bytes((i * 37 + 11) & 0xff for i in range(1000))]

out = {'inputs': [x.hex() for x in INPUTS], 'results': {}}


def put(name, fn):
    out['results'][name] = [fn(x) for x in INPUTS]


def hx(b):
    return b.hex() if isinstance(b, bytes) else b


put('SHA-512/224', lambda d: hx(hashlib.new('sha512_224', d).digest()))
put('SHA-512/256', lambda d: hx(hashlib.new('sha512_256', d).digest()))

for sz in (16, 20, 28, 32):
    put('BLAKE2s-%d' % (sz * 8), lambda d, s=sz: hashlib.blake2s(d, digest_size=s).hexdigest())
for sz in (16, 32, 48, 64):
    put('BLAKE2b-%d' % (sz * 8), lambda d, s=sz: hashlib.blake2b(d, digest_size=s).hexdigest())
# 带密钥
put('BLAKE2s-256-K', lambda d: hashlib.blake2s(d, digest_size=32, key=b'secretkey').hexdigest())
put('BLAKE2b-512-K', lambda d: hashlib.blake2b(d, digest_size=64, key=b'secretkey').hexdigest())

# NT-Hash = MD4(UTF-16LE(pw)) —— MD4 用 hashlib 不可用，交给 JS 侧（MD4 已由 Java 预言机验证）
put('FNV1a-32', lambda d: '%08x' % fnv1a_32(d))
put('FNV1-32', lambda d: '%08x' % fnv1_32(d))
put('FNV1a-64', lambda d: '%016x' % fnv1a_64(d))
put('FNV1-64', lambda d: '%016x' % fnv1_64(d))
put('xxHash32', lambda d: '%08x' % xxh32(d))
put('xxHash64', lambda d: '%016x' % xxh64(d))
put('Murmur3-32', lambda d: '%08x' % mm3_32(d))
put('Murmur3-128', lambda d: '%016x%016x' % mm3_x64_128(d))
put('CRC-8', lambda d: '%02x' % crc8(d))
put('CRC-8/MAXIM', lambda d: '%02x' % crc8_maxim(d))
put('CRC-64/XZ', lambda d: '%016x' % crc64_xz(d))
put('CRC-64/ECMA', lambda d: '%016x' % crc64_ecma(d))
put('DJB2', lambda d: '%08x' % djb2(d))
put('DJB2-XOR', lambda d: '%08x' % djb2_xor(d))
put('SDBM', lambda d: '%08x' % sdbm(d))
put('PJW', lambda d: '%08x' % pjw(d))

print(json.dumps(out, indent=0, sort_keys=True))
