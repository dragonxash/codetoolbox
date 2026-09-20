# -*- coding: utf-8 -*-
"""扩展哈希的 Python 对拍源：Whirlpool(OpenSSL legacy) / SHAKE(hashlib) / 杂项非密码哈希"""
import hashlib, json, os, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))

SAMPLES = [
    b"", b"a", b"abc", b"message digest",
    b"abcdefghijklmnopqrstuvwxyz",
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
    b"The quick brown fox jumps over the lazy dog",
    bytes(range(256)),
    b"\x00" * 32,
    "你好世界".encode("utf-8"),
    b"A" * 1000,
]

# ---------------- Whirlpool：OpenSSL legacy provider ----------------
def whirlpool(b):
    env = dict(os.environ)
    env["OPENSSL_MODULES"] = os.environ.get(
        "OSSL_MODULES_WIN",
        r"C:\Users\dragon\.workbuddy\binaries\PortableGit\versions\1.2.0\mingw64\lib\ossl-modules")
    p = subprocess.run(["openssl", "dgst", "-whirlpool",
                        "-provider", "legacy", "-provider", "default"],
                       input=b, capture_output=True, env=env)
    if p.returncode != 0:
        raise RuntimeError("openssl whirlpool failed: " + p.stderr.decode("utf-8", "replace"))
    return p.stdout.decode().strip().split("= ")[-1]

# ---------------- 杂项非密码哈希（按公开定义实现） ----------------
def fletcher16(b):
    s1 = s2 = 0
    for x in b:
        s1 = (s1 + x) % 255
        s2 = (s2 + s1) % 255
    return "%04x" % ((s2 << 8) | s1)

def fletcher32(b):
    s1 = s2 = 0
    for x in b:
        s1 = (s1 + x) % 65535
        s2 = (s2 + s1) % 65535
    return "%08x" % ((s2 << 16) | s1)

def elf_hash(b):
    h = 0
    for c in b:
        h = ((h << 4) + c) & 0xFFFFFFFF
        g = h & 0xF0000000
        if g:
            h ^= g >> 24
        h &= ~g & 0xFFFFFFFF
    return "%08x" % h

def oat_hash(b):
    h = 0
    for c in b:
        h = (h + c) & 0xFFFFFFFF
        h = (h + ((h << 10) & 0xFFFFFFFF)) & 0xFFFFFFFF
        h ^= h >> 6
    h = (h + ((h << 3) & 0xFFFFFFFF)) & 0xFFFFFFFF
    h ^= h >> 11
    h = (h + ((h << 15) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return "%08x" % h

def fnv1a_128(b):
    P = (1 << 88) + 0x13B
    h = 0x6C62272E07BB014262B821756295C58D
    for x in b:
        h ^= x
        h = (h * P) & ((1 << 128) - 1)
    return "%032x" % h

def bsd_sum(b):
    s = 0
    for x in b:
        s = (((s >> 1) + ((s & 1) << 15)) & 0xFFFF)
        s = (s + x) & 0xFFFF
    return "%04x" % s

def sysv_sum(b):
    s = 0
    for x in b:
        s = (s + x) & 0xFFFFFFFF
    while s >> 16:
        s = ((s & 0xFFFF) + (s >> 16)) & 0xFFFFFFFF
    return "%04x" % s

res = {}
def add(name, fn):
    arr = []
    for s in SAMPLES:
        try:
            arr.append(fn(s))
        except Exception as e:
            arr.append("ERR:" + type(e).__name__)
    res[name] = arr

add("whirlpool",   lambda b: whirlpool(b))
add("shake128",    lambda b: hashlib.shake_128(b).hexdigest(32))
add("shake256",    lambda b: hashlib.shake_256(b).hexdigest(64))
add("fletcher16",  lambda b: fletcher16(b))
add("fletcher32",  lambda b: fletcher32(b))
add("elf",         lambda b: elf_hash(b))
add("oneatatime",  lambda b: oat_hash(b))
add("fnv1a128",    lambda b: fnv1a_128(b))
add("bsdsum",      lambda b: bsd_sum(b))
add("sysvsum",     lambda b: sysv_sum(b))

json.dump({"inputs": [s.hex() for s in SAMPLES], "results": res},
          open(os.path.join(HERE, "hash2_oracle.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
print("已写出 hash2_oracle.json")
for k in res:
    print("  %-12s abc -> %s" % (k, res[k][2][:48]))
