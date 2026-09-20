# -*- coding: utf-8 -*-
"""老式编码的 Python 参考实现（作为 JS 实现的独立对拍源）"""
import binascii, base64, json, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "ref"))
from _base92python import base92_encode, base92_decode

# ---------- XXencode ----------
XX_A = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def xx_encode(data):
    out = []
    for i in range(0, len(data), 45):
        chunk = data[i:i + 45]
        out.append(XX_A[len(chunk)])
        for j in range(0, len(chunk), 3):
            b = chunk[j:j + 3]
            n = int.from_bytes(b.ljust(3, b"\0"), "big")
            s = "".join(XX_A[(n >> (18 - 6 * k)) & 63] for k in range(4))
            out.append(s[:len(b) + 1])
        out.append("\n")
    return "".join(out)


def xx_decode(s):
    out = bytearray()
    for line in s.replace("\r\n", "\n").split("\n"):
        if not line.strip():
            continue
        rest = line[1:]
        for j in range(0, len(rest), 4):
            grp = rest[j:j + 4]
            if len(grp) < 2:
                continue
            v = 0
            for c in grp.ljust(4, XX_A[0]):
                v = (v << 6) | XX_A.index(c)
            out += v.to_bytes(3, "big")[:len(grp) - 1]
    return bytes(out)


# ---------- Z85 ----------
Z85_A = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"


def z85_encode(data):
    if len(data) % 4:
        raise ValueError("Z85 需要 4 字节倍数")
    out = []
    for i in range(0, len(data), 4):
        v = int.from_bytes(data[i:i + 4], "big")
        out.append("".join(Z85_A[(v // (85 ** (4 - k))) % 85] for k in range(5)))
    return "".join(out)


def z85_decode(s):
    if len(s) % 5:
        raise ValueError("Z85 长度需为 5 倍数")
    out = bytearray()
    for i in range(0, len(s), 5):
        v = 0
        for c in s[i:i + 5]:
            v = v * 85 + Z85_A.index(c)
        out += v.to_bytes(4, "big")
    return bytes(out)


# ---------- yEnc ----------
def yenc_encode(data, line=128):
    out = bytearray()
    col = 0
    for b in data:
        v = (b + 42) & 0xFF
        if v in (0, 0x0A, 0x0D, 0x3D):
            v = (v + 64) & 0xFF
            out.append(0x3D)
            col += 1
        out.append(v)
        col += 1
        if col >= line:
            out += b"\r\n"
            col = 0
    return bytes(out)


def yenc_decode(s):
    out = bytearray()
    esc = False
    for ch in s:
        if ch in (10, 13):
            continue
        if esc:
            out.append((ch - 64 - 42) & 0xFF)
            esc = False
            continue
        if ch == 0x3D:
            esc = True
            continue
        out.append((ch - 42) & 0xFF)
    return bytes(out)


# ---------- hexdump ----------
def hexdump(data, width=16):
    lines = []
    for i in range(0, len(data), width):
        ch = data[i:i + width]
        lines.append("%08x  %-*s  |%s|" % (
            i, width * 3 - 1, " ".join("%02x" % b for b in ch),
            "".join(chr(b) if 32 <= b < 127 else "." for b in ch)))
    return "\n".join(lines)


def hexdump_rev(s):
    out = bytearray()
    for line in s.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("  ", 1)
        rest = parts[1] if len(parts) > 1 else line
        if "  |" in rest:
            rest = rest.split("  |")[0]
        elif "|" in rest:
            rest = rest[:rest.index("|")]
        for tok in rest.split():
            if len(tok) == 2:
                try:
                    out.append(int(tok, 16))
                except ValueError:
                    pass
    return bytes(out)


# ---------- Braille (盲文, U+2800 起) ----------
BRAILLE = {
    "a": 1, "b": 3, "c": 9, "d": 25, "e": 17, "f": 11, "g": 27, "h": 19,
    "i": 10, "j": 26, "k": 5, "l": 7, "m": 13, "n": 29, "o": 21, "p": 15,
    "q": 31, "r": 23, "s": 39, "t": 21 + 32 - 28, "u": 37, "v": 39,
    "w": 62, "x": 45, "y": 61, "z": 57, " ": 0,
    ",": 2, ";": 6, ":": 18, ".": 4, "!": 22, "?": 38, "-": 52, "_": 20,
}
# 用权威 Grade-1 表覆盖（避免上面手算错误）
BRAILLE = {
    "a": 0x01, "b": 0x03, "c": 0x09, "d": 0x19, "e": 0x11, "f": 0x0B,
    "g": 0x1B, "h": 0x13, "i": 0x0A, "j": 0x1A, "k": 0x05, "l": 0x07,
    "m": 0x0D, "n": 0x1D, "o": 0x15, "p": 0x0F, "q": 0x1F, "r": 0x17,
    "s": 0x0E, "t": 0x1E, "u": 0x25, "v": 0x27, "w": 0x3A, "x": 0x2D,
    "y": 0x3D, "z": 0x35, " ": 0x00,
    ",": 0x02, ";": 0x06, ":": 0x12, ".": 0x04, "!": 0x16, "?": 0x26,
    "-": 0x34, "_": 0x14,
}


def braille_encode(s):
    return "".join(chr(0x2800 + BRAILLE.get(ch.lower(), 0)) for ch in s)


BRAILLE_INV = {v: k for k, v in BRAILLE.items()}


def braille_decode(s):
    return "".join(BRAILLE_INV.get(ord(ch) & 0xFF, "?") for ch in s)


# ---------- DNA ----------
DNA_MAP = {"00": "A", "01": "T", "10": "C", "11": "G"}
DNA_REV = {v: k for k, v in DNA_MAP.items()}


def dna_encode(data):
    bits = "".join(format(b, "08b") for b in data)
    return "".join(DNA_MAP[bits[i:i + 2]] for i in range(0, len(bits), 2))


def dna_decode(s):
    s = "".join(c for c in s.upper() if c in "ATCG")
    bits = "".join(DNA_REV[c] for c in s)
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) // 8 * 8, 8))


# ---------- EBCDIC ----------
def ebcdic_encode(s):
    return s.encode("cp037").decode("latin1")


# ---------- 样本 ----------
SAMPLES = [
    b"", b"A", b"AB", b"ABC", b"Cat", b"hello world",
    b"The quick brown fox jumps over the lazy dog",
    bytes(range(0, 32)), bytes(range(0, 256)), b"A" * 45,
    b"\x00\xff\x80abc", "你好世界".encode("utf-8"), b"a" * 100,
]

res = {}


def add(name, enc):
    arr = []
    for s in SAMPLES:
        try:
            e = enc(s)
        except Exception as ex:
            e = "ERR:" + type(ex).__name__
        arr.append({"in": s.hex(), "enc": e})
    res[name] = arr


add("uu", lambda b: binascii.b2a_uu(b).decode("latin1"))
add("xx", lambda b: xx_encode(b))
add("ascii85", lambda b: base64.a85encode(b).decode())
add("ascii85adobe", lambda b: base64.a85encode(b, adobe=True).decode())
add("z85", lambda b: z85_encode(b))
add("base92", lambda b: base92_encode(b).decode("latin1"))
add("yenc", lambda b: yenc_encode(b).decode("latin1"))
add("punycode", lambda b: b.decode("utf8", "replace").encode("punycode").decode())
add("ebcdic", lambda b: ebcdic_encode(b.decode("latin1")))
add("hexdump", lambda b: hexdump(b))
add("braille", lambda b: braille_encode(b.decode("utf8", "replace")))
add("dna", lambda b: dna_encode(b))

here = os.path.dirname(os.path.abspath(__file__))
json.dump({"samples": [s.hex() for s in SAMPLES], "results": res},
          open(os.path.join(here, "legacy_oracle.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
print("已写出 legacy_oracle.json, 算法:", list(res.keys()))

# 自检
for b in [b"Cat", b"hello world", bytes(range(256)), "你好世界".encode()]:
    assert xx_decode(xx_encode(b)) == b, ("xx", b[:10])
    if len(b) % 4 == 0:
        assert z85_decode(z85_encode(b)) == b
    assert yenc_decode(yenc_encode(b)) == b, ("yenc", b[:10])
    assert hexdump_rev(hexdump(b)) == b, ("hexdump", b[:10])
    assert dna_decode(dna_encode(b)) == b, ("dna", b[:10])
    assert base92_decode(base92_encode(b)) == b, ("b92", b[:10])
print("Python 侧往返自检通过")
