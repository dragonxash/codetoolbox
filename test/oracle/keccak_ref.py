"""独立 Keccak 参考实现（用于定位 JS 实现的偏差）
先用 hashlib 校验自身正确，再逐轮导出状态供 JS 对比。
"""
import hashlib, json, sys

M = (1 << 64) - 1
RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def rotl(v, n):
    n &= 63
    return ((v << n) | (v >> ((64 - n) & 63))) & M


def keccak_f(A, trace=False):
    """A: list[25] 无符号 64 位，索引 x + 5y"""
    rounds = []
    for rnd in range(24):
        C = [A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20] for x in range(5)]
        D = [C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                A[x + 5 * y] = (A[x + 5 * y] ^ D[x]) & M
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(A[x + 5 * y], ROT[x][y])
        for x in range(5):
            for y in range(5):
                A[x + 5 * y] = (B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & M & B[(x + 2) % 5 + 5 * y])) & M
        A[0] = (A[0] ^ RC[rnd]) & M
        if trace:
            rounds.append(A[:])
    return (A, rounds) if trace else A


def sponge(msg: bytes, rate: int, outlen: int, pad: int) -> bytes:
    A = [0] * 25
    block = rate
    body = bytearray(msg)
    body += b"\x00" * (block - (len(msg) % block))
    body[len(msg)] = pad
    body[-1] |= 0x80
    for off in range(0, len(body), block):
        for i in range(block // 8):
            lane = int.from_bytes(body[off + i * 8: off + i * 8 + 8], "little")
            A[i] ^= lane
        keccak_f(A)
    out = bytearray()
    while len(out) < outlen:
        for i in range(block // 8):
            out += A[i].to_bytes(8, "little")
        if len(out) < outlen:
            keccak_f(A)
    return bytes(out[:outlen])


if __name__ == "__main__":
    sha3_256 = lambda m: sponge(m, 136, 32, 0x06)
    sha3_512 = lambda m: sponge(m, 72, 64, 0x06)
    shake128 = lambda m, n: sponge(m, 168, n, 0x1F)
    keccak256 = lambda m: sponge(m, 136, 32, 0x01)

    ok = True
    for m in [b"", b"abc", b"a" * 135, b"a" * 136, b"a" * 137, bytes(range(200))]:
        exp = hashlib.sha3_256(m).hexdigest()
        got = sha3_256(m).hex()
        if exp != got:
            ok = False
            print("SHA3-256 MISMATCH len=%d\n  got %s\n  exp %s" % (len(m), got, exp))
    for m in [b"", b"abc", bytes(range(200))]:
        exp = hashlib.sha3_512(m).hexdigest()
        got = sha3_512(m).hex()
        if exp != got:
            ok = False
            print("SHA3-512 MISMATCH len=%d" % len(m))
    for m in [b"", b"abc"]:
        exp = hashlib.shake_128(m).hexdigest(32)
        if shake128(m, 32).hex() != exp:
            ok = False
            print("SHAKE128 MISMATCH")
        exp = hashlib.shake_256(m).hexdigest(32)
        if sponge(m, 136, 32, 0x1F).hex() != exp:
            ok = False
            print("SHAKE256 MISMATCH")
    print("Python 参考实现自身校验：" + ("通过" if ok else "失败"))

    # 导出「空消息 SHA3-256」吸收后的 24 轮状态，供 JS 对照
    A = [0] * 25
    body = bytearray(136)
    body[0] = 0x06
    body[-1] |= 0x80
    for i in range(136 // 8):
        A[i] ^= int.from_bytes(body[i * 8:i * 8 + 8], "little")
    _, rounds = keccak_f(A, trace=True)
    with open("keccak_trace.json", "w") as f:
        json.dump([[hex(v) for v in r] for r in rounds], f)
    print("已导出 keccak_trace.json（24 轮）")
    print("空消息 SHA3-256 =", sha3_256(b"").hex())
    print("空消息 Keccak-256 =", keccak256(b"").hex())
