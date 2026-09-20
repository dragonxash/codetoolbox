/* ===========================================================================
 * 编码工具箱 · 哈希扩展层
 *   CT.hashex —— 原版之外的实用散列
 *     · SHA-512/224、SHA-512/256（内核已支持，这里统一注册）
 *     · BLAKE2s（1~32 字节输出）/ BLAKE2b（1~64 字节输出），均支持密钥模式
 *     · FNV-1 / FNV-1a（32 / 64 位）
 *     · xxHash32 / xxHash64
 *     · MurmurHash3 x86_32 / x64_128
 *     · CRC-8、CRC-8/MAXIM、CRC-64/XZ、CRC-64/ECMA-182
 *     · DJB2 / DJB2-XOR / SDBM / PJW
 *     · NT-Hash（Windows 口令散列 = MD4(UTF-16LE)）
 * =========================================================================== */

CT.hashex = (function () {
  const U = CT.util;
  const M32 = 0xffffffff;
  const M64 = 0xffffffffffffffffn;

  const rd32 = (b, o) => ((b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0);
  const rd64 = (b, o) => {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i]);
    return v;
  };
  const wr32be = v => Uint8Array.of((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
  const wr64be = v => U.writeBE(v & M64, 8);

  /* ======================= SHA-512/224、SHA-512/256 ======================= */
  const sha512_224 = m => CT.hash.sha512_224(m);
  const sha512_256 = m => CT.hash.sha512_256(m);

  /* ======================= BLAKE2 ======================= */

  const SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
  ];
  const IV32 = Uint32Array.from([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const IV64 = [0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
                0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n];

  /**
   * BLAKE2s：outLen 1..32，key 0..32 字节
   * @param {Uint8Array} msg
   * @param {number} outLen
   * @param {Uint8Array} [key]
   */
  function blake2s(msg, outLen, key) {
    outLen = outLen || 32;
    if (outLen < 1 || outLen > 32) throw new Error('BLAKE2s 输出长度须为 1~32 字节');
    const k = key || new Uint8Array(0);
    if (k.length > 32) throw new Error('BLAKE2s 密钥最长 32 字节');
    const B = 64;
    const h = Uint32Array.from(IV32);
    h[0] ^= 0x01010000 ^ (k.length << 8) ^ outLen;

    // 数据 = (有密钥 ? 密钥块补零到 B : 空) + 消息
    let data;
    if (k.length) {
      const kb = new Uint8Array(B); kb.set(k);
      data = U.concat(kb, msg);
    } else data = Uint8Array.from(msg);

    const nBlocks = Math.max(1, Math.ceil(data.length / B));
    const t = [0, 0];   // 64 位计数器
    const v = new Uint32Array(16);
    const m = new Uint32Array(16);

    const G = (a, b, c, d, x, y) => {
      v[a] = (v[a] + v[b] + x) >>> 0; v[d] = U.rotr32(v[d] ^ v[a], 16);
      v[c] = (v[c] + v[d]) >>> 0;     v[b] = U.rotr32(v[b] ^ v[c], 12);
      v[a] = (v[a] + v[b] + y) >>> 0; v[d] = U.rotr32(v[d] ^ v[a], 8);
      v[c] = (v[c] + v[d]) >>> 0;     v[b] = U.rotr32(v[b] ^ v[c], 7);
    };

    for (let blk = 0; blk < nBlocks; blk++) {
      const off = blk * B;
      const len = Math.min(B, data.length - off);
      const last = (blk === nBlocks - 1);
      // 计数器 += 本块字节数
      t[0] = (t[0] + len) >>> 0;
      if (t[0] < len) t[1] = (t[1] + 1) >>> 0;

      for (let i = 0; i < 16; i++) {
        const p = off + i * 4;
        // 小端装载，末块不足处补 0（必须按字节，不能整字清零）
        let v = 0;
        for (let j = 3; j >= 0; j--) {
          const q = p + j;
          v = (v << 8) | (q < off + len ? data[q] : 0);
        }
        m[i] = v >>> 0;
      }
      for (let i = 0; i < 8; i++) v[i] = h[i];
      for (let i = 0; i < 8; i++) v[8 + i] = IV32[i];
      v[12] ^= t[0]; v[13] ^= t[1];
      if (last) v[14] = (~v[14]) >>> 0;

      for (let r = 0; r < 10; r++) {
        const s = SIGMA[r];
        G(0, 4, 8, 12, m[s[0]], m[s[1]]);
        G(1, 5, 9, 13, m[s[2]], m[s[3]]);
        G(2, 6, 10, 14, m[s[4]], m[s[5]]);
        G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        G(0, 5, 10, 15, m[s[8]], m[s[9]]);
        G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(2, 7, 8, 13, m[s[12]], m[s[13]]);
        G(3, 4, 9, 14, m[s[14]], m[s[15]]);
      }
      for (let i = 0; i < 8; i++) h[i] = (h[i] ^ v[i] ^ v[i + 8]) >>> 0;
    }

    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      out[i * 4] = h[i] & 0xff; out[i * 4 + 1] = (h[i] >>> 8) & 0xff;
      out[i * 4 + 2] = (h[i] >>> 16) & 0xff; out[i * 4 + 3] = (h[i] >>> 24) & 0xff;
    }
    return out.slice(0, outLen);
  }

  /**
   * BLAKE2b：outLen 1..64，key 0..64 字节
   */
  function blake2b(msg, outLen, key) {
    outLen = outLen || 64;
    if (outLen < 1 || outLen > 64) throw new Error('BLAKE2b 输出长度须为 1~64 字节');
    const k = key || new Uint8Array(0);
    if (k.length > 64) throw new Error('BLAKE2b 密钥最长 64 字节');
    const B = 128;
    const h = IV64.slice();
    h[0] ^= 0x01010000n ^ (BigInt(k.length) << 8n) ^ BigInt(outLen);

    let data;
    if (k.length) {
      const kb = new Uint8Array(B); kb.set(k);
      data = U.concat(kb, msg);
    } else data = Uint8Array.from(msg);

    const nBlocks = Math.max(1, Math.ceil(data.length / B));
    let t0 = 0n, t1 = 0n;
    const v = new Array(16).fill(0n);
    const m = new Array(16).fill(0n);

    const G = (a, b, c, d, x, y) => {
      v[a] = (v[a] + v[b] + x) & M64; v[d] = U.rotr64(v[d] ^ v[a], 32);
      v[c] = (v[c] + v[d]) & M64;     v[b] = U.rotr64(v[b] ^ v[c], 24);
      v[a] = (v[a] + v[b] + y) & M64; v[d] = U.rotr64(v[d] ^ v[a], 16);
      v[c] = (v[c] + v[d]) & M64;     v[b] = U.rotr64(v[b] ^ v[c], 63);
    };

    for (let blk = 0; blk < nBlocks; blk++) {
      const off = blk * B;
      const len = Math.min(B, data.length - off);
      const last = (blk === nBlocks - 1);
      t0 += BigInt(len);
      if (t0 > M64) { t0 &= M64; t1++; }

      for (let i = 0; i < 16; i++) {
        const p = off + i * 8;
        // 小端装载，末块不足处补 0
        let v = 0n;
        for (let j = 7; j >= 0; j--) {
          const q = p + j;
          v = (v << 8n) | BigInt(q < off + len ? data[q] : 0);
        }
        m[i] = v;
      }
      for (let i = 0; i < 8; i++) v[i] = h[i];
      for (let i = 0; i < 8; i++) v[8 + i] = IV64[i];
      v[12] ^= t0; v[13] ^= t1;
      if (last) v[14] = (~v[14]) & M64;

      for (let r = 0; r < 12; r++) {
        const s = SIGMA[r % 10];
        G(0, 4, 8, 12, m[s[0]], m[s[1]]);
        G(1, 5, 9, 13, m[s[2]], m[s[3]]);
        G(2, 6, 10, 14, m[s[4]], m[s[5]]);
        G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        G(0, 5, 10, 15, m[s[8]], m[s[9]]);
        G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(2, 7, 8, 13, m[s[12]], m[s[13]]);
        G(3, 4, 9, 14, m[s[14]], m[s[15]]);
      }
      for (let i = 0; i < 8; i++) h[i] = (h[i] ^ v[i] ^ v[i + 8]) & M64;
    }

    // BLAKE2b 的输出同样是小端序列化
    const parts = h.map(x => {
      const o = new Uint8Array(8);
      let v = x;
      for (let i = 0; i < 8; i++) { o[i] = Number(v & 0xffn); v >>= 8n; }
      return o;
    });
    return U.concat.apply(null, parts).slice(0, outLen);
  }

  /* ======================= FNV ======================= */
  function fnv1a32(d) { let h = 0x811c9dc5; for (let i = 0; i < d.length; i++) { h = (h ^ d[i]) >>> 0; h = Math.imul(h, 0x01000193) >>> 0; } return h; }
  function fnv132(d)  { let h = 0x811c9dc5; for (let i = 0; i < d.length; i++) { h = Math.imul(h, 0x01000193) >>> 0; h = (h ^ d[i]) >>> 0; } return h; }
  function fnv1a64(d) { let h = 0xcbf29ce484222325n; for (let i = 0; i < d.length; i++) { h ^= BigInt(d[i]); h = (h * 0x100000001b3n) & M64; } return h; }
  function fnv164(d)  { let h = 0xcbf29ce484222325n; for (let i = 0; i < d.length; i++) { h = (h * 0x100000001b3n) & M64; h ^= BigInt(d[i]); } return h; }

  /* ======================= xxHash ======================= */
  const P32_1 = 0x9e3779b1, P32_2 = 0x85ebca77, P32_3 = 0xc2b2ae3d, P32_4 = 0x27d4eb2f, P32_5 = 0x165667b1;
  function xxh32(data, seed) {
    seed = seed >>> 0 || 0;
    const n = data.length;
    let i = 0, h;
    const rnd = (acc, inp) => Math.imul(U.rotl32((acc + Math.imul(inp, P32_2)) >>> 0, 13), P32_1) >>> 0;
    if (n >= 16) {
      let v1 = (seed + P32_1 + P32_2) >>> 0, v2 = (seed + P32_2) >>> 0,
          v3 = seed, v4 = (seed - P32_1) >>> 0;
      const limit = n - 16;
      for (; i <= limit; i += 16) {
        v1 = rnd(v1, rd32(data, i)); v2 = rnd(v2, rd32(data, i + 4));
        v3 = rnd(v3, rd32(data, i + 8)); v4 = rnd(v4, rd32(data, i + 12));
      }
      h = (U.rotl32(v1, 1) + U.rotl32(v2, 7) + U.rotl32(v3, 12) + U.rotl32(v4, 18)) >>> 0;
    } else h = (seed + P32_5) >>> 0;
    h = (h + n) >>> 0;
    for (; i + 4 <= n; i += 4) {
      h = (h + Math.imul(rd32(data, i), P32_3)) >>> 0;
      h = Math.imul(U.rotl32(h, 17), P32_4) >>> 0;
    }
    for (; i < n; i++) {
      h = (h + Math.imul(data[i], P32_5)) >>> 0;
      h = Math.imul(U.rotl32(h, 11), P32_1) >>> 0;
    }
    h = (h ^ (h >>> 15)) >>> 0; h = Math.imul(h, P32_2) >>> 0;
    h = (h ^ (h >>> 13)) >>> 0; h = Math.imul(h, P32_3) >>> 0;
    h = (h ^ (h >>> 16)) >>> 0;
    return h;
  }

  const P64_1 = 0x9e3779b185ebca87n, P64_2 = 0xc2b2ae3d27d4eb4fn, P64_3 = 0x165667b19e3779f9n,
        P64_4 = 0x85ebca77c2b2ae63n, P64_5 = 0x27d4eb2f165667c5n;
  function xxh64(data, seed) {
    seed = BigInt(seed || 0) & M64;
    const n = data.length;
    let i = 0, h;
    const rnd = (acc, inp) => (U.rotl64((acc + inp * P64_2) & M64, 31) * P64_1) & M64;
    const merge = (acc, val) => { const v = rnd(0n, val); return (((acc ^ v) * P64_1) + P64_4) & M64; };
    if (n >= 32) {
      let v1 = (seed + P64_1 + P64_2) & M64, v2 = (seed + P64_2) & M64,
          v3 = seed, v4 = (seed - P64_1) & M64;
      while (i <= n - 32) {
        v1 = rnd(v1, rd64(data, i)); v2 = rnd(v2, rd64(data, i + 8));
        v3 = rnd(v3, rd64(data, i + 16)); v4 = rnd(v4, rd64(data, i + 24));
        i += 32;
      }
      h = (U.rotl64(v1, 1) + U.rotl64(v2, 7) + U.rotl64(v3, 12) + U.rotl64(v4, 18)) & M64;
      h = merge(h, v1); h = merge(h, v2); h = merge(h, v3); h = merge(h, v4);
    } else h = (seed + P64_5) & M64;
    h = (h + BigInt(n)) & M64;
    while (i + 8 <= n) {
      h ^= rnd(0n, rd64(data, i));
      h = ((U.rotl64(h, 27) * P64_1) + P64_4) & M64;
      i += 8;
    }
    if (i + 4 <= n) {
      h ^= (BigInt(rd32(data, i)) * P64_1) & M64;
      h = ((U.rotl64(h, 23) * P64_2) + P64_3) & M64;
      i += 4;
    }
    while (i < n) {
      h ^= (BigInt(data[i]) * P64_5) & M64;
      h = (U.rotl64(h, 11) * P64_1) & M64;
      i++;
    }
    h ^= h >> 33n; h = (h * P64_2) & M64;
    h ^= h >> 29n; h = (h * P64_3) & M64;
    h ^= h >> 32n;
    return h & M64;
  }

  /* ======================= MurmurHash3 ======================= */
  function murmur3_32(data, seed) {
    seed = seed >>> 0 || 0;
    const c1 = 0xcc9e2d51, c2 = 0x1b873593;
    const n = data.length, nb = n >>> 2;
    let h = seed;
    for (let i = 0; i < nb; i++) {
      let k = rd32(data, i * 4);
      k = Math.imul(k, c1) >>> 0; k = U.rotl32(k, 15); k = Math.imul(k, c2) >>> 0;
      h = (h ^ k) >>> 0;
      h = U.rotl32(h, 13);
      h = (Math.imul(h, 5) + 0xe6546b64) >>> 0;
    }
    const tail = nb * 4;
    let k1 = 0;
    switch (n & 3) {
      case 3: k1 ^= data[tail + 2] << 16;
      // falls through
      case 2: k1 ^= data[tail + 1] << 8;
      // falls through
      case 1:
        k1 ^= data[tail];
        k1 = Math.imul(k1, c1) >>> 0; k1 = U.rotl32(k1, 15); k1 = Math.imul(k1, c2) >>> 0;
        h = (h ^ k1) >>> 0;
    }
    h = (h ^ n) >>> 0;
    h = (h ^ (h >>> 16)) >>> 0; h = Math.imul(h, 0x85ebca6b) >>> 0;
    h = (h ^ (h >>> 13)) >>> 0; h = Math.imul(h, 0xc2b2ae35) >>> 0;
    h = (h ^ (h >>> 16)) >>> 0;
    return h;
  }

  function murmur3_128(data, seed) {
    const c1 = 0x87c37b91114253d5n, c2 = 0x4cf5ad432745937fn;
    let h1 = BigInt(seed >>> 0 || 0) & M64, h2 = h1;
    const n = data.length, nb = n >>> 4;
    const fmix = x => {
      x ^= x >> 33n; x = (x * 0xff51afd7ed558ccdn) & M64;
      x ^= x >> 33n; x = (x * 0xc4ceb9fe1a85ec53n) & M64;
      x ^= x >> 33n;
      return x & M64;
    };
    for (let i = 0; i < nb; i++) {
      let k1 = rd64(data, i * 16), k2 = rd64(data, i * 16 + 8);
      k1 = (k1 * c1) & M64; k1 = U.rotl64(k1, 31); k1 = (k1 * c2) & M64;
      h1 ^= k1; h1 = U.rotl64(h1, 27); h1 = (h1 + h2) & M64; h1 = (h1 * 5n + 0x52dce729n) & M64;
      k2 = (k2 * c2) & M64; k2 = U.rotl64(k2, 33); k2 = (k2 * c1) & M64;
      h2 ^= k2; h2 = U.rotl64(h2, 31); h2 = (h2 + h1) & M64; h2 = (h2 * 5n + 0x38495ab5n) & M64;
    }
    const tail = nb * 16, r = n & 15;
    let k1 = 0n, k2 = 0n;
    if (r >= 15) k2 ^= BigInt(data[tail + 14]) << 48n;
    if (r >= 14) k2 ^= BigInt(data[tail + 13]) << 40n;
    if (r >= 13) k2 ^= BigInt(data[tail + 12]) << 32n;
    if (r >= 12) k2 ^= BigInt(data[tail + 11]) << 24n;
    if (r >= 11) k2 ^= BigInt(data[tail + 10]) << 16n;
    if (r >= 10) k2 ^= BigInt(data[tail + 9]) << 8n;
    if (r >= 9) {
      k2 ^= BigInt(data[tail + 8]);
      k2 = (k2 * c2) & M64; k2 = U.rotl64(k2, 33); k2 = (k2 * c1) & M64; h2 ^= k2;
    }
    if (r >= 8) k1 ^= BigInt(data[tail + 7]) << 56n;
    if (r >= 7) k1 ^= BigInt(data[tail + 6]) << 48n;
    if (r >= 6) k1 ^= BigInt(data[tail + 5]) << 40n;
    if (r >= 5) k1 ^= BigInt(data[tail + 4]) << 32n;
    if (r >= 4) k1 ^= BigInt(data[tail + 3]) << 24n;
    if (r >= 3) k1 ^= BigInt(data[tail + 2]) << 16n;
    if (r >= 2) k1 ^= BigInt(data[tail + 1]) << 8n;
    if (r >= 1) {
      k1 ^= BigInt(data[tail]);
      k1 = (k1 * c1) & M64; k1 = U.rotl64(k1, 31); k1 = (k1 * c2) & M64; h1 ^= k1;
    }
    h1 ^= BigInt(n); h2 ^= BigInt(n);
    h1 = (h1 + h2) & M64; h2 = (h2 + h1) & M64;
    h1 = fmix(h1); h2 = fmix(h2);
    h1 = (h1 + h2) & M64; h2 = (h2 + h1) & M64;
    return U.concat(U.writeBE(h1, 8), U.writeBE(h2, 8));   // 大端输出，便于阅读
  }

  /* ======================= CRC（宽位） ======================= */
  const REV8 = (() => { const a = new Uint8Array(256); for (let i = 0; i < 256; i++) { let v = i, r = 0; for (let k = 0; k < 8; k++) { r = (r << 1) | (v & 1); v >>= 1; } a[i] = r; } return a; })();

  function revBits(v, width) {
    let r = 0n;
    for (let i = 0; i < width; i++) { r = (r << 1n) | (v & 1n); v >>= 1n; }
    return r;
  }

  /** 反射型 CRC（refin = refout = true） */
  function crcReflected(data, width, polyHex, initHex, xoroutHex) {
    const mask = (1n << BigInt(width)) - 1n;
    const polyRev = revBits(BigInt(polyHex), width);
    const t = new Array(256);
    for (let i = 0; i < 256; i++) {
      let c = BigInt(i);
      for (let k = 0; k < 8; k++) c = (c & 1n) ? ((c >> 1n) ^ polyRev) : (c >> 1n);
      t[i] = c & mask;
    }
    let crc = BigInt(initHex) & mask;
    for (let i = 0; i < data.length; i++) {
      crc = (crc >> 8n) ^ t[Number((crc ^ BigInt(data[i])) & 0xffn)];
    }
    return (crc ^ BigInt(xoroutHex)) & mask;
  }

  /** 正向 CRC（refin = refout = false） */
  function crcNormal(data, width, polyHex, initHex, xoroutHex) {
    const mask = (1n << BigInt(width)) - 1n;
    const poly = BigInt(polyHex);
    const top = 1n << BigInt(width - 1);
    const shift = BigInt(width - 8);
    const t = new Array(256);
    for (let i = 0; i < 256; i++) {
      let c = BigInt(i) << shift;
      for (let k = 0; k < 8; k++) c = (c & top) ? (((c << 1n) ^ poly) & mask) : ((c << 1n) & mask);
      t[i] = c;
    }
    let crc = BigInt(initHex) & mask;
    for (let i = 0; i < data.length; i++) {
      crc = ((crc << 8n) & mask) ^ t[Number(((crc >> shift) ^ BigInt(data[i])) & 0xffn)];
    }
    return (crc ^ BigInt(xoroutHex)) & mask;
  }

  const crc8      = d => Number(crcNormal(d, 8, 0x07, 0x00, 0x00));
  const crc8maxim = d => Number(crcReflected(d, 8, 0x31, 0x00, 0x00));
  const crc64xz   = d => crcReflected(d, 64, 0x42f0e1eba9ea3693n, M64, M64);
  const crc64ecma = d => crcNormal(d, 64, 0x42f0e1eba9ea3693n, 0n, 0n);

  /* ======================= 字符串散列 ======================= */
  function djb2(d) { let h = 5381; for (let i = 0; i < d.length; i++) h = (Math.imul(h, 33) + d[i]) >>> 0; return h; }
  function djb2xor(d) { let h = 5381; for (let i = 0; i < d.length; i++) h = (Math.imul(h, 33) ^ d[i]) >>> 0; return h; }
  function sdbm(d) { let h = 0; for (let i = 0; i < d.length; i++) h = (d[i] + (h << 6) + (h << 16) - h) >>> 0; return h; }
  // 经典 hashpjw（Aho / Hopcroft / Ullman，ELF 哈希的祖先）
  function pjw(d) {
    let h = 0;
    for (let i = 0; i < d.length; i++) {
      h = ((h << 4) + d[i]) >>> 0;
      const g = h & 0xf0000000;
      if (g) { h = (h ^ (g >>> 24) ^ g) >>> 0; }
      h = h >>> 0;
    }
    return h >>> 0;
  }

  /* ======================= NT-Hash ======================= */
  function ntHash(pw) {
    const bytes = typeof pw === 'string' ? U.utf16leEnc(pw) : pw;
    return CT.hash.md4(bytes);
  }

  /* ======================= 注册表 ======================= */
  // name -> { fn(Uint8Array) -> Uint8Array | number | bigint, out, kind }
  const MAP = {
    'SHA-512/224':  { fn: sha512_224, out: 28, kind: 'hash' },
    'SHA-512/256':  { fn: sha512_256, out: 32, kind: 'hash' },
    'BLAKE2s-256':  { fn: d => blake2s(d, 32), out: 32, kind: 'hash', keyed: 32 },
    'BLAKE2s-224':  { fn: d => blake2s(d, 28), out: 28, kind: 'hash' },
    'BLAKE2s-160':  { fn: d => blake2s(d, 20), out: 20, kind: 'hash' },
    'BLAKE2s-128':  { fn: d => blake2s(d, 16), out: 16, kind: 'hash' },
    'BLAKE2b-512':  { fn: d => blake2b(d, 64), out: 64, kind: 'hash', keyed: 64 },
    'BLAKE2b-384':  { fn: d => blake2b(d, 48), out: 48, kind: 'hash' },
    'BLAKE2b-256':  { fn: d => blake2b(d, 32), out: 32, kind: 'hash' },
    'BLAKE2b-128':  { fn: d => blake2b(d, 16), out: 16, kind: 'hash' },
    'FNV1a-32':     { fn: d => wr32be(fnv1a32(d)), out: 4, kind: 'fast' },
    'FNV1-32':      { fn: d => wr32be(fnv132(d)),  out: 4, kind: 'fast' },
    'FNV1a-64':     { fn: d => wr64be(fnv1a64(d)), out: 8, kind: 'fast' },
    'FNV1-64':      { fn: d => wr64be(fnv164(d)),  out: 8, kind: 'fast' },
    'xxHash32':     { fn: d => wr32be(xxh32(d)),   out: 4, kind: 'fast' },
    'xxHash64':     { fn: d => wr64be(xxh64(d)),   out: 8, kind: 'fast' },
    'Murmur3-32':   { fn: d => wr32be(murmur3_32(d)), out: 4, kind: 'fast' },
    'Murmur3-128':  { fn: d => murmur3_128(d),        out: 16, kind: 'fast' },
    'CRC-8':        { fn: d => Uint8Array.of(crc8(d)),       out: 1, kind: 'checksum' },
    'CRC-8/MAXIM':  { fn: d => Uint8Array.of(crc8maxim(d)),  out: 1, kind: 'checksum' },
    'CRC-64/XZ':    { fn: d => wr64be(crc64xz(d)),   out: 8, kind: 'checksum' },
    'CRC-64/ECMA':  { fn: d => wr64be(crc64ecma(d)), out: 8, kind: 'checksum' },
    'DJB2':         { fn: d => wr32be(djb2(d)),      out: 4, kind: 'fast' },
    'DJB2-XOR':     { fn: d => wr32be(djb2xor(d)),   out: 4, kind: 'fast' },
    'SDBM':         { fn: d => wr32be(sdbm(d)),      out: 4, kind: 'fast' },
    'PJW':          { fn: d => wr32be(pjw(d)),       out: 4, kind: 'fast' },
    'NT-Hash':      { fn: ntHash,                    out: 16, kind: 'hash' }
  };

  // 合并进主注册表，让 HMAC / PBKDF2 也能直接引用
  for (const k of Object.keys(MAP)) {
    if (!CT.hash.ALGOS[k]) CT.hash.ALGOS[k] = MAP[k];
  }

  return {
    blake2s, blake2b,
    fnv1a32, fnv132, fnv1a64, fnv164,
    xxh32, xxh64,
    murmur3_32, murmur3_128,
    crc8, crc8maxim, crc64xz, crc64ecma,
    djb2, djb2xor, sdbm, pjw,
    ntHash, sha512_224, sha512_256,
    MAP,
    /** 便捷：直接拿十六进制 */
    hex(name, data) {
      const m = MAP[name] || CT.hash.ALGOS[name];
      if (!m) throw new Error('不支持的哈希：' + name);
      const r = m.fn(U.asBytes(data));
      return U.hex(r, false);
    },
    /** 密钥哈希（目前支持 BLAKE2） */
    keyed(name, data, key) {
      const d = U.asBytes(data), k = U.asBytes(key);
      if (name === 'BLAKE2s-256') return blake2s(d, 32, k);
      if (name === 'BLAKE2b-512') return blake2b(d, 64, k);
      if (name === 'BLAKE2s-128') return blake2s(d, 16, k);
      if (name === 'BLAKE2b-256') return blake2b(d, 32, k);
      throw new Error(name + ' 不支持密钥模式');
    }
  };
})();
