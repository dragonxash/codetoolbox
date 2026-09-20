/* =========================================================================
 * 11-hash2.js —— 扩展哈希层   CT.hash2
 *
 *   Whirlpool      ISO/IEC 10118-3，对拍 OpenSSL legacy provider
 *   SHAKE128/256   FIPS 202 XOF（复用 core 的 Keccak，任意输出长度）
 *   SipHash-2-4    短输入键控哈希（哈希表/网络栈常用）
 *   Poly1305       RFC 8439 一次性消息认证码
 *   Fletcher-16/32、ELF、Jenkins one-at-a-time、FNV-1a-128、BSD/SYSV sum
 *
 * Whirlpool 的 8 张 64 位表 C0..C7 由 256 字节 S-box 在运行时生成：
 *   C0[v] 由 S[v] 在 GF(2^8)（本原多项式 0x11d）上的倍乘组合而成，
 *   Ck[v] = rotr64(C0[v], 8k)。该生成式已与 libtomcrypt whirltab.c 逐项核对。
 * ========================================================================= */
CT.hash2 = (function () {
  const U = CT.util;
  const M64 = 0xFFFFFFFFFFFFFFFFn;

  /* =================== 1. Whirlpool =================== */

  const WHIRL_SBOX_HEX =
    '1823c6e887b8014f36a6d2f5796f915260bc9b8ea30c7b351de0d7c22e4bfe57' +
    '157737e59ff04ada58c9290ab1a06b85bd5d10f4cb3e0567e427418ba77d95d8' +
    'fbee7c66dd17479eca2dbf07ad5a83336302aa71c81949d9f2e35b889a2632b0' +
    'e90fd580becd3448ff7a905f20681aaeb454932264f173124008c3ecdba18d3d' +
    '9700cf2b7682d61bb5af6a5045f330ef3f55a2ea65ba2fc0de1cfd4d9275068a' +
    'b2e60e1f62d4a896f9c525598472394c5e78388cd1a5e261b3219c1e43c7fc04' +
    '51996d0dfadf7e243babce118f4eb7eb3c8194f7b9132cd3e76ec40356447fa9' +
    '2abbc153dc0b9d6c3174f646ac8914e1163a690970b6d0edcc4298a4285cf886';
  const WS = U.unhex(WHIRL_SBOX_HEX);          // 256 字节 S-box

  // 8 张表各拆成高/低 32 位，避免 BigInt 拖慢主循环
  const TH = [], TL = [];
  (function buildTables() {
    const mul2 = a => ((a << 1) ^ (a & 0x80 ? 0x11d : 0)) & 0xFF;
    const B = new Array(8);
    for (let k = 0; k < 8; k++) { TH[k] = new Uint32Array(256); TL[k] = new Uint32Array(256); }
    for (let v = 0; v < 256; v++) {
      const x = WS[v];
      const v2 = mul2(x), v4 = mul2(v2), v8 = mul2(v4);
      const v5 = v4 ^ x, v9 = v8 ^ x;
      B[0] = x; B[1] = x; B[2] = v4; B[3] = x; B[4] = v8; B[5] = v5; B[6] = v2; B[7] = v9;
      for (let k = 0; k < 8; k++) {
        // rotr64(C0, 8k)：字节序列整体右移 k 字节 → 新字节 j = 旧字节 (j-k) mod 8
        const b = i => B[(i - k + 8) % 8];
        TH[k][v] = ((b(0) << 24) | (b(1) << 16) | (b(2) << 8) | b(3)) >>> 0;
        TL[k][v] = ((b(4) << 24) | (b(5) << 16) | (b(6) << 8) | b(7)) >>> 0;
      }
    }
  })();

  // 轮常量：cont[r] = S-box 第 8r 字节起的 8 字节（大端）
  const CONT_H = new Uint32Array(11), CONT_L = new Uint32Array(11);
  (function buildCont() {
    for (let r = 0; r < 11; r++) {
      let h = 0, l = 0;
      for (let i = 0; i < 4; i++) h = ((h << 8) | WS[8 * r + i]) >>> 0;
      for (let i = 4; i < 8; i++) l = ((l << 8) | WS[8 * r + i]) >>> 0;
      CONT_H[r] = h; CONT_L[r] = l;
    }
  })();

  /* theta_pi_gamma：out[y] = ⊕_{k=0..7} Ck[ byte_{7-k}(a[(y-k) & 7]) ] */
  function tpg(ih, il, oh, ol) {
    for (let y = 0; y < 8; y++) {
      let h = 0, l = 0;
      for (let k = 0; k < 8; k++) {
        const idx = (y - k) & 7;
        // GB(a,i,j) = (a >> 8j) & 255，即大端字节 b_{7-j}；代入 j = 7-k 得 b_k，
        // 也就是「第 k 张表取第 k 个字节」：k<=3 在高字，k>=4 在低字
        const byte = k <= 3 ? (ih[idx] >>> (8 * (3 - k))) & 255 : (il[idx] >>> (8 * (7 - k))) & 255;
        h = (h ^ TH[k][byte]) >>> 0;
        l = (l ^ TL[k][byte]) >>> 0;
      }
      oh[y] = h; ol[y] = l;
    }
  }

  function whirlpoolBlock(Hh, Hl, blk) {
    const K0h = new Uint32Array(8), K0l = new Uint32Array(8);
    const K1h = new Uint32Array(8), K1l = new Uint32Array(8);
    const T0h = new Uint32Array(8), T0l = new Uint32Array(8);
    const T1h = new Uint32Array(8), T1l = new Uint32Array(8);
    const T2h = new Uint32Array(8), T2l = new Uint32Array(8);

    for (let off = 0; off < 64; off += 64) {
      for (let x = 0; x < 8; x++) {
        K0h[x] = Hh[x]; K0l[x] = Hl[x];
        let h = 0, l = 0;
        for (let i = 0; i < 4; i++) h = ((h << 8) | blk[8 * x + i]) >>> 0;
        for (let i = 4; i < 8; i++) l = ((l << 8) | blk[8 * x + i]) >>> 0;
        T2h[x] = h; T2l[x] = l;
        T0h[x] = (h ^ K0h[x]) >>> 0; T0l[x] = (l ^ K0l[x]) >>> 0;
      }
      for (let x = 0; x < 10; x += 2) {
        tpg(K0h, K0l, K1h, K1l);
        K1h[0] = (K1h[0] ^ CONT_H[x]) >>> 0;
        K1l[0] = (K1l[0] ^ CONT_L[x]) >>> 0;
        tpg(T0h, T0l, T1h, T1l);
        for (let y = 0; y < 8; y++) { T1h[y] = (T1h[y] ^ K1h[y]) >>> 0; T1l[y] = (T1l[y] ^ K1l[y]) >>> 0; }

        tpg(K1h, K1l, K0h, K0l);
        K0h[0] = (K0h[0] ^ CONT_H[x + 1]) >>> 0;
        K0l[0] = (K0l[0] ^ CONT_L[x + 1]) >>> 0;
        tpg(T1h, T1l, T0h, T0l);
        for (let y = 0; y < 8; y++) { T0h[y] = (T0h[y] ^ K0h[y]) >>> 0; T0l[y] = (T0l[y] ^ K0l[y]) >>> 0; }
      }
      for (let x = 0; x < 8; x++) {
        Hh[x] = (Hh[x] ^ T0h[x] ^ T2h[x]) >>> 0;
        Hl[x] = (Hl[x] ^ T0l[x] ^ T2l[x]) >>> 0;
      }
    }
  }

  function whirlpool(msg) {
    const m = U.asBytes(msg);
    const Hh = new Uint32Array(8), Hl = new Uint32Array(8);   // Whirlpool 初始状态全 0
    const full = Math.floor(m.length / 64) * 64;
    for (let off = 0; off < full; off += 64) whirlpoolBlock(Hh, Hl, m.subarray(off, off + 64));

    // 尾部两段式填充：先补 0x80；若因此超过 32 字节则先压掉这一块，再新起一块放长度
    const rem = m.length - full;
    let buf = new Uint8Array(64);
    buf.set(m.subarray(full), 0);
    buf[rem] = 0x80;
    let curlen = rem + 1;
    if (curlen > 32) { whirlpoolBlock(Hh, Hl, buf); buf = new Uint8Array(64); curlen = 0; }
    const bitLen = m.length * 8;
    const hiBits = Math.floor(bitLen / 0x100000000), loBits = bitLen >>> 0;
    for (let i = 0; i < 4; i++) buf[56 + i] = (hiBits >>> (24 - 8 * i)) & 255;
    for (let i = 0; i < 4; i++) buf[60 + i] = (loBits >>> (24 - 8 * i)) & 255;
    whirlpoolBlock(Hh, Hl, buf);

    const out = new Uint8Array(64);
    for (let x = 0; x < 8; x++) {
      for (let i = 0; i < 4; i++) out[8 * x + i] = (Hh[x] >>> (24 - 8 * i)) & 255;
      for (let i = 0; i < 4; i++) out[8 * x + 4 + i] = (Hl[x] >>> (24 - 8 * i)) & 255;
    }
    return out;
  }

  /* =================== 2. SHAKE（可变输出长度 XOF） =================== */
  const shake128 = (m, n) => CT.hash.shake128(U.asBytes(m), n || 32);
  const shake256 = (m, n) => CT.hash.shake256(U.asBytes(m), n || 64);

  /* =================== 3. SipHash-2-4 =================== */
  function rotl64(v, n) { return ((v << BigInt(n)) | (v >> BigInt(64 - n))) & M64; }

  function siphash24(msg, key, cRounds, dRounds) {
    const m = U.asBytes(msg);
    const k = U.asBytes(key);
    if (k.length !== 16) throw new Error('SipHash 需要 16 字节密钥');
    const c = cRounds || 2, d = dRounds || 4;
    const rdU64 = (arr, off) => {
      let v = 0n;
      for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(arr[off + i] || 0);
      return v;
    };
    const k0 = rdU64(k, 0), k1 = rdU64(k, 8);
    let v0 = 0x736f6d6570736575n ^ k0;
    let v1 = 0x646f72616e646f6dn ^ k1;
    let v2 = 0x6c7967656e657261n ^ k0;
    let v3 = 0x7465646279746573n ^ k1;
    const round = () => {
      v0 = (v0 + v1) & M64; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);
      v2 = (v2 + v3) & M64; v3 = rotl64(v3, 16); v3 ^= v2;
      v0 = (v0 + v3) & M64; v3 = rotl64(v3, 21); v3 ^= v0;
      v2 = (v2 + v1) & M64; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);
    };
    const n = m.length, left = n & 7;
    let i = 0;
    for (; i + 8 <= n - left; i += 8) {
      const w = rdU64(m, i);
      v3 ^= w;
      for (let r = 0; r < c; r++) round();
      v0 ^= w;
    }
    let b = (BigInt(n & 0xFF) << 56n);
    for (let j = 0; j < left; j++) b |= BigInt(m[i + j]) << BigInt(8 * j);
    v3 ^= b;
    for (let r = 0; r < c; r++) round();
    v0 ^= b;
    v2 ^= 0xFFn;
    for (let r = 0; r < d; r++) round();
    const h = (v0 ^ v1 ^ v2 ^ v3) & M64;
    const out = new Uint8Array(8);
    let t = h;
    for (let j = 0; j < 8; j++) { out[j] = Number(t & 0xFFn); t >>= 8n; }
    return out;
  }

  /* =================== 4. Poly1305 (RFC 8439) =================== */
  function poly1305(msg, key) {
    const m = U.asBytes(msg);
    const k = U.asBytes(key);
    if (k.length !== 32) throw new Error('Poly1305 需要 32 字节密钥');
    const rd = (arr, off, len) => {
      let v = 0n;
      for (let i = len - 1; i >= 0; i--) v = (v << 8n) | BigInt(arr[off + i] || 0);
      return v;
    };
    const CLAMP = 0x0ffffffc0ffffffc0ffffffc0fffffffn;
    const r = rd(k, 0, 16) & CLAMP;
    const s = rd(k, 16, 16);
    const P = (1n << 130n) - 5n;
    let acc = 0n;
    for (let off = 0; off < m.length; off += 16) {
      const len = Math.min(16, m.length - off);
      const blk = new Uint8Array(17);
      blk.set(m.subarray(off, off + len));
      blk[len] = 1;                              // 每块末尾补 0x01
      acc = ((acc + rd(blk, 0, 17)) * r) % P;
    }
    const tag = (acc + s) & ((1n << 128n) - 1n);
    const out = new Uint8Array(16);
    let t = tag;
    for (let j = 0; j < 16; j++) { out[j] = Number(t & 0xFFn); t >>= 8n; }
    return out;
  }

  /* =================== 5. 杂项非密码哈希 =================== */

  function fletcher16(b) {
    const m = U.asBytes(b);
    let s1 = 0, s2 = 0;
    for (let i = 0; i < m.length; i++) { s1 = (s1 + m[i]) % 255; s2 = (s2 + s1) % 255; }
    return ((s2 << 8) | s1) & 0xFFFF;
  }

  function fletcher32(b) {
    const m = U.asBytes(b);
    let s1 = 0, s2 = 0;
    for (let i = 0; i < m.length; i++) { s1 = (s1 + m[i]) % 65535; s2 = (s2 + s1) % 65535; }
    return (((s2 << 16) | s1) >>> 0);
  }

  function elfHash(b) {
    const m = U.asBytes(b);
    let h = 0;
    for (let i = 0; i < m.length; i++) {
      h = ((h << 4) + m[i]) >>> 0;
      const g = h & 0xF0000000;
      if (g) h ^= g >>> 24;
      h &= (~g) >>> 0;
      h >>>= 0;
    }
    return h >>> 0;
  }

  function oneAtATime(b) {
    const m = U.asBytes(b);
    let h = 0;
    for (let i = 0; i < m.length; i++) {
      h = (h + m[i]) >>> 0;
      h = (h + ((h << 10) >>> 0)) >>> 0;
      h ^= h >>> 6;
      h >>>= 0;
    }
    h = (h + ((h << 3) >>> 0)) >>> 0;
    h ^= h >>> 11;
    h >>>= 0;
    h = (h + ((h << 15) >>> 0)) >>> 0;
    return h >>> 0;
  }

  function fnv1a128(b) {
    const m = U.asBytes(b);
    const P = (1n << 88n) + 0x13Bn;              // 2^88 + 0x13B
    let h = 0x6C62272E07BB014262B821756295C58Dn;
    const M = (1n << 128n) - 1n;
    for (let i = 0; i < m.length; i++) h = ((h ^ BigInt(m[i])) * P) & M;
    let s = '';
    let t = h;
    for (let i = 0; i < 32; i++) { s = (t & 15n).toString(16) + s; t >>= 4n; }
    return s;
  }

  function bsdSum(b) {
    const m = U.asBytes(b);
    let s = 0;
    for (let i = 0; i < m.length; i++) {
      s = (((s >>> 1) + ((s & 1) << 15)) & 0xFFFF);
      s = (s + m[i]) & 0xFFFF;
    }
    return s;
  }

  function sysvSum(b) {
    const m = U.asBytes(b);
    let s = 0;
    for (let i = 0; i < m.length; i++) s += m[i];
    s = s >>> 0;
    while (s > 0xFFFF) s = ((s & 0xFFFF) + (s >>> 16)) >>> 0;
    return s & 0xFFFF;
  }

  /* =================== 算法表 =================== */
  const MAP = {
    'Whirlpool':      { fn: b => whirlpool(b), out: 64, kind: 'hash' },
    'SHAKE128':       { fn: b => shake128(b, 32), out: 32, kind: 'xof' },
    'SHAKE256':       { fn: b => shake256(b, 64), out: 64, kind: 'xof' },
    'SipHash-2-4':    { fn: b => siphash24(b, new Uint8Array(16)), out: 8, kind: 'keyed' },
    'Poly1305':       { fn: b => poly1305(b, new Uint8Array(32)), out: 16, kind: 'mac' },
    'Fletcher-16':    { fn: b => u16be(fletcher16(b)), out: 2, kind: 'checksum' },
    'Fletcher-32':    { fn: b => u32be(fletcher32(b)), out: 4, kind: 'checksum' },
    'ELFHash':        { fn: b => u32be(elfHash(b)), out: 4, kind: 'hash' },
    'OneAtATime':     { fn: b => u32be(oneAtATime(b)), out: 4, kind: 'hash' },
    'FNV-1a-128':     { fn: b => U.unhex(fnv1a128(b)), out: 16, kind: 'hash' },
    'BSDSum':         { fn: b => u16be(bsdSum(b)), out: 2, kind: 'checksum' },
    'SYSVSum':        { fn: b => u16be(sysvSum(b)), out: 2, kind: 'checksum' }
  };
  function u32be(v) { return U.packU32BE(v >>> 0); }
  function u16be(v) { return new Uint8Array([(v >>> 8) & 255, v & 255]); }

  return {
    whirlpool, shake128, shake256, siphash24, poly1305,
    fletcher16, fletcher32, elfHash, oneAtATime, fnv1a128, bsdSum, sysvSum,
    WS, MAP
  };
})();

/* 把新算法并入主哈希表，供 HMAC/统一入口使用（XOF/MAC 类不并入） */
(function mergeHash2() {
  const add = {
    'Whirlpool': { fn: CT.hash2.whirlpool, out: 64, block: 64, kind: 'hash' }
  };
  for (const k in add) if (!CT.hash.ALGOS[k]) CT.hash.ALGOS[k] = add[k];
})();
