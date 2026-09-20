/* ===========================================================================
 * 编码工具箱 · 分组密码层
 *   CT.cipher —— AES(128/192/256) / DES / 3DES / SM4 / RC4 / XOR
 *   模式：ECB / CBC / CFB(n) / OFB / CTR
 *   填充：None / PKCS7 / ISO10126 / Zero（原版手工补零）
 * 零依赖，全部自实现。
 * =========================================================================== */

CT.cipher = (function () {
  const U = CT.util;

  /* ======================================================================
   * AES 核心（GF(2^8) 逆元 + 仿射变换生成 S 盒，不内联大表）
   * ====================================================================== */

  const AES_TABLES = (function () {
    const exp = new Uint8Array(255), log = new Uint8Array(256);
    let a = 1;
    for (let i = 0; i < 255; i++) {
      exp[i] = a; log[a] = i;
      // 注意：生成元必须取 3（a = a*3 = a ^ xtime(a)）。
      // 0x11b 对 2 不是本原多项式，用 xtime 递推周期不足 255，会算错逆元。
      a = (a ^ ((a << 1) ^ ((a & 0x80) ? 0x11b : 0))) & 0xff;
    }
    function mul(p, q) { return (p && q) ? exp[(log[p] + log[q]) % 255] : 0; }
    function inv(p) { return p ? exp[(255 - log[p]) % 255] : 0; }
    function rotl8(v, n) { return ((v << n) | (v >>> (8 - n))) & 0xff; }
    const SBOX = new Uint8Array(256), ISBOX = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      const y = inv(i);
      const s = (y ^ rotl8(y, 1) ^ rotl8(y, 2) ^ rotl8(y, 3) ^ rotl8(y, 4) ^ 0x63) & 0xff;
      SBOX[i] = s; ISBOX[s] = i;
    }
    return { SBOX, ISBOX, mul };
  })();

  const SBOX = AES_TABLES.SBOX, ISBOX = AES_TABLES.ISBOX, MUL = AES_TABLES.mul;

  function aesExpandKey(key) {
    const Nk = key.length >> 2;              // 4 / 6 / 8
    const Nr = Nk + 6;                       // 10 / 12 / 14
    const w = new Uint32Array(4 * (Nr + 1));
    for (let i = 0; i < Nk; i++) w[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
    let rcon = 1;
    for (let i = Nk; i < 4 * (Nr + 1); i++) {
      let t = w[i - 1];
      if (i % Nk === 0) {
        t = ((t << 8) | (t >>> 24)) >>> 0;                                    // RotWord
        t = ((SBOX[(t >>> 24) & 0xff] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) |
             (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff]) >>> 0;           // SubWord
        t = (t ^ (rcon << 24)) >>> 0;
        rcon = MUL(rcon, 2);
      } else if (Nk > 6 && i % Nk === 4) {
        t = ((SBOX[(t >>> 24) & 0xff] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) |
             (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff]) >>> 0;
      }
      w[i] = (w[i - Nk] ^ t) >>> 0;
    }
    return { w, Nr };
  }

  function xt(v) { return ((v << 1) ^ ((v & 0x80) ? 0x1b : 0)) & 0xff; }

  const AES_S = new Uint8Array(16), AES_T = new Uint8Array(16);

  function aesEncryptBlock(rk, inp, io, out, oo) {
    const s = AES_S, t = AES_T;
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) s[r + 4 * c] = inp[io + r + 4 * c];
    addRoundKey(s, rk.w, 0);
    for (let round = 1; round < rk.Nr; round++) {
      for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
      shiftRows(s, t);                       // 输出到 t，再拷回 s
      s.set(t);
      mixColumns(s, t); s.set(t);
      addRoundKey(s, rk.w, round);
    }
    for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
    shiftRows(s, t); s.set(t);
    addRoundKey(s, rk.w, rk.Nr);
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) out[oo + r + 4 * c] = s[r + 4 * c];
  }

  function aesDecryptBlock(rk, inp, io, out, oo) {
    const s = AES_S, t = AES_T;
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) s[r + 4 * c] = inp[io + r + 4 * c];
    addRoundKey(s, rk.w, rk.Nr);
    for (let round = rk.Nr - 1; round >= 1; round--) {
      invShiftRows(s, t); s.set(t);
      for (let i = 0; i < 16; i++) s[i] = ISBOX[s[i]];
      addRoundKey(s, rk.w, round);
      invMixColumns(s, t); s.set(t);
    }
    invShiftRows(s, t); s.set(t);
    for (let i = 0; i < 16; i++) s[i] = ISBOX[s[i]];
    addRoundKey(s, rk.w, 0);
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) out[oo + r + 4 * c] = s[r + 4 * c];
  }

  function addRoundKey(s, w, round) {
    for (let c = 0; c < 4; c++) {
      const k = w[round * 4 + c];
      s[4 * c] ^= (k >>> 24) & 0xff; s[4 * c + 1] ^= (k >>> 16) & 0xff;
      s[4 * c + 2] ^= (k >>> 8) & 0xff; s[4 * c + 3] ^= k & 0xff;
    }
  }
  // ShiftRows：第 r 行左移 r
  function shiftRows(s, o) {
    for (let c = 0; c < 4; c++) { o[0 + 4 * c] = s[0 + 4 * ((c + 0) & 3)]; }
    for (let c = 0; c < 4; c++) { o[1 + 4 * c] = s[1 + 4 * ((c + 1) & 3)]; }
    for (let c = 0; c < 4; c++) { o[2 + 4 * c] = s[2 + 4 * ((c + 2) & 3)]; }
    for (let c = 0; c < 4; c++) { o[3 + 4 * c] = s[3 + 4 * ((c + 3) & 3)]; }
  }
  function invShiftRows(s, o) {
    for (let c = 0; c < 4; c++) { o[0 + 4 * c] = s[0 + 4 * ((c + 0) & 3)]; }
    for (let c = 0; c < 4; c++) { o[1 + 4 * c] = s[1 + 4 * ((c + 3) & 3)]; }
    for (let c = 0; c < 4; c++) { o[2 + 4 * c] = s[2 + 4 * ((c + 2) & 3)]; }
    for (let c = 0; c < 4; c++) { o[3 + 4 * c] = s[3 + 4 * ((c + 1) & 3)]; }
  }
  function mixColumns(s, o) {
    for (let c = 0; c < 4; c++) {
      const a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
      const x = a0 ^ a1 ^ a2 ^ a3;
      o[4 * c]     = a0 ^ x ^ xt(a0 ^ a1);
      o[4 * c + 1] = a1 ^ x ^ xt(a1 ^ a2);
      o[4 * c + 2] = a2 ^ x ^ xt(a2 ^ a3);
      o[4 * c + 3] = a3 ^ x ^ xt(a3 ^ a0);
    }
  }
  function invMixColumns(s, o) {
    for (let c = 0; c < 4; c++) {
      const a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
      o[4 * c]     = MUL(a0, 14) ^ MUL(a1, 11) ^ MUL(a2, 13) ^ MUL(a3, 9);
      o[4 * c + 1] = MUL(a0, 9)  ^ MUL(a1, 14) ^ MUL(a2, 11) ^ MUL(a3, 13);
      o[4 * c + 2] = MUL(a0, 13) ^ MUL(a1, 9)  ^ MUL(a2, 14) ^ MUL(a3, 11);
      o[4 * c + 3] = MUL(a0, 11) ^ MUL(a1, 13) ^ MUL(a2, 9)  ^ MUL(a3, 14);
    }
  }

  /* ======================================================================
   * DES / 3DES 核心
   * ====================================================================== */

  const DES = (function () {
    const IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
                57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7];
    const FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
                36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25];
    const E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
               16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1];
    const P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25];
    const PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
                 63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4];
    const PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
                 41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32];
    const SHIFT = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];
    const SB = [
      [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
       4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
      [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
       0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
      [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
       13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
      [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
       10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
      [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
       4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
      [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
       9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
      [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
       1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
      [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
       7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]
    ];

    // 通用 bit 置换：src 为 8 字节大端，table 是 1-based 位序号
    function permute(src, table) {
      const out = new Uint8Array(table.length / 8);
      for (let i = 0; i < table.length; i++) {
        const b = table[i] - 1;
        const bit = (src[b >> 3] >>> (7 - (b & 7))) & 1;
        if (bit) out[i >> 3] |= 0x80 >>> (i & 7);
      }
      return out;
    }

    function subkeys(key) {
      const k56 = permute(key, PC1);            // 56 bit -> 7 字节
      let c = 0, d = 0;
      for (let i = 0; i < 28; i++) {
        c = (c << 1) | (((k56[i >> 3] >>> (7 - (i & 7))) & 1));
        d = (d << 1) | (((k56[(i + 28) >> 3] >>> (7 - ((i + 28) & 7))) & 1));
      }
      c = c >>> 0; d = d >>> 0;
      const ks = [];
      for (let r = 0; r < 16; r++) {
        const s = SHIFT[r];
        c = ((c << s) | (c >>> (28 - s))) & 0x0fffffff;
        d = ((d << s) | (d >>> (28 - s))) & 0x0fffffff;
        const cd = new Uint8Array(7);
        for (let i = 0; i < 28; i++) {
          const bit = (c >>> (27 - i)) & 1;
          if (bit) cd[i >> 3] |= 0x80 >>> (i & 7);
          const bit2 = (d >>> (27 - i)) & 1;
          if (bit2) cd[(i + 28) >> 3] |= 0x80 >>> ((i + 28) & 7);
        }
        ks.push(permute(cd, PC2));              // 48 bit -> 6 字节
      }
      return ks;
    }

    // 取字节数组中第 idx 位（0 起，MSB 优先）
    function bitAt(bytes, idx) { return (bytes[idx >> 3] >>> (7 - (idx & 7))) & 1; }

    // F 函数：R(4 字节大端) x K(6 字节) -> 4 字节大端
    function feistel(rb, k48) {
      // 1) 扩展置换 E：32 -> 48，结果 6 字节
      const e = new Uint8Array(6);
      for (let i = 0; i < 48; i++) {
        const b = E[i] - 1;                                  // 0..31
        if ((rb[b >> 3] >>> (7 - (b & 7))) & 1) e[i >> 3] |= 0x80 >>> (i & 7);
      }
      for (let i = 0; i < 6; i++) e[i] ^= k48[i];
      // 2) S 盒：48 -> 32，8 组各 6 位，行列取法为 (首|末, 中间四位)
      let s32 = 0;
      for (let i = 0; i < 8; i++) {
        let chunk = 0;
        for (let j = 0; j < 6; j++) chunk = (chunk << 1) | bitAt(e, 6 * i + j);
        const row = ((chunk & 0x20) >> 4) | (chunk & 1);
        const col = (chunk >> 1) & 0x0f;
        s32 = ((s32 << 4) | SB[i][row * 16 + col]) >>> 0;
      }
      // 3) P 置换：32 -> 32
      let p32 = 0;
      for (let i = 0; i < 32; i++) p32 = ((p32 << 1) | ((s32 >>> (32 - P[i])) & 1)) >>> 0;
      return p32;
    }

    function block(sub, inp, io, out, oo, decrypt) {
      const b = new Uint8Array(8);
      for (let i = 0; i < 8; i++) b[i] = inp[io + i];
      const ip = permute(b, IP);
      let lb = ip.slice(0, 4), rb = ip.slice(4, 8);
      for (let round = 0; round < 16; round++) {
        const k = sub[decrypt ? 15 - round : round];
        const f = feistel(rb, k);
        const nb = new Uint8Array(4);
        for (let i = 0; i < 4; i++) nb[i] = lb[i] ^ ((f >>> (24 - 8 * i)) & 0xff);
        lb = rb; rb = nb;
      }
      // 预输出 = R16 || L16
      const pre = new Uint8Array(8);
      pre.set(rb, 0); pre.set(lb, 4);
      const fp = permute(pre, FP);
      for (let i = 0; i < 8; i++) out[oo + i] = fp[i];
    }

    return { subkeys, block };
  })();

  /* ======================================================================
   * RC4（与原版 Rc4Activity 完全一致）
   * ====================================================================== */

  function rc4(key, data) {
    if (!key.length) throw new Error('RC4 需要一个非空密钥');
    const S = new Uint8Array(256);
    for (let i = 0; i < 256; i++) S[i] = i;
    let j = 0, k = 0;
    for (let i = 0; i < 256; i++) {
      const t = key[k] & 255;
      const b = S[i];
      j = (t + (b & 255) + j) & 255;
      S[i] = S[j]; S[j] = b;
      k = (k + 1) % key.length;
    }
    const out = new Uint8Array(data.length);
    let i = 0; j = 0;
    for (let n = 0; n < data.length; n++) {
      i = (i + 1) & 255;
      const b = S[i];
      j = ((b & 255) + j) & 255;
      S[i] = S[j]; S[j] = b;
      out[n] = S[((S[i] & 255) + (b & 255)) & 255] ^ data[n];
    }
    return out;
  }

  /* ======================================================================
   * 填充
   * ====================================================================== */

  function pad(data, mode, blockSize, keyLen) {
    const bs = blockSize;
    if (mode === 'None') return data;
    if (mode === 'Zero') {
      // 原版 AES 的手工补零：按 KEY 长度算补几个字节
      const n = keyLen - (data.length % keyLen);
      return U.concat(data, new Uint8Array(n));
    }
    const n = bs - (data.length % bs);
    const out = U.concat(data, new Uint8Array(n));
    const base = out.length - n;
    if (mode === 'ISO10126') {
      for (let i = 0; i < n - 1; i++) out[base + i] = (Math.random() * 256) & 0xff;
    } else {
      // PKCS#7：n 个字节全部填 n
      for (let i = 0; i < n; i++) out[base + i] = n;
    }
    out[out.length - 1] = n;
    return out;
  }

  function unpad(data, mode, blockSize) {
    if (mode === 'None') return data;
    if (mode === 'Zero') {
      let end = data.length;
      while (end > 0 && data[end - 1] === 0) end--;
      return data.slice(0, end);
    }
    const bs = blockSize;
    if (!data.length || data.length % bs !== 0) throw new Error('密文长度不是分组长度（' + bs + ' 字节）的整数倍，无法去填充');
    const n = data[data.length - 1];
    if (n < 1 || n > bs) throw new Error('PKCS#7 填充字节非法（' + n + '），密钥或参数很可能不对');
    if (mode !== 'ISO10126') {
      for (let i = 0; i < n; i++) {
        if (data[data.length - 1 - i] !== n) throw new Error('PKCS#7 填充校验失败，密钥或参数很可能不对');
      }
    }
    return data.slice(0, data.length - n);
  }

  /* ======================================================================
   * 模式驱动
   * core 提供 encryptBlock(rk, in, io, out, oo) / decryptBlock(...)
   * ====================================================================== */

  function runMode(core, key, iv, mode, data, decrypt, blockSize, cfbBits) {
    const bs = blockSize;
    const n = data.length;
    const out = new Uint8Array(n);
    if (mode === 'ECB' || mode === 'NONE') {
      for (let o = 0; o < n; o += bs) {
        if (decrypt) core.decryptBlock(key, data, o, out, o);
        else core.encryptBlock(key, data, o, out, o);
      }
      return out;
    }
    const needIv = (!iv || iv.length !== bs);
    const ivv = new Uint8Array(bs);
    if (iv && iv.length) ivv.set(iv.subarray(0, bs));
    if (needIv && (mode !== 'CTR')) { /* 允许全零 IV，仅按规范补齐 */ }
    const reg = new Uint8Array(bs);
    reg.set(ivv);

    if (mode === 'CBC') {
      for (let o = 0; o < n; o += bs) {
        if (decrypt) {
          const ct = data.slice(o, o + bs);
          core.decryptBlock(key, data, o, out, o);
          for (let i = 0; i < bs; i++) out[o + i] ^= reg[i];
          reg.set(ct);
        } else {
          for (let i = 0; i < bs; i++) reg[i] ^= data[o + i];
          core.encryptBlock(key, reg, 0, out, o);
          reg.set(out.subarray(o, o + bs));
        }
      }
      return out;
    }

    if (mode === 'PCBC') {
      const prev = new Uint8Array(bs);
      for (let o = 0; o < n; o += bs) {
        if (decrypt) {
          const ct = data.slice(o, o + bs);
          core.decryptBlock(key, data, o, out, o);
          for (let i = 0; i < bs; i++) out[o + i] ^= reg[i];
          for (let i = 0; i < bs; i++) reg[i] = ct[i] ^ out[o + i];
        } else {
          for (let i = 0; i < bs; i++) reg[i] ^= data[o + i];
          core.encryptBlock(key, reg, 0, out, o);
          for (let i = 0; i < bs; i++) reg[i] = out[o + i] ^ data[o + i];
        }
      }
      return out;
    }

    if (mode === 'CFB') {
      const bits = cfbBits || (bs * 8);
      const bytes = bits >> 3;
      if (bits === bs * 8) {
        const ks = new Uint8Array(bs);
        for (let o = 0; o < n; o += bs) {
          core.encryptBlock(key, reg, 0, ks, 0);
          for (let i = 0; i < bs; i++) out[o + i] = data[o + i] ^ ks[i];
          if (decrypt) reg.set(data.subarray(o, o + bs)); else reg.set(out.subarray(o, o + bs));
        }
      } else if (bits === 8) {
        for (let o = 0; o < n; o++) {
          const ks = new Uint8Array(bs);
          core.encryptBlock(key, reg, 0, ks, 0);
          out[o] = data[o] ^ ks[0];
          reg.copyWithin(0, 1); reg[bs - 1] = decrypt ? data[o] : out[o];
        }
      } else {
        throw new Error('暂不支持 CFB-' + bits + '（仅支持 CFB-8 与整块 CFB）');
      }
      return out;
    }

    if (mode === 'OFB') {
      const ks = new Uint8Array(bs);
      for (let o = 0; o < n; o += bs) {
        core.encryptBlock(key, reg, 0, ks, 0);
        reg.set(ks);
        const len = Math.min(bs, n - o);
        for (let i = 0; i < len; i++) out[o + i] = data[o + i] ^ ks[i];
      }
      return out;
    }

    if (mode === 'CTR') {
      const ctr = new Uint8Array(bs);
      ctr.set(ivv);
      const ks = new Uint8Array(bs);
      for (let o = 0; o < n; o += bs) {
        core.encryptBlock(key, ctr, 0, ks, 0);
        const len = Math.min(bs, n - o);
        for (let i = 0; i < len; i++) out[o + i] = data[o + i] ^ ks[i];
        for (let i = bs - 1; i >= 0; i--) { if (++ctr[i] & 0xff) break; }
      }
      return out;
    }

    throw new Error('不支持的加密模式：' + mode);
  }

  /* ======================================================================
   * 对外统一 API
   * ====================================================================== */

  const ALGO_BLOCK = { AES: 16, DES: 8, '3DES': 8, DES3: 8, SM4: 16 };

  // 把密钥按算法要求补/截断（对齐原版 getKEYBytes 行为）
  function fitKey(key, algo) {
    let want;
    if (algo === 'AES') want = key.length > 24 ? 32 : (key.length > 16 ? 24 : 16);
    else if (algo === 'DES') want = 8;
    else if (algo === '3DES' || algo === 'DES3') want = 24;
    else want = 16;
    const out = new Uint8Array(want);
    out.set(key.subarray(0, Math.min(want, key.length)));
    return out;
  }

  function coreFor(algo, key) {
    if (algo === 'AES') {
      const rk = aesExpandKey(key);
      return {
        blockSize: 16,
        encryptBlock: (k, i, io, o, oo) => aesEncryptBlock(rk, i, io, o, oo),
        decryptBlock: (k, i, io, o, oo) => aesDecryptBlock(rk, i, io, o, oo)
      };
    }
    if (algo === 'DES') {
      const sub = DES.subkeys(key);
      return {
        blockSize: 8,
        encryptBlock: (k, i, io, o, oo) => DES.block(sub, i, io, o, oo, false),
        decryptBlock: (k, i, io, o, oo) => DES.block(sub, i, io, o, oo, true)
      };
    }
    if (algo === '3DES' || algo === 'DES3') {
      const k1 = DES.subkeys(key.subarray(0, 8));
      const k2 = DES.subkeys(key.subarray(8, 16));
      const k3 = DES.subkeys(key.subarray(16, 24));
      const tmp = new Uint8Array(8);
      return {
        blockSize: 8,
        encryptBlock: (k, i, io, o, oo) => {
          DES.block(k1, i, io, tmp, 0, false);
          DES.block(k2, tmp, 0, tmp, 0, true);
          DES.block(k3, tmp, 0, o, oo, false);
        },
        decryptBlock: (k, i, io, o, oo) => {
          DES.block(k3, i, io, tmp, 0, true);
          DES.block(k2, tmp, 0, tmp, 0, false);
          DES.block(k1, tmp, 0, o, oo, true);
        }
      };
    }
    if (algo === 'SM4') return CT.sm4.core(key);
    throw new Error('不支持的算法：' + algo);
  }

  function process(params, decrypt) {
    const algo = params.algo;
    const data = U.asBytes(params.data || new Uint8Array(0));
    const rawKey = U.asBytes(params.key || new Uint8Array(0));

    if (algo === 'RC4') {
      if (!rawKey.length) throw new Error('RC4 需要密钥');
      return rc4(rawKey, data);
    }
    if (algo === 'XOR') {
      if (!rawKey.length) throw new Error('异或需要一个非空密钥');
      return U.xor(data, rawKey);
    }

    const key = fitKey(rawKey, algo);
    const core = coreFor(algo, key);
    const bs = core.blockSize;
    const mode = (params.mode || 'CBC').toUpperCase();
    const padding = params.padding || 'PKCS7';
    const ivBytes = U.asBytes(params.iv || new Uint8Array(0));
    const iv = new Uint8Array(bs);
    iv.set(ivBytes.subarray(0, bs));

    const body = decrypt ? data : pad(data, padding, bs, key.length);
    const res = runMode(core, key, iv, mode, body, decrypt, bs, params.cfbBits);
    return decrypt ? unpad(res, padding, bs) : res;
  }

  return {
    encrypt: p => process(p, false),
    decrypt: p => process(p, true),
    rc4,
    pad, unpad, fitKey,
    _aes: { expand: aesExpandKey, encryptBlock: aesEncryptBlock, decryptBlock: aesDecryptBlock },
    _des: DES,
    _runMode: runMode, _coreFor: coreFor
  };
})();
