/* ===========================================================================
 * 编码工具箱 · 基础层
 *   CT.util  —— 字节 / 十六进制 / Base64 / 字符集 / 校验和
 *   CT.hash  —— 哈希算法族（含国密 SM3、SHA-3/Keccak、RIPEMD-160）
 * 零依赖。所有函数输入输出均为 Uint8Array 或字符串（除非注明）。
 * =========================================================================== */

CT.util = (function () {
  const HEX_L = '0123456789abcdef';
  const HEX_U = '0123456789ABCDEF';

  /* ---------- 字符串 <-> 字节 ---------- */

  function utf8Enc(str) {
    // 手写 UTF-8 编码：不依赖 TextEncoder，保证 file:// 与旧引擎一致
    const out = [];
    for (let i = 0; i < str.length; i++) {
      let c = str.charCodeAt(i);
      // 处理代理对（emoji 等）
      if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
        const d = str.charCodeAt(i + 1);
        if (d >= 0xdc00 && d <= 0xdfff) {
          c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
          i++;
        }
      }
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
      else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
      else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 0x3f), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
    return Uint8Array.from(out);
  }

  function utf8Dec(b, fatal) {
    let s = '';
    for (let i = 0; i < b.length; ) {
      const c = b[i++];
      let cp;
      if (c < 0x80) cp = c;
      else if (c >= 0xc0 && c < 0xe0) cp = ((c & 0x1f) << 6) | (b[i++] & 0x3f);
      else if (c >= 0xe0 && c < 0xf0) cp = ((c & 0x0f) << 12) | ((b[i++] & 0x3f) << 6) | (b[i++] & 0x3f);
      else if (c >= 0xf0) cp = ((c & 0x07) << 18) | ((b[i++] & 0x3f) << 12) | ((b[i++] & 0x3f) << 6) | (b[i++] & 0x3f);
      else { if (fatal) throw new Error('UTF-8 字节序列非法'); cp = 0xfffd; }
      if (cp > 0xffff) {
        cp -= 0x10000;
        s += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
      } else s += String.fromCharCode(cp);
    }
    return s;
  }

  function utf16leEnc(str) {
    const o = new Uint8Array(str.length * 2);
    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i);
      o[i * 2] = c & 0xff; o[i * 2 + 1] = c >> 8;
    }
    return o;
  }
  function utf16beEnc(str) {
    const o = new Uint8Array(str.length * 2);
    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i);
      o[i * 2 + 1] = c & 0xff; o[i * 2] = c >> 8;
    }
    return o;
  }
  function utf16leDec(b) {
    let s = '';
    for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode(b[i] | (b[i + 1] << 8));
    return s;
  }
  function utf16beDec(b) {
    let s = '';
    for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode((b[i] << 8) | b[i + 1]);
    return s;
  }

  function latin1Enc(str) {
    const o = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) o[i] = str.charCodeAt(i) & 0xff;
    return o;
  }
  function latin1Dec(b) {
    let s = '';
    const CH = 8192;
    for (let i = 0; i < b.length; i += CH) s += String.fromCharCode.apply(null, b.subarray(i, i + CH));
    return s;
  }

  /* ---------- hex ---------- */

  function hex(b, upper) {
    const T = upper ? HEX_U : HEX_L;
    let s = '';
    for (let i = 0; i < b.length; i++) s += T[b[i] >> 4] + T[b[i] & 15];
    return s;
  }

  // 宽松解析：忽略非十六进制字符；奇数长度时末尾单字符按高位补零处理（原版直接丢弃）
  function unhex(str, keepOddTail) {
    const clean = String(str).replace(/[^0-9a-fA-F]/g, '');
    const n = keepOddTail ? Math.ceil(clean.length / 2) : (clean.length >> 1);
    const o = new Uint8Array(n);
    for (let i = 0; i < n; i++) o[i] = parseInt(clean.substr(i * 2, 2), 16);
    return o;
  }

  /* ---------- Base64（标准表，无换行） ---------- */

  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const B64_URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

  function b64enc(b, urlSafe, pad) {
    const T = urlSafe ? B64_URL : B64;
    const usePad = pad !== false;
    let out = '';
    for (let i = 0; i < b.length; i += 3) {
      const n = (b[i] << 16) | ((b[i + 1] || 0) << 8) | (b[i + 2] || 0);
      const rem = b.length - i;
      out += T[(n >> 18) & 63] + T[(n >> 12) & 63];
      out += rem > 1 ? T[(n >> 6) & 63] : (usePad ? '=' : '');
      out += rem > 2 ? T[n & 63] : (usePad ? '=' : '');
    }
    return out;
  }

  function b64dec(str, urlSafe) {
    let s = String(str).replace(/[\s\r\n]/g, '');
    if (urlSafe || /[-_]/.test(s)) s = s.replace(/-/g, '+').replace(/_/g, '/');
    s = s.replace(/=+$/, '');
    const out = [];
    let acc = 0, bits = 0;
    for (let i = 0; i < s.length; i++) {
      const idx = B64.indexOf(s[i]);
      if (idx < 0) continue;
      acc = (acc << 6) | idx; bits += 6;
      if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); }
    }
    return Uint8Array.from(out);
  }

  /* ---------- 杂项 ---------- */

  function concat() {
    let n = 0;
    for (let i = 0; i < arguments.length; i++) n += arguments[i].length;
    const o = new Uint8Array(n);
    let p = 0;
    for (let i = 0; i < arguments.length; i++) { o.set(arguments[i], p); p += arguments[i].length; }
    return o;
  }
  function equal(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }
  function xor(a, b) {
    const o = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) o[i] = a[i] ^ b[i % b.length];
    return o;
  }
  // 循环右移（用于各种分组密码）
  function rotl32(v, n) { return ((v << n) | (v >>> (32 - n))) >>> 0; }
  function rotr32(v, n) { return ((v >>> n) | (v << (32 - n))) >>> 0; }
  function rotl64(v, n) {
    n = BigInt(n) & 63n;
    return ((v << n) | (v >> (64n - n))) & 0xffffffffffffffffn;
  }
  function rotr64(v, n) {
    n = BigInt(n) & 63n;
    return ((v >> n) | (v << (64n - n))) & 0xffffffffffffffffn;
  }
  function toU32(x) { return Number(x & 0xffffffffn) >>> 0; }
  function fromU32(x) { return BigInt(x >>> 0); }

  function readBE(b) { let v = 0n; for (let i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]); return v; }
  function writeBE(v, len) {
    const o = new Uint8Array(len);
    for (let i = len - 1; i >= 0; i--) { o[i] = Number(v & 0xffn); v >>= 8n; }
    return o;
  }
  function packU32BE(v) {
    return Uint8Array.of((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
  }
  function packU32LE(v) {
    return Uint8Array.of(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff);
  }

  // 把任意输入统一成字节
  function asBytes(x) {
    if (x instanceof Uint8Array) return x;
    if (Array.isArray(x)) return Uint8Array.from(x);
    if (typeof x === 'string') return utf8Enc(x);
    if (x && typeof x.length === 'number') return Uint8Array.from(x);
    throw new Error('无法转换为字节数组');
  }

  /* ---------- 校验和 ---------- */

  // CRC-32 / IEEE 802.3（与原版 java.util.zip.CRC32 一致）
  const CRC32_T = (function () {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c >>> 0;
    }
    return t;
  })();

  function crc32(b, seed) {
    let c = (seed === undefined ? 0 : seed) ^ 0xffffffff;
    for (let i = 0; i < b.length; i++) c = CRC32_T[(c ^ b[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  }

  // CRC-32C / Castagnoli（iSCSI、ext4）
  const CRC32C_T = (function () {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0x82f63b78 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c >>> 0;
    }
    return t;
  })();
  function crc32c(b) {
    let c = 0xffffffff;
    for (let i = 0; i < b.length; i++) c = CRC32C_T[(c ^ b[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  }

  // CRC-16 常见变体
  function crc16(b, poly, init, refin, refout, xorout) {
    let crc = init;
    if (refin) {
      for (let i = 0; i < b.length; i++) {
        crc ^= b[i];
        for (let k = 0; k < 8; k++) crc = (crc & 1) ? ((crc >>> 1) ^ poly) : (crc >>> 1);
      }
    } else {
      for (let i = 0; i < b.length; i++) {
        crc ^= b[i] << 8;
        for (let k = 0; k < 8; k++) crc = (crc & 0x8000) ? (((crc << 1) ^ poly) & 0xffff) : ((crc << 1) & 0xffff);
      }
    }
    if (refout !== refin) crc = reverse16(crc);
    return (crc ^ xorout) & 0xffff;
  }
  function reverse16(v) { let r = 0; for (let i = 0; i < 16; i++) { r = (r << 1) | (v & 1); v >>= 1; } return r & 0xffff; }

  const CRC16_VARIANTS = {
    'CRC-16/ARC':      { poly: 0xa001, init: 0x0000, refin: true,  refout: true,  xorout: 0x0000 },
    'CRC-16/CCITT':    { poly: 0x1021, init: 0x0000, refin: false, refout: false, xorout: 0x0000 },
    'CRC-16/XMODEM':   { poly: 0x1021, init: 0x0000, refin: false, refout: false, xorout: 0x0000 },
    'CRC-16/MODBUS':   { poly: 0xa001, init: 0xffff, refin: true,  refout: true,  xorout: 0x0000 },
    'CRC-16/USB':      { poly: 0xa001, init: 0xffff, refin: true,  refout: true,  xorout: 0xffff },
    'CRC-16/X-25':     { poly: 0x8408, init: 0xffff, refin: true,  refout: true,  xorout: 0xffff },
    'CRC-16/DNP':      { poly: 0xa6bc, init: 0x0000, refin: true,  refout: true,  xorout: 0xffff }
  };

  // Adler-32（与原版 java.util.zip.Adler32 一致）
  function adler32(b) {
    let a = 1, s = 0;
    for (let i = 0; i < b.length; i++) {
      a += b[i];
      s += a;
      if ((i & 0xfff) === 0xfff) { a %= 65521; s %= 65521; }
    }
    return (((s % 65521) << 16) | (a % 65521)) >>> 0;
  }

  return {
    utf8Enc, utf8Dec, utf16leEnc, utf16beEnc, utf16leDec, utf16beDec,
    latin1Enc, latin1Dec,
    hex, unhex, b64enc, b64dec, B64, B64_URL,
    concat, equal, xor, asBytes,
    rotl32, rotr32, rotl64, rotr64, toU32, fromU32,
    readBE, writeBE, packU32BE, packU32LE,
    crc32, crc32c, crc16, CRC16_VARIANTS, adler32
  };
})();


CT.hash = (function () {
  const U = CT.util;

  /* ======================= 工具：整数立方根 → 常量 ======================= */

  function primes(n) {
    const out = [];
    for (let x = 2; out.length < n; x++) {
      let ok = true;
      for (let i = 0; i < out.length && out[i] * out[i] <= x; i++) if (x % out[i] === 0) { ok = false; break; }
      if (ok) out.push(x);
    }
    return out;
  }

  function icbrt(n) {
    if (n < 2n) return n;
    let x = 1n << BigInt(Math.ceil(n.toString(2).length / 3) + 1);
    for (;;) {
      const y = (2n * x + n / (x * x)) / 3n;
      if (y >= x) return x;
      x = y;
    }
  }

  // K[i] = floor(frac(cbrt(p_i)) * 2^bits)  —— SHA-2 标准常量，精确整数推导
  function cubeFracConstants(count, bits) {
    const out = [];
    const scale = 1n << BigInt(bits * 3);
    for (const p of primes(count)) {
      const c = icbrt(BigInt(p) * scale);
      out.push(c & ((1n << BigInt(bits)) - 1n));
    }
    return out;
  }

  // H0 = floor(frac(sqrt(p_i)) * 2^bits)
  function sqrtFracConstants(count, bits) {
    const out = [];
    const scale = 1n << BigInt(bits * 2);
    for (const p of primes(count)) {
      let x = 1n << BigInt(Math.ceil((BigInt(p) * scale).toString(2).length / 2) + 1);
      for (;;) { const y = (x + (BigInt(p) * scale) / x) >> 1n; if (y >= x) break; x = y; }
      out.push(x & ((1n << BigInt(bits)) - 1n));
    }
    return out;
  }

  const K256 = cubeFracConstants(64, 32);
  const H256 = sqrtFracConstants(8, 32);
  const K512 = cubeFracConstants(80, 64);
  const H512 = sqrtFracConstants(8, 64);

  /* ======================= MD5 ======================= */

  function md5(msg) {
    // MD5 的常量来自 floor(|sin(i+1)| * 2^32)，与 SHA-2 的立方根常量不是一回事
    const K = new Uint32Array(64);
    for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) >>> 0;
    const S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
               5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
               4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
               6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
    let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    const m = padLE(msg, 8);
    const M = new Uint32Array(16);
    for (let off = 0; off < m.length; off += 64) {
      for (let i = 0; i < 16; i++) M[i] = m[off + i * 4] | (m[off + i * 4 + 1] << 8) | (m[off + i * 4 + 2] << 16) | (m[off + i * 4 + 3] << 24);
      let A = a0, B = b0, C = c0, D = d0;
      for (let i = 0; i < 64; i++) {
        let F, g;
        if (i < 16) { F = (B & C) | (~B & D); g = i; }
        else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) & 15; }
        else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) & 15; }
        else { F = C ^ (B | ~D); g = (7 * i) & 15; }
        F = (F + A + K[i] + M[g]) >>> 0;
        A = D; D = C; C = B;
        B = (B + U.rotl32(F, S[i])) >>> 0;
      }
      a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
    }
    return U.concat(U.packU32LE(a0), U.packU32LE(b0), U.packU32LE(c0), U.packU32LE(d0));
  }

  /* ======================= MD2（RFC 1319） ======================= */

  const MD2_S = Uint8Array.from([
    41,46,67,201,162,216,124,1,61,54,84,161,236,240,6,19,98,167,5,243,192,199,115,140,152,147,43,217,188,76,130,202,
    30,155,87,60,253,212,224,22,103,66,111,24,138,23,229,18,190,78,196,214,218,158,222,73,160,251,245,142,187,47,238,122,
    169,104,121,145,21,178,7,63,148,194,16,137,11,34,95,33,128,127,93,154,90,144,50,39,53,62,204,231,191,247,151,3,
    255,25,48,179,72,165,181,209,215,94,146,42,172,86,170,198,79,184,56,210,150,164,125,182,118,252,107,226,156,116,4,241,
    69,157,112,89,100,113,135,32,134,91,207,101,230,45,168,2,27,96,37,173,174,176,185,246,28,70,97,105,52,64,126,15,
    85,71,163,35,221,81,175,58,195,92,249,206,186,197,234,38,44,83,13,110,133,40,132,9,211,223,205,244,65,129,77,82,
    106,220,55,200,108,193,171,250,36,225,123,8,12,189,177,74,120,136,149,139,227,99,232,109,233,203,213,254,59,0,29,57,
    242,239,183,14,102,88,208,228,166,119,114,248,235,117,75,10,49,68,80,180,143,237,31,26,219,153,141,51,159,17,131,20
  ]);

  function md2(msg) {
    const L = 16;
    // Step 1：无论消息长度是否为 16 的倍数，都必须补块（长度为 16 的倍数时补满一整块）
    const n = Math.floor(msg.length / L) + 1;
    const padLen = n * L - msg.length;
    let m = U.concat(msg, new Uint8Array(padLen).fill(padLen));

    // Step 2：独立计算 16 字节校验和，带 L 链式递推（RFC 1319 §3.2）
    const C = new Uint8Array(16);
    let l = 0;
    for (let i = 0; i < m.length; i++) {
      C[i % 16] ^= MD2_S[m[i] ^ l];
      l = C[i % 16];
    }
    m = U.concat(m, C);                    // 校验和作为最后一块参与运算

    // Step 3~4：48 字节状态，18 轮变换，逐块处理
    const X = new Uint8Array(48);
    for (let i = 0; i < m.length; i += L) {
      for (let j = 0; j < L; j++) { X[16 + j] = m[i + j]; X[32 + j] = X[16 + j] ^ X[j]; }
      let t = 0;
      for (let j = 0; j < 18; j++) {
        for (let k = 0; k < 48; k++) { X[k] ^= MD2_S[t]; t = X[k]; }
        t = (t + j) & 0xff;
      }
    }
    return X.slice(0, 16);
  }

  /* ======================= MD4（RFC 1320） ======================= */

  function md4(msg) {
    let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
    const m = padLE(msg, 8);
    const M = new Uint32Array(16);
    for (let off = 0; off < m.length; off += 64) {
      for (let i = 0; i < 16; i++) M[i] = m[off + i * 4] | (m[off + i * 4 + 1] << 8) | (m[off + i * 4 + 2] << 16) | (m[off + i * 4 + 3] << 24);
      let A = a, B = b, C = c, D = d;
      const R = (v, n) => U.rotl32(v, n);
      // round 1: F(x,y,z) = (x&y)|(~x&z), k = 0..15
      for (let i = 0; i < 16; i += 4) {
        A = R((A + ((B & C) | (~B & D)) + M[i]) >>> 0, 3);
        D = R((D + ((A & B) | (~A & C)) + M[i + 1]) >>> 0, 7);
        C = R((C + ((D & A) | (~D & B)) + M[i + 2]) >>> 0, 11);
        B = R((B + ((C & D) | (~C & A)) + M[i + 3]) >>> 0, 19);
      }
      // round 2: G(x,y,z) = (x&y)|(x&z)|(y&z), k = 0,4,8,12,1,5,...
      const K2 = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15];
      for (let i = 0; i < 16; i += 4) {
        A = R((A + ((B & C) | (B & D) | (C & D)) + M[K2[i]] + 0x5a827999) >>> 0, 3);
        D = R((D + ((A & B) | (A & C) | (B & C)) + M[K2[i + 1]] + 0x5a827999) >>> 0, 5);
        C = R((C + ((D & A) | (D & B) | (A & B)) + M[K2[i + 2]] + 0x5a827999) >>> 0, 9);
        B = R((B + ((C & D) | (C & A) | (D & A)) + M[K2[i + 3]] + 0x5a827999) >>> 0, 13);
      }
      // round 3: H(x,y,z) = x^y^z, k = 0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15
      const K3 = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15];
      for (let i = 0; i < 16; i += 4) {
        A = R((A + (B ^ C ^ D) + M[K3[i]] + 0x6ed9eba1) >>> 0, 3);
        D = R((D + (A ^ B ^ C) + M[K3[i + 1]] + 0x6ed9eba1) >>> 0, 9);
        C = R((C + (D ^ A ^ B) + M[K3[i + 2]] + 0x6ed9eba1) >>> 0, 11);
        B = R((B + (C ^ D ^ A) + M[K3[i + 3]] + 0x6ed9eba1) >>> 0, 15);
      }
      a = (a + A) >>> 0; b = (b + B) >>> 0; c = (c + C) >>> 0; d = (d + D) >>> 0;
    }
    return U.concat(U.packU32LE(a), U.packU32LE(b), U.packU32LE(c), U.packU32LE(d));
  }

  /* ======================= SHA-1 ======================= */

  function sha1(msg) {
    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    const m = padBE(msg, 8);
    const w = new Uint32Array(80);
    for (let off = 0; off < m.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = (m[off + i * 4] << 24) | (m[off + i * 4 + 1] << 16) | (m[off + i * 4 + 2] << 8) | m[off + i * 4 + 3];
      for (let i = 16; i < 80; i++) w[i] = U.rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
      let a = h0, b = h1, c = h2, d = h3, e = h4;
      for (let i = 0; i < 80; i++) {
        let f, k;
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else { f = b ^ c ^ d; k = 0xca62c1d6; }
        const t = (U.rotl32(a, 5) + f + e + k + w[i]) >>> 0;
        e = d; d = c; c = U.rotl32(b, 30); b = a; a = t;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0; h4 = (h4 + e) >>> 0;
    }
    return U.concat(U.packU32BE(h0), U.packU32BE(h1), U.packU32BE(h2), U.packU32BE(h3), U.packU32BE(h4));
  }

  /* ======================= SHA-224 / SHA-256 ======================= */

  function sha256core(msg, outLen) {
    // SHA-256 的 IV 由 sqrtFracConstants 精确推导（等价于标准常量，顺带自校验推导）；
    // SHA-224 的 IV 是另一组定值，直接写死。
    const H = outLen === 28
      ? [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4]
      : H256.map(v => Number(v) >>> 0);
    const K = K256.map(Number);
    const m = padBE(msg, 8);
    const w = new Uint32Array(64);
    for (let off = 0; off < m.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = (m[off + i * 4] << 24) | (m[off + i * 4 + 1] << 16) | (m[off + i * 4 + 2] << 8) | m[off + i * 4 + 3];
      for (let i = 16; i < 64; i++) {
        const s0 = U.rotr32(w[i - 15], 7) ^ U.rotr32(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = U.rotr32(w[i - 2], 17) ^ U.rotr32(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const S1 = U.rotr32(e, 6) ^ U.rotr32(e, 11) ^ U.rotr32(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        const S0 = U.rotr32(a, 2) ^ U.rotr32(a, 13) ^ U.rotr32(a, 22);
        const mj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + mj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    const out = [];
    for (let i = 0; i < 8; i++) out.push(U.packU32BE(H[i]));
    const full = U.concat.apply(null, out);
    return outLen === 28 ? full.slice(0, 28) : full;
  }
  function sha256(m) { return sha256core(m, 32); }
  function sha224(m) { return sha256core(m, 28); }

  /* ======================= SHA-384 / SHA-512（BigInt 64 位） ======================= */

  const M64 = 0xffffffffffffffffn;

  function sha512core(msg, outLen) {
    // 标准初始值（SHA-512 / SHA-384 / SHA-512-224 / SHA-512-256 只差 IV 与截断长度）
    const IV = {
      64: [0x6a09e667f3bcc908n,0xbb67ae8584caa73bn,0x3c6ef372fe94f82bn,0xa54ff53a5f1d36f1n,
           0x510e527fade682d1n,0x9b05688c2b3e6c1fn,0x1f83d9abfb41bd6bn,0x5be0cd19137e2179n],
      48: [0xcbbb9d5dc1059ed8n,0x629a292a367cd507n,0x9159015a3070dd17n,0x152fecd8f70e5939n,
           0x67332667ffc00b31n,0x8eb44a8768581511n,0xdb0c2e0d64f98fa7n,0x47b5481dbefa4fa4n],
      // SHA-512/224（FIPS 180-4 §5.3.6）
      28: [0x8c3d37c819544da2n,0x73e1996689dcd4d6n,0x1dfab7ae32ff9c82n,0x679dd514582f9fcfn,
           0x0f6d2b697bd44da8n,0x77e36f7304c48942n,0x3f9d85a86a1d36c8n,0x1112e6ad91d692a1n],
      // SHA-512/256（FIPS 180-4 §5.3.7）
      32: [0x22312194fc2bf72cn,0x9f555fa3c84c64c2n,0x2393b86b6f53b151n,0x963877195940eabdn,
           0x96283ee2a88effe3n,0xbe5e1e2553863992n,0x2b0199fc2c85b8aan,0x0eb72ddc81c52ca2n]
    }[outLen];
    const K = K512.map(v => v & M64);
    const H = IV.slice();
    const m = padBE(msg, 16, 128);
    const w = new Array(80);
    for (let off = 0; off < m.length; off += 128) {
      for (let i = 0; i < 16; i++) {
        let v = 0n;
        for (let j = 0; j < 8; j++) v = (v << 8n) | BigInt(m[off + i * 8 + j]);
        w[i] = v;
      }
      for (let i = 16; i < 80; i++) {
        const s0 = U.rotr64(w[i - 15], 1) ^ U.rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7n);
        const s1 = U.rotr64(w[i - 2], 19) ^ U.rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6n);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & M64;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 80; i++) {
        const S1 = U.rotr64(e, 14) ^ U.rotr64(e, 18) ^ U.rotr64(e, 41);
        const ch = (e & f) ^ ((~e & M64) & g);
        const t1 = (h + S1 + ch + K[i] + w[i]) & M64;
        const S0 = U.rotr64(a, 28) ^ U.rotr64(a, 34) ^ U.rotr64(a, 39);
        const mj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + mj) & M64;
        h = g; g = f; f = e; e = (d + t1) & M64; d = c; c = b; b = a; a = (t1 + t2) & M64;
      }
      const nv = [a, b, c, d, e, f, g, h];
      for (let i = 0; i < 8; i++) H[i] = (H[i] + nv[i]) & M64;
    }
    const out = [];
    for (let i = 0; i < 8; i++) out.push(U.writeBE(H[i], 8));
    const full = U.concat.apply(null, out);
    return outLen === 64 ? full : full.slice(0, outLen);
  }
  function sha512(m) { return sha512core(m, 64); }
  function sha384(m) { return sha512core(m, 48); }
  function sha512_224(m) { return sha512core(m, 28); }
  function sha512_256(m) { return sha512core(m, 32); }

  /* ======================= SHA-3 / Keccak ======================= */

  const RC = [
    0x0000000000000001n,0x0000000000008082n,0x800000000000808an,0x8000000080008000n,
    0x000000000000808bn,0x0000000080000001n,0x8000000080008081n,0x8000000000008009n,
    0x000000000000008an,0x0000000000000088n,0x0000000080008009n,0x000000008000000an,
    0x000000008000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,
    0x8000000000008002n,0x8000000000000080n,0x000000000000800an,0x800000008000000an,
    0x8000000080008081n,0x8000000000008080n,0x0000000080000001n,0x8000000080008008n
  ];
  const ROTC = [
    [0,36,3,41,18],
    [1,44,10,45,2],
    [62,6,43,15,61],
    [28,55,25,21,56],
    [27,20,39,8,14]
  ];
  const M64K = 0xffffffffffffffffn;

  function keccakF(A) {
    for (let round = 0; round < 24; round++) {
      const C = new Array(5);
      for (let x = 0; x < 5; x++) C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
      for (let x = 0; x < 5; x++) {
        const D = C[(x + 4) % 5] ^ U.rotl64(C[(x + 1) % 5], 1);
        for (let y = 0; y < 5; y++) A[x + 5 * y] = (A[x + 5 * y] ^ D) & M64K;
      }
      const B = new Array(25).fill(0n);
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) {
        B[y + 5 * ((2 * x + 3 * y) % 5)] = U.rotl64(A[x + 5 * y], ROTC[x][y]);
      }
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) {
        A[x + 5 * y] = (B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y] & M64K) & B[(x + 2) % 5 + 5 * y])) & M64K;
      }
      A[0] = (A[0] ^ RC[round]) & M64K;
    }
    return A;
  }

  // rate 单位：字节
  function keccak(msg, rateBytes, outLen, domainPad) {
    const A = new Array(25).fill(0n);
    const block = rateBytes;
    const padLen = block - (msg.length % block);
    const padded = U.concat(msg, new Uint8Array(padLen));
    // 多填充位：0x01 ... 0x80（SHA-3）或 0x80（原始 Keccak，domainPad=0x01 时用 0x00 起始）
    padded[msg.length] = domainPad;
    padded[padded.length - 1] |= 0x80;

    for (let off = 0; off < padded.length; off += block) {
      for (let i = 0; i < block / 8; i++) {
        let v = 0n;
        for (let j = 0; j < 8; j++) v |= BigInt(padded[off + i * 8 + j]) << BigInt(8 * j);
        A[i] = (A[i] ^ v) & M64K;
      }
      keccakF(A);
    }
    const out = new Uint8Array(outLen);
    let p = 0;
    outer:
    for (;;) {
      for (let i = 0; i < block / 8 && p < outLen; i++) {
        let v = A[i];
        for (let j = 0; j < 8 && p < outLen; j++) { out[p++] = Number(v & 0xffn); v >>= 8n; }
      }
      if (p >= outLen) break outer;
      keccakF(A);
    }
    return out;
  }

  const sha3_224 = m => keccak(m, 144, 28, 0x06);
  const sha3_256 = m => keccak(m, 136, 32, 0x06);
  const sha3_384 = m => keccak(m, 104, 48, 0x06);
  const sha3_512 = m => keccak(m, 72, 64, 0x06);
  const shake128 = (m, n) => keccak(m, 168, n, 0x1f);
  const shake256 = (m, n) => keccak(m, 136, n, 0x1f);
  // 原始 Keccak（以太坊用 Keccak-256，填充位为 0x01，与 NIST SHA-3 不同）
  const keccak256 = m => keccak(m, 136, 32, 0x01);
  const keccak512 = m => keccak(m, 72, 64, 0x01);

  /* ======================= RIPEMD-160 ======================= */

  function ripemd160(msg) {
    const zl = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
                7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
                3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
                1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
                4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
    const zr = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
                6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
                15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
                8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
                12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
    const sl = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
                7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
                11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
                11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
                9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
    const sr = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
                9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
                9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
                15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
                8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
    let h0=0x67452301,h1=0xefcdab89,h2=0x98badcfe,h3=0x10325476,h4=0xc3d2e1f0;
    const m = padLE(msg, 8);
    const X = new Uint32Array(16);
    for (let off = 0; off < m.length; off += 64) {
      for (let i = 0; i < 16; i++) X[i] = m[off+i*4] | (m[off+i*4+1]<<8) | (m[off+i*4+2]<<16) | (m[off+i*4+3]<<24);
      let al=h0,bl=h1,cl=h2,dl=h3,el=h4;
      let ar=h0,br=h1,cr=h2,dr=h3,er=h4;
      for (let j = 0; j < 80; j++) {
        const rnd = (j / 16) | 0;
        let f, K;
        if (rnd === 0) { f = bl ^ cl ^ dl; K = 0x00000000; }
        else if (rnd === 1) { f = (bl & cl) | (~bl & dl); K = 0x5a827999; }
        else if (rnd === 2) { f = (bl | ~cl) ^ dl; K = 0x6ed9eba1; }
        else if (rnd === 3) { f = (bl & dl) | (cl & ~dl); K = 0x8f1bbcdc; }
        else { f = bl ^ (cl | ~dl); K = 0xa953fd4e; }
        const t = (U.rotl32((al + f + X[zl[j]] + K) >>> 0, sl[j]) + el) >>> 0;
        al = el; el = dl; dl = U.rotl32(cl, 10); cl = bl; bl = t;

        if (rnd === 0) { f = br ^ (cr | ~dr); K = 0x50a28be6; }
        else if (rnd === 1) { f = (br & dr) | (cr & ~dr); K = 0x5c4dd124; }
        else if (rnd === 2) { f = (br | ~cr) ^ dr; K = 0x6d703ef3; }
        else if (rnd === 3) { f = (br & cr) | (~br & dr); K = 0x7a6d76e9; }
        else { f = br ^ cr ^ dr; K = 0x00000000; }
        const t2 = (U.rotl32((ar + f + X[zr[j]] + K) >>> 0, sr[j]) + er) >>> 0;
        ar = er; er = dr; dr = U.rotl32(cr, 10); cr = br; br = t2;
      }
      const t = (h1 + cl + dr) >>> 0;
      h1 = (h2 + dl + er) >>> 0;
      h2 = (h3 + el + ar) >>> 0;
      h3 = (h4 + al + br) >>> 0;
      h4 = (h0 + bl + cr) >>> 0;
      h0 = t;
    }
    return U.concat(U.packU32LE(h0), U.packU32LE(h1), U.packU32LE(h2), U.packU32LE(h3), U.packU32LE(h4));
  }

  /* ======================= SM3（GB/T 32905-2016） ======================= */

  function sm3(msg) {
    let V = [0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e];
    const m = padBE(msg, 8);
    const W = new Uint32Array(68), W1 = new Uint32Array(64);
    const T = 0x7a879d8a;
    const rot = U.rotl32;
    for (let off = 0; off < m.length; off += 64) {
      for (let i = 0; i < 16; i++) W[i] = ((m[off+i*4]<<24)|(m[off+i*4+1]<<16)|(m[off+i*4+2]<<8)|m[off+i*4+3]) >>> 0;
      for (let i = 16; i < 68; i++) {
        const x = (W[i-16] ^ W[i-9] ^ rot(W[i-3], 15)) >>> 0;
        const p1 = (x ^ rot(x, 15) ^ rot(x, 23)) >>> 0;
        W[i] = (p1 ^ rot(W[i-13], 7) ^ W[i-6]) >>> 0;
      }
      for (let i = 0; i < 64; i++) W1[i] = (W[i] ^ W[i + 4]) >>> 0;
      let [A,B,C,D,E,F,G,H] = V;
      for (let j = 0; j < 64; j++) {
        const Tj = j < 16 ? 0x79cc4519 : 0x7a879d8a;
        const A12 = rot(A, 12);
        let SS1 = rot((A12 + E + rot(Tj, j % 32)) >>> 0, 7);
        const SS2 = (SS1 ^ A12) >>> 0;
        const FF = j < 16 ? (A ^ B ^ C) : ((A & B) | (A & C) | (B & C));
        const GG = j < 16 ? (E ^ F ^ G) : ((E & F) | (~E & G));
        const TT1 = ((FF >>> 0) + D + SS2 + W1[j]) >>> 0;
        const TT2 = ((GG >>> 0) + H + SS1 + W[j]) >>> 0;
        D = C; C = rot(B, 9); B = A; A = TT1;
        H = G; G = rot(F, 19); F = E; E = (TT2 ^ rot(TT2, 9) ^ rot(TT2, 17)) >>> 0;
      }
      V = [ (V[0]^A)>>>0, (V[1]^B)>>>0, (V[2]^C)>>>0, (V[3]^D)>>>0,
            (V[4]^E)>>>0, (V[5]^F)>>>0, (V[6]^G)>>>0, (V[7]^H)>>>0 ];
    }
    return U.concat.apply(null, V.map(U.packU32BE));
  }

  /* ======================= 填充辅助 ======================= */

  // 填充长度：使 len + 1 + pad + lenBytes 恰为 block 的整数倍（pad 可为 0）
  function padCount(len, lenBytes, block) {
    const rem = (len + 1 + lenBytes) % block;
    return rem === 0 ? 0 : block - rem;
  }

  // 大端长度字段（SHA 家族）；block 默认 64，SHA-512 需传 128
  function padBE(msg, lenBytes, block) {
    block = block || 64;
    const bitLen = msg.length * 8;
    const padLen = padCount(msg.length, lenBytes, block);
    const tail = new Uint8Array(lenBytes);
    if (lenBytes === 8) {
      // 高 4 字节放 bitLen 高位（JS 安全整数范围内够用）
      const hi = Math.floor(bitLen / 4294967296);
      const lo = bitLen >>> 0;
      tail[0] = (hi >>> 24) & 0xff; tail[1] = (hi >>> 16) & 0xff; tail[2] = (hi >>> 8) & 0xff; tail[3] = hi & 0xff;
      tail[4] = (lo >>> 24) & 0xff; tail[5] = (lo >>> 16) & 0xff; tail[6] = (lo >>> 8) & 0xff; tail[7] = lo & 0xff;
    } else {
      // 128 位长度：高 8 字节为 0
      const lo = bitLen >>> 0;
      const hi = Math.floor(bitLen / 4294967296);
      tail[8] = (hi >>> 24) & 0xff; tail[9] = (hi >>> 16) & 0xff; tail[10] = (hi >>> 8) & 0xff; tail[11] = hi & 0xff;
      tail[12] = (lo >>> 24) & 0xff; tail[13] = (lo >>> 16) & 0xff; tail[14] = (lo >>> 8) & 0xff; tail[15] = lo & 0xff;
    }
    return U.concat(msg, Uint8Array.of(0x80), new Uint8Array(padLen), tail);
  }

  // 小端长度字段（MD 家族、RIPEMD）
  function padLE(msg, lenBytes, block) {
    block = block || 64;
    const bitLen = msg.length * 8;
    const padLen = padCount(msg.length, lenBytes, block);
    const tail = new Uint8Array(lenBytes);
    const lo = bitLen >>> 0;
    const hi = Math.floor(bitLen / 4294967296);
    tail[0] = lo & 0xff; tail[1] = (lo >>> 8) & 0xff; tail[2] = (lo >>> 16) & 0xff; tail[3] = (lo >>> 24) & 0xff;
    if (lenBytes === 8) { tail[4] = hi & 0xff; tail[5] = (hi >>> 8) & 0xff; tail[6] = (hi >>> 16) & 0xff; tail[7] = (hi >>> 24) & 0xff; }
    return U.concat(msg, Uint8Array.of(0x80), new Uint8Array(padLen), tail);
  }

  /* ======================= 算法注册表 ======================= */

  const ALGOS = {
    'MD2':        { fn: md2,        out: 16, block: 16, kind: 'hash' },
    'MD4':        { fn: md4,        out: 16, block: 64, kind: 'hash' },
    'MD5':        { fn: md5,        out: 16, block: 64, kind: 'hash' },
    'SHA-1':      { fn: sha1,       out: 20, block: 64, kind: 'hash' },
    'SHA-224':    { fn: sha224,     out: 28, block: 64, kind: 'hash' },
    'SHA-256':    { fn: sha256,     out: 32, block: 64, kind: 'hash' },
    'SHA-384':    { fn: sha384,     out: 48, block: 128, kind: 'hash' },
    'SHA-512':    { fn: sha512,     out: 64, block: 128, kind: 'hash' },
    'SHA-512/224':{ fn: sha512_224, out: 28, block: 128, kind: 'hash' },
    'SHA-512/256':{ fn: sha512_256, out: 32, block: 128, kind: 'hash' },
    'SHA3-224':   { fn: sha3_224,   out: 28, block: 144, kind: 'hash' },
    'SHA3-256':   { fn: sha3_256,   out: 32, block: 136, kind: 'hash' },
    'SHA3-384':   { fn: sha3_384,   out: 48, block: 104, kind: 'hash' },
    'SHA3-512':   { fn: sha3_512,   out: 64, block: 72,  kind: 'hash' },
    'Keccak-256': { fn: keccak256,  out: 32, block: 136, kind: 'hash' },
    'Keccak-512': { fn: keccak512,  out: 64, block: 72,  kind: 'hash' },
    'RIPEMD-160': { fn: ripemd160,  out: 20, block: 64, kind: 'hash' },
    'SM3':        { fn: sm3,        out: 32, block: 64, kind: 'hash' },
    'CRC32':      { fn: b => U.packU32BE(U.crc32(b)),      out: 4, kind: 'checksum' },
    'CRC32C':     { fn: b => U.packU32BE(U.crc32c(b)),     out: 4, kind: 'checksum' },
    'Adler32':    { fn: b => U.packU32BE(U.adler32(b)),    out: 4, kind: 'checksum' },
    // Java String.hashCode()：32 位有符号，转十进制字符串
    'JavaHash':   { fn: b => U.utf8Enc(String(javaHash(b))), out: 0, kind: 'checksum' }
  };
  // CRC32 / Adler32 的“原版呈现”：小写 hex，无前缀无补零
  function crc32Text(b) { return CT.util.crc32(b).toString(16); }
  function adler32Text(b) { return CT.util.adler32(b).toString(16); }

  function javaHash(b) {
    const s = U.utf8Dec(b);
    let h = 0;
    for (let i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
    return h;
  }

  // 原始 Keccak / SHA-3 的字节流（供外部使用）
  function hmac(hashName, key, msg) {
    const a = ALGOS[hashName];
    if (!a) throw new Error('不支持的哈希算法：' + hashName);
    const block = a.block;
    let k = key;
    if (k.length > block) k = a.fn(k);
    if (k.length < block) k = U.concat(k, new Uint8Array(block - k.length));
    const ipad = new Uint8Array(block), opad = new Uint8Array(block);
    for (let i = 0; i < block; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    return a.fn(U.concat(opad, a.fn(U.concat(ipad, msg))));
  }

  function pbkdf2(hashName, password, salt, iterations, dkLen) {
    const a = ALGOS[hashName];
    if (!a) throw new Error('不支持的哈希算法：' + hashName);
    const hLen = a.out;
    dkLen = dkLen || hLen;
    const blocks = Math.ceil(dkLen / hLen);
    const out = new Uint8Array(blocks * hLen);
    for (let i = 1; i <= blocks; i++) {
      const idx = U.packU32BE(i);
      let u = hmac(hashName, password, U.concat(salt, idx));
      const t = u.slice();
      for (let j = 1; j < iterations; j++) {
        u = hmac(hashName, password, u);
        for (let k = 0; k < hLen; k++) t[k] ^= u[k];
      }
      out.set(t, (i - 1) * hLen);
    }
    return out.slice(0, dkLen);
  }

  return {
    md2, md4, md5, sha1, sha224, sha256, sha384, sha512,
    sha512_224, sha512_256,
    sha3_224, sha3_256, sha3_384, sha3_512, shake128, shake256,
    keccak256, keccak512, ripemd160, sm3,
    javaHash, crc32Text, adler32Text,
    hmac, pbkdf2, ALGOS,
    _padBE: padBE, _padLE: padLE, _keccak: keccak, _keccakF: keccakF,
    _consts: { K256, H256, K512, H512, RC }
  };
})();
