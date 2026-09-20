/* ===========================================================================
 * 编码工具箱 · 进制 / BASE 层
 *   CT.base —— 原版 8 种（BASE16/32/36/58/62/64/85/91，行为逐字节对齐原 APP）
 *              + 扩展（BASE64URL / BASE58CHECK / BASE32HEX / Crockford32 / Z85 / BASE45）
 * =========================================================================== */

CT.base = (function () {
  const U = CT.util;

  /* ---------------- 原版字母表（与 dex 中完全一致） ---------------- */
  const ALPHABET = {
    base32: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
    base58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    base62: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
    // 注意：作者改过 basE91 字母表，标准里的 < > | 被替换成 ' \ -
    base91: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;\'=\\?@[]^_`{-}~"'
  };

  /* ---------------- 字节 <-> 字符串（Latin-1，对应 Java 的 byte[]） ---------------- */
  const s2b = U.latin1Enc;
  const b2s = U.latin1Dec;

  /* ================= BASE16 ================= */
  const b16e = b => U.hex(b, false);
  const b16d = s => U.unhex(s);

  /* ================= BASE64 ================= */
  const b64e = b => U.b64enc(b, false, true);
  // 原版走 Android Base64.decode(...,0)，对空白宽容；这里同样忽略空白
  const b64d = s => U.b64dec(String(s).replace(/[\s\r\n]/g, ''), false);

  /* ================= BASE32（原版自定义，无填充） ================= */

  function b32e(data) {
    const cArr = ALPHABET.base32;
    const n = data.length;
    const length = ((n * 8) / 5 | 0) + (n % 5 !== 0 ? 1 : 0);
    const out = new Array(length);
    let i = 0, p = 0;                       // i: 字节内位偏移, p: 当前字节
    for (let k = 0; k < length; k++) {
      if (i > 3) {
        const i4 = data[p] & (255 >> i);
        i = (i + 5) % 8;
        let i5 = i4 << i;
        if (p < n - 1) i5 |= (255 & data[p + 1]) >> (8 - i);
        out[k] = cArr[i5];
        p++;
      } else {
        const i6 = i + 5;
        out[k] = cArr[(data[p] >> (8 - i6)) & 31];
        i = i6 % 8;
        if (i === 0) p++;
      }
    }
    return out.join('');
  }

  function b32d(str) {
    const cArr = ALPHABET.base32;
    const map = new Int8Array(128).fill(-1);
    for (let i2 = 0; i2 < cArr.length; i2++) {
      const b = i2;
      map[cArr.charCodeAt(i2)] = b;
      // 原版只给前 24 个字母补小写映射，y/z 的小写不认
      if (i2 < 24) map[cArr.charCodeAt(i2) + 32] = b;
    }
    const ca = String(str);
    const length = (ca.length * 5) / 8 | 0;
    const out = new Int8Array(length);
    let i3 = 0, i4 = 0;
    for (let k = 0; k < ca.length; k++) {
      const cc = ca.charCodeAt(k);
      const b2 = cc < 128 ? map[cc] : -1;
      if (i3 <= 3) {
        i3 = (i3 + 5) % 8;
        if (i3 === 0) { out[i4] = b2 | out[i4]; i4++; }
        else out[i4] = (b2 << (8 - i3)) | out[i4];
      } else {
        i3 = (i3 + 5) % 8;
        const i5 = i4 + 1;
        out[i4] = out[i4] | (b2 >> i3);
        if (i5 < length) out[i5] = out[i5] | (b2 << (8 - i3));
        i4 = i5;
      }
    }
    return new Uint8Array(out.buffer, 0, length);
  }

  /* ================= BASE36（BigInteger 语义：有符号大端） ================= */

  function biFromBytes(b) {
    if (!b.length) throw new Error('Zero length BigInteger');
    let v = 0n;
    for (let i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]);
    if (b[0] & 0x80) v -= (1n << BigInt(8 * b.length));
    return v;
  }

  // 等价于 Java BigInteger.toByteArray()：最小二进制补码表示
  function biToBytes(v) {
    if (v === 0n) return Uint8Array.of(0);
    let n = 1;
    for (;;) {
      const half = 1n << BigInt(8 * n - 1);
      if (v >= -half && v < half) break;
      n++;
    }
    let m = v < 0n ? (1n << BigInt(8 * n)) + v : v;
    const out = new Uint8Array(n);
    for (let i = n - 1; i >= 0; i--) { out[i] = Number(m & 0xffn); m >>= 8n; }
    return out;
  }

  function b36e(data) {
    const s = biFromBytes(data).toString(36);
    if (s.charAt(0) === '-') return 'f' + s.slice(1);
    return 'z' + s;
  }
  function b36d(str) {
    const s = String(str);
    if (!s.length) throw new Error('StringIndexOutOfBoundsException');
    let v;
    if (s.charAt(0) === 'z') v = BigInt(parseRadix36(s.slice(1)));
    else v = -BigInt(parseRadix36(s.slice(1)));
    return biToBytes(v);
  }
  function parseRadix36(s) {
    if (!/^-?[0-9a-zA-Z]+$/.test(s)) throw new Error('NumberFormatException');
    let neg = false, t = s;
    if (t.charAt(0) === '-') { neg = true; t = t.slice(1); }
    let v = 0n;
    for (const ch of t.toLowerCase()) {
      const d = parseInt(ch, 36);
      if (isNaN(d)) throw new Error('NumberFormatException');
      v = v * 36n + BigInt(d);
    }
    return (neg ? -v : v).toString();
  }

  /* ================= BASE58（Bitcoin 版） ================= */

  function b58e(data) {
    const cArr = ALPHABET.base58, L = cArr.length;
    const a = Uint8Array.from(data);
    let i = 0;
    while (i < a.length && a[i] === 0) i++;
    const length = a.length * 2;
    const b = new Uint8Array(length);
    let i2 = i, i3 = length;
    while (i2 < a.length) {
      const d = divmod(a, i2, 256, L);
      if (a[i2] === 0) i2++;
      i3--;
      b[i3] = cArr.charCodeAt(d);
    }
    while (i3 < length && b[i3] === cArr.charCodeAt(0)) i3++;
    for (;;) {
      i--;
      if (i >= 0) { i3--; b[i3] = cArr.charCodeAt(0); }
      else return b2s(b.subarray(i3, length));
    }
  }
  // 就地除法：把 a[p..] 当作大整数，除以 divisor，返回余数；商写回 a
  function divmod(a, p, mul, divisor) {
    let r = 0;
    for (let i = p; i < a.length; i++) {
      const v = r * mul + (a[i] & 255);
      a[i] = (v / divisor) | 0;
      r = v % divisor;
    }
    return r;
  }
  function b58d(str) {
    const cArr = ALPHABET.base58, L = cArr.length;
    const s = String(str);
    const map = new Int8Array(128).fill(-1);
    for (let i = 0; i < L; i++) map[cArr.charCodeAt(i)] = i;
    const length = s.length;
    const a = new Int8Array(length);
    for (let i = 0; i < length; i++) {
      const cc = s.charCodeAt(i);
      a[i] = (cc < 0 || cc >= 128) ? -1 : map[cc];
    }
    let i4 = 0;
    while (i4 < length && a[i4] === 0) i4++;
    const b = new Int8Array(length);
    let i5 = i4, i6 = length;
    while (i5 < length) {
      const d = divmodI8(a, i5, L, 256);
      if (a[i5] === 0) i5++;
      i6--;
      b[i6] = d;
    }
    while (i6 < length && b[i6] === 0) i6++;
    return new Uint8Array(b.buffer, i6 - i4, length - (i6 - i4));
  }
  function divmodI8(a, p, mul, divisor) {
    let r = 0;
    for (let i = p; i < a.length; i++) {
      const v = r * mul + (a[i] & 255);
      a[i] = (v / divisor) | 0;
      r = v % divisor;
    }
    return r;
  }

  /* ================= BASE62（原版非常规实现：i 作转义前缀） ================= */

  function b62e(data) {
    const cArr = ALPHABET.base62;
    let sb = '';
    let i = 0, i2 = 0, i3 = 0;
    for (;;) {
      let s1 = 'ia', s2 = 'ic';
      if (i >= data.length) break;
      i2 = (i2 << 8) | (data[i] & 255);
      i3 += 8;
      while (i3 > 5) {
        i3 -= 6;
        const c = cArr[i2 >> i3];
        sb += c === 'i' ? 'ia' : (c === '+' ? 'ib' : (c === '/' ? 'ic' : c));
        i2 &= (1 << i3) - 1;
      }
      i++;
    }
    if (i3 > 0) {
      const c2 = cArr[i2 << (6 - i3)];
      if (c2 !== 'i') {
        if (c2 === '+') s2 = 'ib';
        else if (c2 !== '/') s2 = c2;
        s1 = s2;
      }
      sb += s1;
    }
    return sb;
  }

  function b62d(str) {
    const cArr = ALPHABET.base62;
    const map = new Uint8Array(256);
    const ca = String(str);
    const out = [];
    let i = 0, i2 = 0, i3 = 0;
    while (i < ca.length) {
      let c = ca[i];
      if (c === 'i') {
        i++;
        const c2 = ca[i];
        if (c2 === 'a') c = 'i';
        else if (c2 === 'b') c = '+';
        else if (c2 === 'c') c = '/';
        else { i--; c = ca[i]; }
      }
      for (let k = 0; k < cArr.length; k++) map[cArr.charCodeAt(k)] = k;
      i2 = (i2 << 6) | map[c.charCodeAt(0)];
      i3 += 6;
      while (i3 > 7) { i3 -= 8; out.push((i2 >> i3) & 0xff); i2 &= (1 << i3) - 1; }
      i++;
    }
    return Uint8Array.from(out);
  }

  /* ================= BASE85（ASCII85，零块用 z） ================= */

  function b85e(data) {
    const P = [1, 85, 7225, 614125, 52200625];
    let sb = '';
    const buf = new Int8Array(4);
    let i = 0;
    for (let k = 0; k < data.length; k++) {
      buf[i] = data[k];
      i++;
      if (i === 4) {
        const v = ((buf[0] & 255) << 24) | ((buf[1] & 255) << 16) | ((buf[2] & 255) << 8) | (buf[3] & 255);
        if (v === 0) sb += 'z';
        else {
          let j = v >>> 0;
          for (let m = 0; m < 5; m++) {
            const d = P[4 - m];
            sb += String.fromCharCode(Math.floor(j / d) + 33);
            j = j % d;
          }
        }
        buf.fill(0); i = 0;
      }
    }
    if (i > 0) {
      for (let m = i; m < 4; m++) buf[m] = 0;
      const v = ((buf[0] & 255) << 24) | ((buf[1] & 255) << 16) | ((buf[2] & 255) << 8) | (buf[3] & 255);
      const c = [];
      let j = v >>> 0;
      for (let m = 0; m < 5; m++) { const d = P[4 - m]; c.push(Math.floor(j / d) + 33); j = j % d; }
      for (let m = 0; m < c.length - (4 - i); m++) sb += String.fromCharCode(c[m]);
    }
    return sb;
  }

  function b85d(str) {
    const P = [1, 85, 7225, 614125, 52200625];
    const clean = s2b(String(str).replace(/\s+/g, ''));
    const buf = new Int8Array(5);
    const out = [];
    let i4 = 0;
    const chunk = b => {
      const v = (((b[0] & 255) - 33) * P[4] + 0 + ((b[1] & 255) - 33) * P[3] + ((b[2] & 255) - 33) * P[2]
              + ((b[3] & 255) - 33) * P[1] + ((b[4] & 255) - 33) * P[0]) | 0;
      return [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];
    };
    for (let k = 0; k < clean.length; k++) {
      const b = clean[k];
      let i;
      if (b === 122) {
        for (let m = 0; m < 5; m++) buf[i4 + m] = 33;
        i = i4 + 5;
      } else { buf[i4] = b; i = i4 + 1; }
      if (i !== 5) i4 = i;
      else { for (const x of chunk(buf)) out.push(x); buf.fill(0); i4 = 0; }
    }
    if (i4 > 0) {
      for (let m = i4; m < 5; m++) buf[m] = 117;
      const d = chunk(buf);
      for (let m = 0; m < d.length - (5 - i4); m++) out.push(d[m]);
    }
    return Uint8Array.from(out);
  }

  /* ================= BASE91（标准 basE91 + 作者改过的字母表） ================= */

  function b91e(data) {
    const cArr = ALPHABET.base91, L = cArr.length;
    let out = '';
    let i = 0, i2 = 0;
    for (let k = 0; k < data.length; k++) {
      i |= (data[k] & 255) << i2;
      i2 += 8;
      if (i2 > 13) {
        let i3 = i & 8191;
        if (i3 > 88) { i2 -= 13; i >>= 13; }
        else { i3 = i & 16383; i2 -= 14; i >>= 14; }
        out += cArr[i3 % L] + cArr[(i3 / L) | 0];
      }
    }
    if (i2 > 0) {
      out += cArr[i % L];
      if (i2 > 7 || i > 90) out += cArr[(i / L) | 0];
    }
    return out;
  }

  function b91d(str) {
    const cArr = ALPHABET.base91, L = cArr.length;
    const map = new Int8Array(256).fill(-1);
    for (let i = 0; i < L; i++) map[cArr.charCodeAt(i)] = i;
    const src = s2b(String(str));
    const out = [];
    let b2 = -1, i3 = 0, i4 = 0;
    for (let k = 0; k < src.length; k++) {
      const b4 = map[src[k] & 255];
      if (b4 !== -1) {
        if (b2 === -1) b2 = b4;
        else {
          const i5 = b2 + (b4 * L);
          i3 |= i5 << i4;
          i4 += (i5 & 8191) > 88 ? 13 : 14;
          do { out.push(i3 & 0xff); i3 >>= 8; i4 -= 8; } while (i4 > 7);
          b2 = -1;
        }
      }
    }
    if (b2 !== -1) out.push(((b2 << i4) | i3) & 0xff);
    return Uint8Array.from(out);
  }

  /* ================= 扩展：BASE64URL ================= */
  const b64ue = (b, pad) => U.b64enc(b, true, pad !== false);
  const b64ud = s => U.b64dec(s, true);

  /* ================= 扩展：BASE32HEX（RFC4648，带填充） ================= */
  const B32HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV';
  function b32hexe(data) {
    let out = '', bits = 0, acc = 0;
    for (let i = 0; i < data.length; i++) {
      acc = (acc << 8) | data[i]; bits += 8;
      while (bits >= 5) { bits -= 5; out += B32HEX[(acc >> bits) & 31]; }
    }
    if (bits > 0) out += B32HEX[(acc << (5 - bits)) & 31];
    while (out.length % 8) out += '=';
    return out;
  }
  function b32hexd(str) {
    const s = String(str).replace(/=+$/, '').toUpperCase();
    const map = new Map();
    for (let i = 0; i < B32HEX.length; i++) map.set(B32HEX[i], i);
    let out = [], bits = 0, acc = 0;
    for (const ch of s) {
      const v = map.get(ch);
      if (v === undefined) continue;
      acc = (acc << 5) | v; bits += 5;
      if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); }
    }
    return Uint8Array.from(out);
  }

  /* ================= 扩展：Crockford Base32 ================= */
  const CROCK = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  function crocke(data) {
    let out = '', bits = 0, acc = 0;
    for (let i = 0; i < data.length; i++) {
      acc = (acc << 8) | data[i]; bits += 8;
      while (bits >= 5) { bits -= 5; out += CROCK[(acc >> bits) & 31]; }
    }
    if (bits > 0) out += CROCK[(acc << (5 - bits)) & 31];
    return out;   // Crockford 规范不补 '='，也不分组
  }
  function crockd(str) {
    const s = String(str).toUpperCase().replace(/[-\s]/g, '')
      .replace(/[IL]/g, '1').replace(/O/g, '0');
    const map = new Map();
    for (let i = 0; i < CROCK.length; i++) map.set(CROCK[i], i);
    let out = [], bits = 0, acc = 0;
    for (const ch of s) {
      const v = map.get(ch);
      if (v === undefined) throw new Error('Crockford Base32 中出现非法字符：' + ch);
      acc = (acc << 5) | v; bits += 5;
      if (bits >= 8) { bits -= 8; out.push((acc >> bits) & 0xff); }
    }
    return Uint8Array.from(out);
  }

  /* ================= 扩展：Z85（ZeroMQ） ================= */
  const Z85 = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#';
  function z85e(data) {
    if (data.length % 4 !== 0) throw new Error('Z85 要求输入长度为 4 的倍数');
    let out = '';
    for (let i = 0; i < data.length; i += 4) {
      let v = ((data[i] << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3]) >>> 0;
      const c = new Array(5);
      for (let j = 4; j >= 0; j--) { c[j] = Z85[v % 85]; v = Math.floor(v / 85); }
      out += c.join('');
    }
    return out;
  }
  function z85d(str) {
    const s = String(str);
    if (s.length % 5 !== 0) throw new Error('Z85 要求输入长度为 5 的倍数');
    const map = new Map();
    for (let i = 0; i < Z85.length; i++) map.set(Z85[i], i);
    const out = new Uint8Array(s.length / 5 * 4);
    let p = 0;
    for (let i = 0; i < s.length; i += 5) {
      let v = 0;
      for (let j = 0; j < 5; j++) {
        const d = map.get(s[i + j]);
        if (d === undefined) throw new Error('Z85 出现非法字符：' + s[i + j]);
        v = v * 85 + d;
      }
      out[p++] = (v >>> 24) & 0xff; out[p++] = (v >>> 16) & 0xff;
      out[p++] = (v >>> 8) & 0xff; out[p++] = v & 0xff;
    }
    return out;
  }

  /* ================= 扩展：BASE45（RFC 9285） ================= */
  const B45 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
  function b45e(data) {
    let out = '';
    for (let i = 0; i < data.length; i += 2) {
      if (i + 1 < data.length) {
        const v = data[i] * 256 + data[i + 1];
        out += B45[v % 45] + B45[Math.floor(v / 45) % 45] + B45[Math.floor(v / 2025)];
      } else {
        out += B45[data[i] % 45] + B45[Math.floor(data[i] / 45)];
      }
    }
    return out;
  }
  function b45d(str) {
    const s = String(str).toUpperCase();
    const map = new Map();
    for (let i = 0; i < B45.length; i++) map.set(B45[i], i);
    const vals = [];
    for (const ch of s) {
      const v = map.get(ch);
      if (v === undefined) throw new Error('BASE45 出现非法字符：' + ch);
      vals.push(v);
    }
    const out = [];
    let i = 0;
    while (i < vals.length) {
      const rem = vals.length - i;
      if (rem >= 3) {
        const v = vals[i] + vals[i + 1] * 45 + vals[i + 2] * 2025;
        if (v > 0xffff) throw new Error('BASE45 三元组溢出');
        out.push((v >> 8) & 0xff, v & 0xff);
        i += 3;
      } else if (rem === 2) {
        const v = vals[i] + vals[i + 1] * 45;
        if (v > 0xff) throw new Error('BASE45 二元组溢出');
        out.push(v);
        i += 2;
      } else throw new Error('BASE45 长度非法');
    }
    return Uint8Array.from(out);
  }

  /* ================= 扩展：BASE58CHECK ================= */
  function b58checke(data) {
    const chk = CT.hash.sha256(CT.hash.sha256(data)).subarray(0, 4);
    return b58e(U.concat(data, chk));
  }
  function b58checkd(str) {
    const raw = b58d(str);
    if (raw.length < 4) throw new Error('BASE58Check 数据过短');
    const body = raw.subarray(0, raw.length - 4);
    const chk = raw.subarray(raw.length - 4);
    const exp = CT.hash.sha256(CT.hash.sha256(body)).subarray(0, 4);
    if (!U.equal(chk, exp)) throw new Error('BASE58Check 校验和不匹配');
    return body;
  }

  /* ================= 统一入口 ================= */

  const MAP = {
    'BASE16':       { enc: d => b16e(d),                     dec: s => b16d(s),              text: true },
    'BASE32':       { enc: b32e,                             dec: s => b32d(s) },
    'BASE32HEX':    { enc: b32hexe,                          dec: s => b32hexd(s),           text: true },
    'CROCKFORD32':  { enc: crocke,                           dec: s => crockd(s),            text: true },
    'BASE36':       { enc: b36e,                             dec: s => b36d(s),              text: true },
    'BASE45':       { enc: b45e,                             dec: s => b45d(s),              text: true },
    'BASE58':       { enc: b58e,                             dec: s => b58d(s) },
    'BASE58CHECK':  { enc: b58checke,                        dec: s => b58checkd(s) },
    'BASE62':       { enc: b62e,                             dec: s => b62d(s),              text: true },
    'BASE64':       { enc: b64e,                             dec: s => b64d(s),              text: true },
    'BASE64URL':    { enc: b => b64ue(b, true),              dec: s => b64ud(s),             text: true },
    'BASE85':       { enc: b85e,                             dec: s => b85d(s),              text: true },
    'Z85':          { enc: z85e,                             dec: s => z85d(s),              text: true },
    'BASE91':       { enc: b91e,                             dec: s => b91d(s) }
  };

  const ORDER = ['BASE16', 'BASE32', 'BASE32HEX', 'CROCKFORD32', 'BASE36', 'BASE45', 'BASE58',
                 'BASE58CHECK', 'BASE62', 'BASE64', 'BASE64URL', 'BASE85', 'Z85', 'BASE91'];

  function encode(name, data) {
    const m = MAP[name];
    if (!m) throw new Error('不支持的 BASE：' + name);
    return m.enc(data);
  }
  function decode(name, text) {
    const m = MAP[name];
    if (!m) throw new Error('不支持的 BASE：' + name);
    return m.dec(text);
  }

  return {
    ALPHABET, MAP, ORDER, encode, decode,
    b16e, b16d, b32e, b32d, b36e, b36d, b58e, b58d, b58checke, b58checkd,
    b62e, b62d, b64e, b64d, b64ue, b64ud, b85e, b85d, b91e, b91d,
    b32hexe, b32hexd, crocke, crockd, z85e, z85d, b45e, b45d,
    _bi: { fromBytes: biFromBytes, toBytes: biToBytes }
  };
})();
