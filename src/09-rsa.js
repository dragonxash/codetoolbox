/* ===========================================================================
 * 编码工具箱 · 非对称层（RSA）
 *   CT.rsa ——
 *     密钥：PEM/DER 解析（PKCS#1 / PKCS#8 / SPKI）、由 p,q,e 造密钥、
 *           由 n,e,d 反推 p,q、密钥生成
 *     运算：原始 / PKCS#1 v1.5 / OAEP(SHA-1、SHA-256) 加解密
 *           签名与验签（PKCS#1 v1.5、PSS）
 *     攻击：小指数直接开方、共模攻击、Håstad 广播、Fermat 分解、
 *           Pollard rho、Pollard p−1、Wiener 攻击
 * =========================================================================== */

CT.rsa = (function () {
  const U = CT.util;
  const C = CT.cipher;
  const H = CT.hash;

  /* ---- 哈希名归一化：SHA256 / sha-256 / Sha256 都收敛到表里的 'SHA-256' ---- */
  const HASH_ALIAS = (() => {
    const m = {};
    for (const k of Object.keys(H.ALGOS)) m[k.toUpperCase().replace(/[^A-Z0-9/]/g, '')] = k;
    return m;
  })();
  function canonHash(name) {
    if (name === undefined || name === null || name === '') return 'SHA-256';
    if (H.ALGOS[name]) return String(name);
    const k = String(name).toUpperCase().replace(/[^A-Z0-9/]/g, '');
    return HASH_ALIAS[k] || String(name);
  }
  /** 取哈希算法描述对象（含 .fn 与 .out），名字写法不限 */
  function hashAlg(name) { return H.ALGOS[canonHash(name)]; }

  /* ======================= 基础数论 ======================= */
  function egcd(a, b) {
    let [old_r, r] = [a, b], [old_s, s] = [1n, 0n], [old_t, t] = [0n, 1n];
    while (r !== 0n) {
      const q = old_r / r;
      [old_r, r] = [r, old_r - q * r];
      [old_s, s] = [s, old_s - q * s];
      [old_t, t] = [t, old_t - q * t];
    }
    return { g: old_r, x: old_s, y: old_t };
  }
  function modinv(a, m) {
    const { g, x } = egcd(((a % m) + m) % m, m);
    if (g !== 1n) throw new Error('模逆不存在');
    return ((x % m) + m) % m;
  }
  function powmod(b, e, m) {
    if (m === 1n) return 0n;
    let r = 1n; b = ((b % m) + m) % m;
    while (e > 0n) {
      if (e & 1n) r = (r * b) % m;
      b = (b * b) % m;
      e >>= 1n;
    }
    return r;
  }
  /** 整数 k 次方根（向下取整） */
  function iroot(k, n) {
    if (n < 0n) throw new Error('负数无法开偶次根');
    if (n < 2n) return n;
    k = BigInt(k);
    if (k === 1n) return n;
    // 用位数给出可靠的初值，避免 Number 精度问题
    const bits = n.toString(2).length;
    let x = 1n << BigInt(Math.max(1, Math.ceil(bits / Number(k))));
    for (let i = 0; i < 500; i++) {
      const xk1 = x ** (k - 1n);
      if (xk1 === 0n) break;
      const nx = ((k - 1n) * x + n / xk1) / k;
      if (nx >= x) break;
      x = nx;
    }
    while (x ** k > n) x -= 1n;
    while ((x + 1n) ** k <= n) x += 1n;
    return x;
  }
  function isPrime(n, rounds) {
    if (n < 2n) return false;
    for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
      if (n === p) return true;
      if (n % p === 0n) return false;
    }
    let d = n - 1n, r = 0;
    while ((d & 1n) === 0n) { d >>= 1n; r++; }
    const roundsN = rounds || 24;
    witness: for (let i = 0; i < roundsN; i++) {
      const b = randBig(2n, n - 2n);
      let x = powmod(b, d, n);
      if (x === 1n || x === n - 1n) continue;
      for (let j = 0; j < r - 1; j++) {
        x = (x * x) % n;
        if (x === n - 1n) continue witness;
      }
      return false;
    }
    return true;
  }
  function randBig(lo, hi) {
    const bits = (hi - lo).toString(2).length + 8;
    const bytes = CT.misc.randBytes(Math.ceil(bits / 8));
    let v = 0n;
    for (const b of bytes) v = (v << 8n) | BigInt(b);
    return lo + (v % (hi - lo + 1n));
  }
  /**
   * 生成一个 bits 位素数。
   * topBits（默认 1）：把最高的几个二进制位置 1。
   * 生成 RSA 的两半时传 2，可保证两根都 ≥ 2^(bits−0.5)，
   * 从而 n = p·q 的位长严格等于 bits（否则会随机掉到 bits−1 位）。
   */
  function genPrime(bits, topBits) {
    topBits = topBits || 1;
    const nBytes = Math.ceil(bits / 8);
    const mask = (0xff << (8 - topBits)) & 0xff;
    for (;;) {
      const bytes = CT.misc.randBytes(nBytes);
      bytes[0] |= mask;
      bytes[bytes.length - 1] |= 1;
      let p = 0n;
      for (const b of bytes) p = (p << 8n) | BigInt(b);
      if (isPrime(p)) return p;
    }
  }
  function nextPrime(n) {
    if (n < 2n) return 2n;
    let x = n | 1n;
    if (x <= 2n) return 2n;
    while (!isPrime(x)) x += 2n;
    return x;
  }
  const gcd = (a, b) => { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) { [a, b] = [b, a % b]; } return a; };

  /* ======================= 整数字节 ↔ BigInt ======================= */
  function bytesToBig(b) {
    let v = 0n;
    for (const x of b) v = (v << 8n) | BigInt(x);
    return v;
  }
  function bigToBytes(v, len) {
    if (v < 0n) throw new Error('负数无法转为字节');
    let hex = v.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    let out = U.unhex(hex);
    if (len !== undefined) {
      if (out.length > len) throw new Error('数值超出目标长度');
      const pad = new Uint8Array(len);
      pad.set(out, len - out.length);
      out = pad;
    }
    return out;
  }

  /* ======================= 极简 DER 解析 ======================= */
  function derParse(bytes, off, end) {
    off = off || 0; end = end === undefined ? bytes.length : end;
    const out = [];
    while (off < end) {
      const tag = bytes[off++];
      if (off >= end) break;
      let len = bytes[off++];
      if (len & 0x80) {
        const n = len & 0x7f;
        if (n === 0 || n > 4) throw new Error('不支持的 DER 长度编码');
        len = 0;
        for (let i = 0; i < n; i++) len = (len << 8) | bytes[off++];
      }
      const start = off, stop = off + len;
      if (stop > end) throw new Error('DER 长度越界，数据可能被截断');
      const node = { tag, start, end: stop, raw: bytes.subarray(start, stop) };
      if (tag === 0x30 || tag === 0x31 || tag === 0xa0) node.children = derParse(bytes, start, stop);
      out.push(node);
      off = stop;
    }
    return out;
  }
  const derInt = node => bytesToBig(node.raw);
  const derOid = node => {
    const b = node.raw;
    const parts = [Math.floor(b[0] / 40), b[0] % 40];
    let v = 0;
    for (let i = 1; i < b.length; i++) {
      v = (v << 7) | (b[i] & 0x7f);
      if (!(b[i] & 0x80)) { parts.push(v); v = 0; }
    }
    return parts.join('.');
  };
  const OID = {
    '1.2.840.113549.1.1.1': 'rsaEncryption',
    '1.2.840.113549.1.1.5': 'sha1WithRSA',
    '1.2.840.113549.1.1.11': 'sha256WithRSA',
    '1.2.840.113549.1.1.12': 'sha384WithRSA',
    '1.2.840.113549.1.1.13': 'sha512WithRSA',
    '1.2.840.113549.1.1.10': 'RSASSA-PSS'
  };

  /* ======================= PEM ======================= */
  function pemToDer(pem) {
    const text = String(pem);
    // 可能有多个 PEM 块（如公钥 + 私钥同时粘贴）：优先取私钥块，否则取第一个
    const re = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
    const blocks = [];
    let m;
    while ((m = re.exec(text))) {
      blocks.push({ label: m[1], der: U.b64dec(m[2].replace(/[\s\r\n]/g, ''), false) });
    }
    if (!blocks.length) throw new Error('未找到合法的 PEM 块（缺少 -----BEGIN ...----- 头）');
    const priv = blocks.find(b => /PRIVATE/.test(b.label));
    return priv || blocks[0];
  }

  /**
   * 解析 PEM 或纯 Base64/DER，返回 { n, e, d?, p?, q?, dp?, dq?, qInv?, bits, kind }
   */
  function parseKey(input, format) {
    let der, label = '';
    if (typeof input === 'string' && /-----BEGIN/.test(input)) {
      const r = pemToDer(input);
      der = r.der; label = r.label;
    } else if (format === 'hex') {
      der = U.unhex(String(input).replace(/\s/g, ''));
    } else if (typeof input === 'string') {
      der = U.b64dec(String(input).replace(/\s/g, ''), false);
    } else der = U.asBytes(input);

    const top = derParse(der);
    if (!top.length || top[0].tag !== 0x30) throw new Error('DER 顶层不是 SEQUENCE');
    const seq = top[0].children;

    // PKCS#8 PrivateKeyInfo：SEQUENCE { INTEGER 0, SEQ{alg}, OCTET STRING }
    if (seq.length === 3 && seq[0].tag === 0x02 && seq[1].tag === 0x30 && seq[2].tag === 0x04) {
      const oid = derOid(seq[1].children[0]);
      if (OID[oid] !== 'rsaEncryption' && oid !== '1.2.840.113549.1.1.1') {
        throw new Error('PKCS#8 中的算法不是 RSA（' + oid + '）');
      }
      const inner = parseKey(seq[2].raw);
      return Object.assign(inner, { kind: 'pkcs8', label: label || 'PRIVATE KEY' });
    }
    // SPKI：SEQUENCE { SEQ{alg}, BIT STRING }
    if (seq.length === 2 && seq[0].tag === 0x30 && seq[1].tag === 0x03) {
      const bs = seq[1].raw.subarray(1);         // 去掉未用位数
      const inner = derParse(bs)[0];
      const nums = inner.children.map(derInt);
      return { n: nums[0], e: nums[1], bits: nums[0].toString(2).length, kind: 'spki', label: label || 'PUBLIC KEY' };
    }
    // PKCS#1 私钥：9 个 INTEGER
    if (seq.length >= 9 && seq.every(x => x.tag === 0x02)) {
      const v = seq.map(derInt);
      // 私钥里已有 p、q，顺手把 φ(n) 与 λ(n)=lcm(p−1,q−1) 导出来，
      // 后面做 CRT / 攻击 / 校验时不必再算
      let phi, lam;
      try {
        phi = (v[4] - 1n) * (v[5] - 1n);
        lam = phi / gcd(v[4] - 1n, v[5] - 1n);
      } catch (e) { phi = undefined; lam = undefined; }
      return {
        version: v[0], n: v[1], e: v[2], d: v[3], p: v[4], q: v[5],
        dp: v[6], dq: v[7], qInv: v[8],
        phi, lambda: lam,
        bits: v[1].toString(2).length, kind: 'pkcs1-private', label: label || 'RSA PRIVATE KEY'
      };
    }
    // PKCS#1 公钥：2 个 INTEGER
    if (seq.length === 2 && seq.every(x => x.tag === 0x02)) {
      const v = seq.map(derInt);
      return { n: v[0], e: v[1], bits: v[0].toString(2).length, kind: 'pkcs1-public', label: label || 'RSA PUBLIC KEY' };
    }
    throw new Error('无法识别的 RSA 密钥结构（组件数 ' + seq.length + '）');
  }

  /* ======================= 编码成 PEM ======================= */
  function derLen(n) {
    if (n < 0x80) return Uint8Array.of(n);
    const bytes = [];
    let v = n;
    while (v > 0) { bytes.unshift(v & 0xff); v >>= 8; }
    return Uint8Array.of(0x80 | bytes.length, ...bytes);
  }
  function derTag(tag, content) {
    return U.concat(Uint8Array.of(tag), derLen(content.length), content);
  }
  function derIntEnc(v) {
    let hex = v.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    let b = U.unhex(hex);
    if (b[0] & 0x80) b = U.concat(Uint8Array.of(0), b);
    return derTag(0x02, b);
  }
  const derSeq = parts => derTag(0x30, U.concat.apply(null, parts));
  function derB64Wrap(label, content) {
    const b64 = U.b64enc(content, false, true);
    const lines = [];
    for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
    return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
  }
  function exportPkcs1Private(k) {
    return derB64Wrap('RSA PRIVATE KEY', derSeq([0, 1, 2, 3, 4, 5, 6, 7, 8].map(i =>
      derIntEnc([0n, k.n, k.e, k.d, k.p, k.q, k.dp, k.dq, k.qInv][i]))));
  }
  function exportPkcs1Public(k) {
    return derB64Wrap('RSA PUBLIC KEY', derSeq([derIntEnc(k.n), derIntEnc(k.e)]));
  }
  function exportSpki(k) {
    const alg = derSeq([derTag(0x06, U.unhex('2a864886f70d010101')), derTag(0x05, new Uint8Array(0))]);
    const pkcs1 = derSeq([derIntEnc(k.n), derIntEnc(k.e)]);
    const bits = U.concat(Uint8Array.of(0), pkcs1);
    return derB64Wrap('PUBLIC KEY', derSeq([alg, derTag(0x03, bits)]));
  }
  function exportPkcs8(k) {
    const alg = derSeq([derTag(0x06, U.unhex('2a864886f70d010101')), derTag(0x05, new Uint8Array(0))]);
    const pkcs1 = derSeq([0n, k.n, k.e, k.d, k.p, k.q, k.dp, k.dq, k.qInv].map(derIntEnc));
    return derB64Wrap('PRIVATE KEY', derSeq([derIntEnc(0n), alg, derTag(0x04, pkcs1)]));
  }

  /* ======================= 由 p,q,e 造密钥 ======================= */
  function keyFromPQE(p, q, e) {
    p = BigInt(p); q = BigInt(q); e = BigInt(e);
    const n = p * q;
    const phi = (p - 1n) * (q - 1n);
    const lam = phi / gcd(p - 1n, q - 1n);
    let d;
    try { d = modinv(e, phi); } catch (err) { d = modinv(e, lam); }
    const dp = d % (p - 1n), dq = d % (q - 1n);
    const qInv = modinv(q, p);
    return { n, e, d, p, q, dp, dq, qInv, phi, lambda: lam, bits: n.toString(2).length, kind: 'constructed' };
  }
  function keyFromNED(n, e, d) {
    n = BigInt(n); e = BigInt(e); d = BigInt(d);
    const k = e * d - 1n;
    if (k === 0n) throw new Error('e·d ≡ 1 不成立');
    let t = k, s = 0n;
    while ((t & 1n) === 0n) { t >>= 1n; s++; }
    for (let attempt = 0; attempt < 200; attempt++) {
      const g = randBig(2n, n - 1n);
      let x = powmod(g, t, n);
      if (x === 1n || x === n - 1n) continue;
      for (let i = 0n; i < s; i++) {
        const y = (x * x) % n;
        if (y === 1n) {
          const p = gcd(x - 1n, n);
          if (p > 1n && p < n) return keyFromPQE(p, n / p, e);
          break;
        }
        if (y === n - 1n) break;
        x = y;
      }
    }
    throw new Error('未能由 (n, e, d) 分解出 p、q，请重试');
  }
  function generate(bits, e) {
    bits = bits || 2048; e = BigInt(e || 65537);
    const half = bits >> 1;
    for (;;) {
      const p = genPrime(half, 2), q = genPrime(bits - half, 2);
      if (p === q) continue;
      if (gcd(e, (p - 1n) * (q - 1n)) !== 1n) continue;
      return keyFromPQE(p, q, e);
    }
  }

  /* ======================= 字节 ↔ 整数（定长） ======================= */
  const kLen = n => Math.ceil(n.toString(2).length / 8);

  function os2ip(b) { return bytesToBig(b); }
  const i2osp = (v, len) => bigToBytes(v, len);

  /* ======================= 填充 ======================= */
  function mgf1(seed, len, hashName) {
    hashName = canonHash(hashName);
    const a = hashAlg(hashName);
    if (!a) throw new Error('MGF1 不支持哈希：' + hashName);
    const count = Math.ceil(len / a.out);
    const out = new Uint8Array(count * a.out);
    for (let i = 0; i < count; i++) out.set(a.fn(U.concat(seed, U.packU32BE(i))), i * a.out);
    return out.slice(0, len);
  }

  function padPkcs1v15(msg, k) {
    if (msg.length > k - 11) throw new Error(`明文过长：最多 ${k - 11} 字节，当前 ${msg.length}`);
    const ps = new Uint8Array(k - msg.length - 3);
    const r = CT.misc.randBytes(ps.length);
    for (let i = 0; i < ps.length; i++) ps[i] = r[i] === 0 ? 1 : r[i];
    return U.concat(Uint8Array.of(0, 2), ps, Uint8Array.of(0), msg);
  }
  function unpadPkcs1v15(em) {
    if (em[0] !== 0 || em[1] !== 2) throw new Error('PKCS#1 v1.5 填充头错误（应为 00 02）');
    const idx = em.indexOf(0, 2);
    if (idx < 0) throw new Error('PKCS#1 v1.5 填充缺少分隔符');
    if (idx < 10) throw new Error('PKCS#1 v1.5 填充块过短');
    return em.slice(idx + 1);
  }

  function oaepEncode(msg, k, hashName, label) {
    hashName = canonHash(hashName);
    const a = hashAlg(hashName);
    if (!a) throw new Error('OAEP 不支持哈希：' + hashName);
    const hLen = a.out;
    if (msg.length > k - 2 * hLen - 2) throw new Error(`明文过长：最多 ${k - 2 * hLen - 2} 字节，当前 ${msg.length}`);
    const lHash = a.fn(U.asBytes(label || new Uint8Array(0)));
    const ps = new Uint8Array(k - msg.length - 2 * hLen - 2);
    const db = U.concat(lHash, ps, Uint8Array.of(1), msg);
    const seed = CT.misc.randBytes(hLen);
    const dbMask = mgf1(seed, k - hLen - 1, hashName);
    const maskedDB = db.map((x, i) => x ^ dbMask[i]);
    const seedMask = mgf1(maskedDB, hLen, hashName);
    const maskedSeed = seed.map((x, i) => x ^ seedMask[i]);
    return U.concat(Uint8Array.of(0), maskedSeed, maskedDB);
  }
  function oaepDecode(em, k, hashName, label) {
    hashName = canonHash(hashName);
    const a = hashAlg(hashName);
    const hLen = a.out;
    if (em[0] !== 0) throw new Error('OAEP 首字节应为 0x00');
    const maskedSeed = em.slice(1, 1 + hLen);
    const maskedDB = em.slice(1 + hLen);
    const seedMask = mgf1(maskedDB, hLen, hashName);
    const seed = maskedSeed.map((x, i) => x ^ seedMask[i]);
    const dbMask = mgf1(seed, k - hLen - 1, hashName);
    const db = maskedDB.map((x, i) => x ^ dbMask[i]);
    const lHash = a.fn(U.asBytes(label || new Uint8Array(0)));
    for (let i = 0; i < hLen; i++) {
      if (db[i] !== lHash[i]) throw new Error('OAEP 校验失败：lHash 不匹配');
    }
    let idx = -1;
    for (let i = hLen; i < db.length; i++) {
      if (db[i] === 1) { idx = i; break; }
      if (db[i] !== 0) throw new Error('OAEP 校验失败：PS 段含非零字节');
    }
    if (idx < 0) throw new Error('OAEP 校验失败：未找到 0x01 分隔符');
    return db.slice(idx + 1);
  }

  /* ======================= 加解密 ======================= */
  function encrypt(params) {
    const { key, data } = params;
    const padding = (params.padding || 'PKCS1v15');
    const hashName = canonHash(params.hash);
    const msg = U.asBytes(data);
    const k = kLen(key.n);
    let em;
    if (padding === 'Raw' || padding === 'None') {
      if (msg.length > k) throw new Error('明文长度超过模长');
      em = i2osp(os2ip(msg), k);
      return i2osp(powmod(os2ip(em), key.e, key.n), k);
    }
    if (padding === 'PKCS1v15') em = padPkcs1v15(msg, k);
    else if (padding === 'OAEP') em = oaepEncode(msg, k, hashName, params.label);
    else throw new Error('不支持的 RSA 填充：' + padding);
    return i2osp(powmod(os2ip(em), key.e, key.n), k);
  }
  function decrypt(params) {
    const { key, data } = params;
    const padding = (params.padding || 'PKCS1v15');
    const hashName = canonHash(params.hash);
    const k = kLen(key.n);
    const c = os2ip(U.asBytes(data));
    let m;
    if (key.d !== undefined && key.p !== undefined && key.q !== undefined) {
      // 带 CRT 加速
      const m1 = powmod(c, key.dp !== undefined ? key.dp : key.d % (key.p - 1n), key.p);
      const m2 = powmod(c, key.dq !== undefined ? key.dq : key.d % (key.q - 1n), key.q);
      const qInv = key.qInv !== undefined ? key.qInv : modinv(key.q, key.p);
      const h = (((m1 - m2) % key.p + key.p) % key.p) * qInv % key.p;
      m = m2 + h * key.q;
    } else if (key.d !== undefined) {
      m = powmod(c, key.d, key.n);
    } else throw new Error('解密需要私钥（缺少 d）');
    const em = i2osp(m, k);
    if (padding === 'Raw' || padding === 'None') {
      // 去掉前导 0
      let i = 0;
      while (i < k - 1 && em[i] === 0) i++;
      return em.slice(i);
    }
    if (padding === 'PKCS1v15') return unpadPkcs1v15(em);
    if (padding === 'OAEP') return oaepDecode(em, k, hashName, params.label);
    throw new Error('不支持的 RSA 填充：' + padding);
  }

  /* ======================= 签名 / 验签 ======================= */
  /* 摘要算法的 ASN.1 Object Identifier（RFC 8017 附录 B / RFC 5754）
   * 注意 SHA-2 家族的尾号：SHA-224=.4  SHA-256=.1  SHA-384=.2  SHA-512=.3
   * （不是按 224→1、256→2 的顺序排的，早先这里曾整体错位一格） */
  const DIGEST_OID = {
    'MD2': '2a864886f70d0202',
    'MD4': '2a864886f70d0204',
    'MD5': '2a864886f70d0205',
    'SHA-1': '2b0e03021a',
    'SHA-224': '608648016503040204',
    'SHA-256': '608648016503040201',
    'SHA-384': '608648016503040202',
    'SHA-512': '608648016503040203',
    'SHA-512/224': '608648016503040205',
    'SHA-512/256': '608648016503040206',
    'SHA3-224': '608648016503040207',
    'SHA3-256': '608648016503040208',
    'SHA3-384': '608648016503040209',
    'SHA3-512': '60864801650304020a',
    'RIPEMD-160': '2b24030201'
  };
  function digestInfo(hashName, digest) {
    const oid = DIGEST_OID[hashName];
    if (!oid) throw new Error('签名暂不支持该摘要算法的 OID：' + hashName);
    const alg = derSeq([derTag(0x06, U.unhex(oid)), derTag(0x05, new Uint8Array(0))]);
    return derSeq([alg, derTag(0x04, digest)]);
  }
  function sign(params) {
    const { key, data } = params;
    const hashName = canonHash(params.hash);
    const a = hashAlg(hashName);
    if (!a) throw new Error('不支持的哈希：' + hashName);
    const digest = a.fn(U.asBytes(data));
    if (!key.d) throw new Error('签名需要私钥');
    if ((params.padding || 'PKCS1v15') === 'PSS') return pssEncode(key, digest, hashName, 'sign');
    const t = digestInfo(hashName, digest);
    const k = kLen(key.n);
    if (t.length > k - 11) throw new Error('密钥太短，无法承载该哈希的 DigestInfo');
    const em = U.concat(
      Uint8Array.of(0, 1),
      new Uint8Array(k - t.length - 3).fill(0xff),
      Uint8Array.of(0), t
    );
    return i2osp(powmod(os2ip(em), key.d, key.n), k);
  }
  function verify(params) {
    const { key, data, signature } = params;
    const hashName = canonHash(params.hash);
    const a = hashAlg(hashName);
    const digest = a.fn(U.asBytes(data));
    const k = kLen(key.n);
    const m = powmod(os2ip(U.asBytes(signature)), key.e, key.n);
    let em;
    try { em = i2osp(m, k); } catch (e) { return false; }
    if ((params.padding || 'PKCS1v15') === 'PSS') return pssVerify(key, digest, hashName, em);
    const t = digestInfo(hashName, digest);
    if (em[0] !== 0 || em[1] !== 1) return false;
    const idx = em.indexOf(0, 2);
    if (idx < 0) return false;
    for (let i = 2; i < idx; i++) if (em[i] !== 0xff) return false;
    return U.hex(em.slice(idx + 1)) === U.hex(t);
  }

  /* ---- PSS（RFC 8017 §9.1） ---- */
  function pssEncode(key, digest, hashName, mode) {
    hashName = canonHash(hashName);
    const a = hashAlg(hashName);
    const hLen = a.out, sLen = hLen;
    const k = kLen(key.n);
    if (k < hLen + sLen + 2) throw new Error('密钥太短，无法进行 PSS');
    const salt = mode === 'sign' ? CT.misc.randBytes(sLen) : null;
    const mPrime = U.concat(new Uint8Array(8), digest, salt);
    const hv = a.fn(mPrime);
    const ps = new Uint8Array(k - sLen - hLen - 2);
    const db = U.concat(ps, Uint8Array.of(1), salt);
    const dbMask = mgf1(hv, k - hLen - 1, hashName);
    const maskedDB = db.map((x, i) => x ^ dbMask[i]);
    maskedDB[0] &= 0x7f;
    const em = U.concat(maskedDB, hv, Uint8Array.of(0xbc));
    return mode === 'sign' ? i2osp(powmod(os2ip(em), key.d, key.n), k) : em;
  }
  function pssVerify(key, digest, hashName, em) {
    hashName = canonHash(hashName);
    const a = hashAlg(hashName);
    const hLen = a.out, sLen = hLen;
    const k = kLen(key.n);
    if (em[em.length - 1] !== 0xbc) return false;
    const maskedDB = em.slice(0, k - hLen - 1);
    const hv = em.slice(k - hLen - 1, k - 1);
    if (maskedDB[0] & 0x80) return false;
    const dbMask = mgf1(hv, k - hLen - 1, hashName);
    const db = maskedDB.map((x, i) => x ^ dbMask[i]);
    db[0] &= 0x7f;
    const idx = db.indexOf(1, k - hLen - 1 - sLen - 1);
    if (idx < 0) return false;
    for (let i = 0; i < idx; i++) if (db[i] !== 0) return false;
    const salt = db.slice(idx + 1);
    const hv2 = a.fn(U.concat(new Uint8Array(8), digest, salt));
    return U.hex(hv) === U.hex(hv2);
  }

  /* ======================= 攻击套件 ======================= */

  /** e 很小且 m^e < n：直接开 e 次方 */
  function smallExponentRoot(c, e, n) {
    c = BigInt(c); e = BigInt(e);
    const r = iroot(e, c);
    if (r ** e === c) return { m: r, ok: true, note: 'm^e < n，直接开方成功' };
    if (n !== undefined && powmod(r, e, n) === c % BigInt(n)) return { m: r, ok: true, note: '开方后取模一致' };
    return { m: r, ok: false, note: '不是完全 e 次方，需用广播/共模等方法' };
  }

  /** 共模攻击：同一 n，不同 e1/e2 且互素 */
  function commonModulus(n, e1, c1, e2, c2) {
    n = BigInt(n); e1 = BigInt(e1); e2 = BigInt(e2);
    const { g, x, y } = egcd(e1, e2);
    if (g !== 1n) throw new Error('e1 与 e2 不互素，共模攻击不适用');
    let m;
    if (x < 0n) m = powmod(modinv(BigInt(c1), n), -x, n);
    else m = powmod(BigInt(c1), x, n);
    let t;
    if (y < 0n) t = powmod(modinv(BigInt(c2), n), -y, n);
    else t = powmod(BigInt(c2), y, n);
    m = (m * t) % n;
    return m;
  }

  /** Håstad 广播攻击：同一明文、同一小 e、不同 n */
  function hastadBroadcast(pairs, e) {
    e = BigInt(e);
    const ns = pairs.map(p => BigInt(p.n));
    const r = crt(pairs.map(p => BigInt(p.c)), ns);
    const root = iroot(e, r);
    if (root ** e !== r) throw new Error('CRT 结果不是完全 e 次方，广播攻击失败');
    return root;
  }

  /** 中国剩余定理 */
  function crt(remainders, moduli) {
    let M = 1n;
    for (const m of moduli) M *= m;
    let x = 0n;
    for (let i = 0; i < moduli.length; i++) {
      const Mi = M / moduli[i];
      x = (x + remainders[i] * Mi % M * modinv(Mi % moduli[i], moduli[i])) % M;
    }
    return ((x % M) + M) % M;
  }

  /** Fermat 分解：p、q 很接近时极快 */
  function fermatFactor(n, maxIter) {
    n = BigInt(n);
    if (n % 2n === 0n) return { p: 2n, q: n / 2n };
    maxIter = maxIter || 1e6;
    let a = iroot(2, n);
    if (a * a < n) a += 1n;
    for (let i = 0; i < maxIter; i++) {
      const b2 = a * a - n;
      if (b2 >= 0n) {
        const b = iroot(2, b2);
        if (b * b === b2) return { p: a - b, q: a + b, iterations: i };
      }
      a += 1n;
    }
    throw new Error(`Fermat 分解在 ${maxIter} 次迭代内未成功`);
  }

  /** Pollard rho（Brent 改进） */
  function pollardRho(n, maxIter) {
    n = BigInt(n);
    if (n % 2n === 0n) return 2n;
    if (isPrime(n)) return n;
    maxIter = maxIter || 5e6;
    for (let c = 1n; c < 64n; c++) {
      let x = 2n, y = 2n, d = 1n, steps = 0;
      const f = v => (v * v + c) % n;
      while (d === 1n) {
        x = f(x); y = f(f(y));
        d = gcd(x - y, n);
        if (++steps > maxIter) break;
      }
      if (d > 1n && d < n) return d;
    }
    throw new Error('Pollard rho 未能在限定步数内分解');
  }

  /** Pollard p−1：p−1 光滑时有效 */
  function pollardP1(n, bound) {
    n = BigInt(n);
    bound = bound || 100000;
    let a = 2n;
    for (let i = 2; i <= bound; i++) {
      a = powmod(a, BigInt(i), n);
      const d = gcd(a - 1n, n);
      if (d > 1n && d < n) return d;
      if (d === n) break;
    }
    throw new Error('Pollard p−1 未找到因子（可提高上界或换 B 值）');
  }

  /** Wiener 攻击：d 很小时由 e/n 的连分数还原 d */
  function wienerAttack(e, n) {
    e = BigInt(e); n = BigInt(n);
    let num = e, den = n;
    const cf = [];
    while (den) { cf.push(num / den); [num, den] = [den, num % den]; }
    const conv = [];
    // 收敛分数 h/k ≈ e/n。注意对应关系是 e/n ≈ k_RSA/d，
    // 所以分子 h 是 RSA 里的 k，分母 k 才是私钥 d —— 别弄反。
    let hPrev = 0n, h = 1n, kPrev = 1n, k = 0n;
    for (const a of cf) {
      const kNext = a * k + kPrev, hNext = a * h + hPrev;
      kPrev = k; k = kNext; hPrev = h; h = hNext;
      if (h === 0n || k === 0n) continue;          // 0/1 这个收敛项无意义
      if ((e * k - 1n) % h !== 0n) continue;      // 要求 h | (e·d − 1)
      const phi = (e * k - 1n) / h;
      const s = n - phi + 1n;                     // p + q
      const disc = s * s - 4n * n;                // (p − q)^2
      if (disc < 0n) continue;
      const r = iroot(2, disc);
      if (r * r !== disc) continue;
      if ((s + r) % 2n !== 0n) continue;
      const p = (s + r) / 2n, q = (s - r) / 2n;
      if (p * q === n) return { d: k, k: h, p, q, phi };
      conv.push({ d: k, k: h });
    }
    throw new Error('Wiener 攻击失败：d 可能不够小');
  }

  /** 由 d 与 e 分解 n（等价 keyFromNED 的分解部分） */
  function factorFromDE(n, e, d) {
    n = BigInt(n); e = BigInt(e); d = BigInt(d);
    const k = e * d - 1n;
    let t = k, s = 0n;
    while ((t & 1n) === 0n) { t >>= 1n; s++; }
    for (let i = 0; i < 500; i++) {
      const g = randBig(2n, n - 1n);
      let x = powmod(g, t, n);
      if (x === 1n || x === n - 1n) continue;
      for (let j = 0n; j < s; j++) {
        const y = (x * x) % n;
        if (y === 1n) {
          const p = gcd(x - 1n, n);
          if (p > 1n && p < n) return { p, q: n / p };
          break;
        }
        if (y === n - 1n) break;
        x = y;
      }
    }
    throw new Error('由 (n, e, d) 分解失败，请重试');
  }

  /** 已知 p、q，直接解出明文（等价于还原私钥后解密） */
  function decryptWithFactors(n, e, c, p, q) {
    const k = keyFromPQE(p, q, e);
    if (k.n !== BigInt(n)) throw new Error('p × q 不等于 n，参数有误');
    return powmod(BigInt(c), k.d, k.n);
  }

  /** 自动尝试一系列分解方法 */
  function autoFactor(n, options) {
    n = BigInt(n);
    const opt = options || {};
    const tried = [];
    const attempt = (name, fn) => {
      try {
        const r = fn();
        if (!r || !r.p || !r.q) { tried.push(name + ' 无结果'); return null; }
        if (r.p > 1n && r.q > 1n && r.p * r.q === n) { tried.push(name + ' 成功'); return r; }
        tried.push(name + ' 结果无效');
        return null;
      } catch (e) { tried.push(name + ' 失败'); return null; }
    };
    if (n % 2n === 0n) return { p: 2n, q: n / 2n, method: '偶数直接除 2', tried };
    let r = attempt('Fermat 分解', () => fermatFactor(n, opt.fermatIter || 200000));
    if (r) return Object.assign(r, { method: 'Fermat 分解（p、q 接近）', tried });
    r = attempt('Pollard p−1', () => { const d = pollardP1(n, opt.pm1Bound || 20000); return { p: d, q: n / d }; });
    if (r) return Object.assign(r, { method: 'Pollard p−1', tried });
    r = attempt('Pollard rho', () => { const d = pollardRho(n, opt.rhoIter || 2000000); return { p: d, q: n / d }; });
    if (r) return Object.assign(r, { method: 'Pollard rho', tried });
    throw new Error('自动分解全部失败（' + tried.join('；') + '）');
  }

  /* ======================= 统一入口 ======================= */
  return {
    // 数论
    egcd, modinv, powmod, iroot, isPrime, genPrime, nextPrime, gcd, randBig,
    bytesToBig, bigToBytes,
    // DER / PEM
    derParse, derInt, derOid, OID, pemToDer, parseKey,
    exportPkcs1Private, exportPkcs1Public, exportSpki, exportPkcs8,
    // 密钥
    keyFromPQE, keyFromNED, generate,
    // 加解密
    encrypt, decrypt, padPkcs1v15, unpadPkcs1v15, oaepEncode, oaepDecode, mgf1,
    // 签名
    sign, verify, digestInfo,
    // 攻击
    smallExponentRoot, commonModulus, hastadBroadcast, crt,
    fermatFactor, pollardRho, pollardP1, wienerAttack, factorFromDE,
    decryptWithFactors, autoFactor,
    kLen
  };
})();
