/* 与佛论禅 (keyfc tudoucode) 核心算法 —— 纯 JS，无依赖
 * V1 佛曰：    UTF-16LE -> AES-256-CBC -> 128 字表（>=0x80 加随机关键字）
 * V2 如是我闻：UTF-8 -> 7z(LZMA1) -> AES-256-CBC -> 256 字表
 */
(function (root, factory) {
  const mod = factory();
  if (typeof module === 'object' && module.exports) module.exports = mod;
  else root.Buddha = mod;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* ============================ AES-256 ============================ */
  function buildTables() {
    // GF(2^8) 乘法逆元 + 仿射变换生成 S 盒，避免手抄出错
    const exp = new Uint8Array(512), log = new Uint8Array(256);
    let x = 1;
    for (let i = 0; i < 255; i++) { exp[i] = x; log[x] = i; x ^= (x << 1) ^ ((x & 0x80) ? 0x1b : 0); x &= 0xff; }
    for (let i = 255; i < 512; i++) exp[i] = exp[i - 255];
    const inv = new Uint8Array(256); // inv[0]=0
    for (let i = 1; i < 256; i++) inv[i] = exp[255 - log[i]];
    const SBOX = new Uint8Array(256), INV = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      const b = inv[i];
      let s = b ^ rotl8(b, 1) ^ rotl8(b, 2) ^ rotl8(b, 3) ^ rotl8(b, 4) ^ 0x63;
      s &= 0xff;
      SBOX[i] = s; INV[s] = i;
    }
    const M = [];
    for (let n = 0; n < 15; n++) M[n] = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      M[2][i] = mul(i, 2); M[3][i] = mul(i, 3);
      M[9][i] = mul(i, 9); M[11][i] = mul(i, 11); M[13][i] = mul(i, 13); M[14][i] = mul(i, 14);
    }
    function mul(a, b) { return (a && b) ? exp[log[a] + log[b]] : 0; }
    function rotl8(v, n) { return ((v << n) | (v >> (8 - n))) & 0xff; }
    return { SBOX, INV, M };
  }
  const T = buildTables();
  const SBOX = T.SBOX, INV_SBOX = T.INV, M = T.M;

  function subWord(w) {
    return ((SBOX[(w >>> 24) & 0xff] << 24) | (SBOX[(w >>> 16) & 0xff] << 16) |
      (SBOX[(w >>> 8) & 0xff] << 8) | SBOX[w & 0xff]) >>> 0;
  }

  function AES256(key) {
    const Nk = 8, Nr = 14;
    const w = new Array(4 * (Nr + 1));
    for (let i = 0; i < Nk; i++) w[i] = ((key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3]) >>> 0;
    let rcon = 1;
    for (let i = Nk; i < w.length; i++) {
      let t = w[i - 1];
      if (i % Nk === 0) {
        t = ((t << 8) | (t >>> 24)) >>> 0;
        t = (subWord(t) ^ (rcon << 24)) >>> 0;
        rcon = ((rcon << 1) ^ ((rcon & 0x80) ? 0x1b : 0)) & 0xff;
      } else if (i % Nk === 4) t = subWord(t);
      w[i] = (w[i - Nk] ^ t) >>> 0;
    }
    this.Nr = Nr;
    this.rk = new Uint8Array(16 * (Nr + 1));
    let k = 0;
    for (let r = 0; r <= Nr; r++)
      for (let c = 0; c < 4; c++) {
        const v = w[r * 4 + c];
        this.rk[k++] = (v >>> 24) & 0xff; this.rk[k++] = (v >>> 16) & 0xff;
        this.rk[k++] = (v >>> 8) & 0xff; this.rk[k++] = v & 0xff;
      }
  }
  AES256.prototype.encryptBlock = function (inp, o, out, oo) {
    const rk = this.rk, Nr = this.Nr, s = new Uint8Array(16);
    for (let i = 0; i < 16; i++) s[i] = inp[o + i] ^ rk[i];
    for (let round = 1; round <= Nr; round++) {
      for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]];
      const t = new Uint8Array(16);
      for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) t[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
      if (round !== Nr) {
        for (let c = 0; c < 4; c++) {
          const a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
          t[4 * c] = M[2][a0] ^ M[3][a1] ^ a2 ^ a3;
          t[4 * c + 1] = a0 ^ M[2][a1] ^ M[3][a2] ^ a3;
          t[4 * c + 2] = a0 ^ a1 ^ M[2][a2] ^ M[3][a3];
          t[4 * c + 3] = M[3][a0] ^ a1 ^ a2 ^ M[2][a3];
        }
      }
      for (let i = 0; i < 16; i++) s[i] = t[i] ^ rk[round * 16 + i];
    }
    for (let i = 0; i < 16; i++) out[oo + i] = s[i];
  };
  AES256.prototype.decryptBlock = function (inp, o, out, oo) {
    const rk = this.rk, Nr = this.Nr, s = new Uint8Array(16);
    for (let i = 0; i < 16; i++) s[i] = inp[o + i] ^ rk[Nr * 16 + i];
    for (let round = Nr - 1; round >= 0; round--) {
      const t = new Uint8Array(16);
      for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) t[r + 4 * c] = s[r + 4 * ((c - r + 4) % 4)];
      for (let i = 0; i < 16; i++) t[i] = INV_SBOX[t[i]];
      for (let i = 0; i < 16; i++) t[i] ^= rk[round * 16 + i];
      if (round !== 0) {
        for (let c = 0; c < 4; c++) {
          const a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
          t[4 * c] = M[14][a0] ^ M[11][a1] ^ M[13][a2] ^ M[9][a3];
          t[4 * c + 1] = M[9][a0] ^ M[14][a1] ^ M[11][a2] ^ M[13][a3];
          t[4 * c + 2] = M[13][a0] ^ M[9][a1] ^ M[14][a2] ^ M[11][a3];
          t[4 * c + 3] = M[11][a0] ^ M[13][a1] ^ M[9][a2] ^ M[14][a3];
        }
      }
      for (let i = 0; i < 16; i++) s[i] = t[i];
    }
    for (let i = 0; i < 16; i++) out[oo + i] = s[i];
  };

  function cbcEncrypt(data, key, iv) {
    const aes = new AES256(key);
    const pad = 16 - (data.length % 16);
    const n = data.length + pad;
    const src = new Uint8Array(n);
    src.set(data);
    for (let i = data.length; i < n; i++) src[i] = pad;
    const out = new Uint8Array(n);
    const block = new Uint8Array(16);
    let prev = new Uint8Array(iv);
    for (let i = 0; i < n; i += 16) {
      for (let j = 0; j < 16; j++) block[j] = src[i + j] ^ prev[j];
      aes.encryptBlock(block, 0, out, i);
      prev = out.subarray(i, i + 16);
    }
    return out;
  }
  function cbcDecrypt(data, key, iv) {
    const aes = new AES256(key);
    const n = data.length - (data.length % 16);
    const out = new Uint8Array(n);
    const block = new Uint8Array(16);
    let prev = new Uint8Array(iv);
    for (let i = 0; i < n; i += 16) {
      block.set(data.subarray(i, i + 16));
      aes.decryptBlock(block, 0, out, i);
      for (let j = 0; j < 16; j++) out[i + j] ^= prev[j];
      prev = new Uint8Array(block);
    }
    const pad = out[n - 1];
    if (pad > 0 && pad <= 16) {
      let ok = true;
      for (let i = n - pad; i < n; i++) if (out[i] !== pad) { ok = false; break; }
      if (ok) return out.subarray(0, n - pad);
    }
    return out;
  }

  /* ============================ CRC32 ============================ */
  const CRC_T = (function () {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c >>> 0;
    }
    return t;
  })();
  function crc32(buf) {
    let c = 0xFFFFFFFF;
    for (let i = 0; i < buf.length; i++) c = CRC_T[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
    return (c ^ 0xFFFFFFFF) >>> 0;
  }

  /* ============================ 7z 编码工具 ============================ */
  function wnum(out, value) {
    // 7z 变长数字
    let v = value;
    if (v < 0x80) { out.push(v); return; }
    let len = 0, tmp = v;
    while (tmp >= 0x100) { tmp >>>= 8; len++; }   // len = 后续字节数-1 的计数起点
    // 简化实现：逐字节倒序
    const bytes = [];
    let t = v;
    while (t > 0) { bytes.push(t & 0xff); t = Math.floor(t / 256); }
    const n = bytes.length;               // 总字节数(含首字节)
    let first = 0;
    for (let i = 0; i < n - 1; i++) first |= (0x80 >> i);
    first |= bytes[n - 1];
    out.push(first);
    for (let i = n - 2; i >= 0; i--) out.push(bytes[i]);
  }
  function rnum(b, p) {
    let first = b[p++], mask = 0x80, value = 0;
    for (let i = 0; i < 8; i++) {
      if (!(first & mask)) { value += (first & (mask - 1)) * Math.pow(2, 8 * i); return [value, p]; }
      value += b[p] * Math.pow(2, 8 * i); p++;
      mask >>= 1;
    }
    return [value, p];
  }
  function u32le(v) { return [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]; }
  function u64le(v) {
    const lo = v % 4294967296, hi = Math.floor(v / 4294967296);
    return u32le(lo).concat(u32le(hi));
  }
  function rdU32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }
  function rdU64(b, o) { return rdU32(b, o) + rdU32(b, o + 4) * 4294967296; }

  /* --------- 构造 7z（单文件，LZMA1 或 Copy 存储） --------- */
  function build7z(content, name, useLzma) {
    let payload, coderId, props, unpackSize = content.length;
    if (useLzma) {
      const r = lzmaEncode(content);
      if (r && r.data.length < content.length) { payload = r.data; coderId = [0x03, 0x01, 0x01]; props = r.props; }
      else { payload = content; coderId = [0x00]; props = null; }
    } else {
      payload = content; coderId = [0x00]; props = null;
    }
    const nameUtf16 = [];
    const nm = name + '\u0000';
    for (let i = 0; i < nm.length; i++) { const c = nm.charCodeAt(i); nameUtf16.push(c & 0xff, (c >>> 8) & 0xff); }

    const h = [];
    h.push(0x01);                    // kHeader
    h.push(0x04);                    // kMainStreamsInfo
    h.push(0x06, 0x00, 0x01, 0x09);  // kPackInfo: pos=0, num=1, kSize
    wnum(h, payload.length);
    h.push(0x00);                    // kEnd
    h.push(0x07);                    // kUnPackInfo
    h.push(0x0B, 0x01, 0x00);        // kFolder, numFolders=1, external=0
    h.push(0x01);                    // numCoders=1
    h.push(props ? (coderId.length | 0x20) : coderId.length); // flags
    coderId.forEach(b => h.push(b));
    if (props) { wnum(h, props.length); props.forEach(b => h.push(b)); }
    h.push(0x0C); wnum(h, unpackSize); // kCodersUnpackSize
    h.push(0x00);                    // kEnd (UnPackInfo)
    h.push(0x08, 0x0A, 0x01);        // kSubStreamsInfo, kCRC, allDefined
    u32le(crc32(content)).forEach(b => h.push(b));
    h.push(0x00);                    // kEnd
    h.push(0x00);                    // kEnd (StreamsInfo)
    h.push(0x05, 0x01);              // kFilesInfo, numFiles=1
    // 注意：原版(SharpCompress) 的 kName 长度字段 = 名字字节数 + 1，这里保持一致以确保互解
    h.push(0x11); wnum(h, nameUtf16.length + 1); h.push(0x00);   // kName
    nameUtf16.forEach(b => h.push(b));
    h.push(0x00);                    // kEnd
    h.push(0x00);                    // kEnd (Header)

    const hdr = new Uint8Array(h);
    const total = new Uint8Array(32 + payload.length + hdr.length);
    total.set([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x03], 0);
    const nextOff = payload.length, nextSize = hdr.length;
    const tail = u64le(nextOff).concat(u64le(nextSize), u32le(crc32(hdr)));
    total.set(tail, 12);
    total.set(u32le(crc32(new Uint8Array(tail))), 8);
    total.set(payload, 32);
    total.set(hdr, 32 + payload.length);
    return total;
  }

  /* --------- 解析 7z + 解压 --------- */
  function parse7z(data) {
    if (data[0] !== 0x37 || data[1] !== 0x7A) throw new Error('不是 7z 数据（密钥/密文可能有误）');
    const nextOff = rdU64(data, 12), nextSize = rdU64(data, 20);
    let p = 32 + nextOff;
    const end = p + nextSize;
    const info = { folders: [] };
    if (data[p++] !== 0x01) throw new Error('7z 头解析失败');
    while (p < end) {
      const t = data[p++];
      if (t === 0x00) break;
      if (t === 0x04) {            // kMainStreamsInfo
        while (p < end) {
          const st = data[p++];
          if (st === 0x00) break;
          if (st === 0x06) {      // kPackInfo
            let v; [info.packPos, p] = rnum(data, p);
            let num; [num, p] = rnum(data, p);
            while (p < end) {
              const s2 = data[p++];
              if (s2 === 0x00) break;
              if (s2 === 0x09) { info.packSizes = []; for (let i = 0; i < num; i++) { [v, p] = rnum(data, p); info.packSizes.push(v); } }
              else { [v, p] = rnum(data, p); p += v; }
            }
          } else if (st === 0x07) { // kUnPackInfo
            while (p < end) {
              const s2 = data[p++];
              if (s2 === 0x00) break;
              if (s2 === 0x0B) {   // kFolder
                let numF; [numF, p] = rnum(data, p);
                p++;                 // external
                for (let i = 0; i < numF; i++) {
                  let numC; [numC, p] = rnum(data, p);
                  const f = { coders: [], numOut: 0 };
                  for (let c = 0; c < numC; c++) {
                    const flags = data[p++];
                    const idSize = flags & 0x0F, complex = flags & 0x10, hasAttr = flags & 0x20;
                    const id = []; for (let k = 0; k < idSize; k++) id.push(data[p++]);
                    let nin = 1, nout = 1;
                    if (complex) { [nin, p] = rnum(data, p); [nout, p] = rnum(data, p); }
                    let props = null;
                    if (hasAttr) { let ps; [ps, p] = rnum(data, p); props = data.subarray(p, p + ps); p += ps; }
                    f.coders.push({ id, nin, nout, props });
                    f.numOut += nout;
                  }
                  info.folders.push(f);
                }
              } else if (s2 === 0x0C) {  // kCodersUnpackSize
                info.unpackSizes = [];
                for (const f of info.folders) for (let i = 0; i < f.numOut; i++) { let v; [v, p] = rnum(data, p); info.unpackSizes.push(v); }
              } else { let v; [v, p] = rnum(data, p); p += v; }
            }
          } else if (st === 0x08) { // kSubStreamsInfo
            p = end;
          } else { let v; [v, p] = rnum(data, p); p += v; }
        }
      } else { let v; [v, p] = rnum(data, p); p += v; }
    }
    const f = info.folders[0], c = f.coders[0];
    const packed = data.subarray(32 + (info.packPos || 0), 32 + (info.packPos || 0) + info.packSizes[0]);
    const unpackSize = info.unpackSizes[0];
    const idHex = c.id.map(b => b.toString(16).padStart(2, '0')).join('');
    if (idHex === '00') return packed.slice(0, unpackSize);      // Copy
    if (idHex === '030101') {
      const d = c.props[0], lc = d % 9, lp = ((d / 9) | 0) % 5, pb = (((d / 9) | 0) / 5 | 0) % 5;
      const dict = rdU32(c.props, 1);
      return lzmaDecode(packed, unpackSize, lc, lp, pb);
    }
    if (idHex === '21') throw new Error('暂不支持 LZMA2 编码');
    throw new Error('不支持的 7z 压缩算法: ' + idHex);
  }

  /* ============================ LZMA1 解压 ============================ */
  function lzmaDecode(input, unpackSize, lc, lp, pb) {
    const rd = {
      data: input, pos: 0, range: 0xFFFFFFFF, code: 0,
      norm() { if (this.range < (1 << 24)) { this.range <<= 8; this.range >>>= 0; this.code = ((this.code << 8) | (this.data[this.pos++] || 0)) >>> 0; this.code >>>= 0; } },
      bit(probs, i) {
        const prob = probs[i];
        let bound = ((this.range >>> 11) * prob) >>> 0;
        let s;
        if ((this.code >>> 0) < bound) { this.range = bound; probs[i] = prob + ((2048 - prob) >>> 5); s = 0; }
        else { this.range = (this.range - bound) >>> 0; this.code = (this.code - bound) >>> 0; probs[i] = prob - (prob >>> 5); s = 1; }
        this.norm();
        return s;
      },
      direct(count) {
        let res = 0;
        for (let i = 0; i < count; i++) {
          this.range >>>= 1;
          const t = ((this.code - this.range) >>> 31) ? 1 : 0;
          if (t === 0) this.code = (this.code - this.range) >>> 0;
          res = (res << 1) | (1 - t);
          this.norm();
        }
        return res >>> 0;
      }
    };
    rd.pos = 1;  // LZMA1 首字节固定为 0
    for (let i = 0; i < 4; i++) rd.code = ((rd.code << 8) | input[rd.pos++]) >>> 0;

    const posStateMask = (1 << pb) - 1, litPosMask = (1 << lp) - 1;
    const numLit = 1 << (lc + lp);
    let o = 0;
    const LIT = o; o += numLit * 0x300;
    const IS_MATCH = o; o += 12 * 16;
    const IS_REP = o; o += 12;
    const IS_REP_G0 = o; o += 12;
    const IS_REP_G1 = o; o += 12;
    const IS_REP_G2 = o; o += 12;
    const IS_REP0_LONG = o; o += 12 * 16;
    const POS_SLOT = o; o += 4 * 64;
    const SPEC_POS = o; o += 128 - 14;
    const ALIGN = o; o += 16;
    const LEN_C = o; o += 1;
    const LEN_LOW = o; o += 16 * 8;
    const LEN_MID = o; o += 16 * 8;
    const LEN_HIGH = o; o += 256;
    const RLEN_C = o; o += 1;
    const RLEN_LOW = o; o += 16 * 8;
    const RLEN_MID = o; o += 16 * 8;
    const RLEN_HIGH = o; o += 256;
    const probs = new Uint16Array(o).fill(1024);

    function treeDecode(off, bits) {      // MSB first
      let m = 1, sym = 0;
      for (let i = 0; i < bits; i++) { const b = rd.bit(probs, off + m); m = (m << 1) + b; sym = (sym << 1) | b; }
      return sym;
    }
    function revDecode(off, bits) {       // LSB first
      let m = 1, sym = 0;
      for (let i = 0; i < bits; i++) { const b = rd.bit(probs, off + m); m = (m << 1) + b; sym |= (b << i); }
      return sym;
    }
    function lenDecode(cOff, lowOff, midOff, highOff, posState) {
      if (rd.bit(probs, cOff) === 0) return treeDecode(lowOff + (posState << 3), 3);
      if (rd.bit(probs, cOff + 1) === 0) return 8 + treeDecode(midOff + (posState << 3), 3);
      return 16 + treeDecode(highOff, 8);
    }

    const out = new Uint8Array(unpackSize);
    let state = 0, rep0 = 0, rep1 = 0, rep2 = 0, rep3 = 0, nowPos = 0, prevByte = 0;
    while (nowPos < unpackSize) {
      const posState = nowPos & posStateMask;
      if (rd.bit(probs, IS_MATCH + (state << 4) + posState) === 0) {
        const litState = ((nowPos & litPosMask) << lc) + (prevByte >>> (8 - lc));
        const p = LIT + litState * 0x300;
        let sym = 1;
        if (state >= 7) {
          let mb = out[nowPos - rep0 - 1] || 0;
          do {
            const mbbit = (mb >> 7) & 1; mb = (mb << 1) & 0xff;
            const bit = rd.bit(probs, p + ((1 + mbbit) << 8) + sym);
            sym = ((sym << 1) + bit) & 0x1ff;
            if (mbbit !== bit) { while (sym < 0x100) { const b2 = rd.bit(probs, p + sym); sym = ((sym << 1) + b2) & 0x1ff; } break; }
          } while (sym < 0x100);
        } else {
          do { const b2 = rd.bit(probs, p + sym); sym = ((sym << 1) + b2) & 0x1ff; } while (sym < 0x100);
        }
        prevByte = sym & 0xff;
        out[nowPos++] = prevByte;
        state = state < 4 ? 0 : (state < 10 ? state - 3 : state - 6);
        continue;
      }
      let len;
      if (rd.bit(probs, IS_REP + state) === 1) {
        if (rd.bit(probs, IS_REP_G0 + state) === 0) {
          if (rd.bit(probs, IS_REP0_LONG + (state << 4) + posState) === 0) {
            state = state < 7 ? 9 : 11;
            out[nowPos] = out[nowPos - rep0 - 1];
            nowPos++; prevByte = out[nowPos - 1];
            continue;
          }
        } else {
          let dist;
          if (rd.bit(probs, IS_REP_G1 + state) === 0) dist = rep1;
          else {
            if (rd.bit(probs, IS_REP_G2 + state) === 0) dist = rep2;
            else { dist = rep3; rep3 = rep2; }
            rep2 = rep1;
          }
          rep1 = rep0; rep0 = dist;
        }
        len = 2 + lenDecode(RLEN_C, RLEN_LOW, RLEN_MID, RLEN_HIGH, posState);
        state = state < 7 ? 8 : 11;
      } else {
        rep3 = rep2; rep2 = rep1; rep1 = rep0;
        len = 2 + lenDecode(LEN_C, LEN_LOW, LEN_MID, LEN_HIGH, posState);
        const lenToPos = Math.min(len - 2, 3);
        const posSlot = treeDecode(POS_SLOT + (lenToPos << 6), 6);
        if (posSlot >= 4) {
          const numDirect = (posSlot >> 1) - 1;
          rep0 = ((2 | (posSlot & 1)) << numDirect);
          if (posSlot < 14) rep0 += revDecode(SPEC_POS + rep0 - posSlot - 1, numDirect);
          else {
            rep0 += rd.direct(numDirect - 4) << 4;
            rep0 += revDecode(ALIGN, 4);
          }
          if (rep0 === 0xFFFFFFFF) break;
        } else rep0 = posSlot;
        state = state < 7 ? 7 : 10;
      }
      for (let i = 0; i < len; i++) out[nowPos + i] = out[nowPos + i - rep0 - 1];
      nowPos += len;
      prevByte = out[nowPos - 1];
    }
    return out;
  }

  /* --------- LZMA1 压缩（可选，未启用时走 Copy 存储） --------- */
  function lzmaEncode(content) {
    if (typeof LzmaEncoder === 'undefined') return null;
    return null;
  }

  /* ============================ 字表 ============================ */
  const TABLE1 = ('滅 苦 婆 娑 耶 陀 跋 多 漫 都 殿 悉 夜 爍 帝 吉 ' +
    '利 阿 無 南 那 怛 喝 羯 勝 摩 伽 謹 波 者 穆 僧 ' +
    '室 藝 尼 瑟 地 彌 菩 提 蘇 醯 盧 呼 舍 佛 參 沙 ' +
    '伊 隸 麼 遮 闍 度 蒙 孕 薩 夷 迦 他 姪 豆 特 逝 ' +
    '朋 輸 楞 栗 寫 數 曳 諦 羅 曰 咒 即 密 若 般 故 ' +
    '不 實 真 訶 切 一 除 能 等 是 上 明 大 神 知 三 ' +
    '藐 耨 得 依 諸 世 槃 涅 竟 究 想 夢 倒 顛 離 遠 ' +
    '怖 恐 有 礙 心 所 以 亦 智 道 。 集 盡 死 老 至').split(' ');
  const MARK = '冥 奢 梵 呐 俱 哆 怯 諳 罰 侄 缽 皤'.split(' ');
  const TABLE2 = ('謹 穆 僧 室 藝 瑟 彌 提 蘇 醯 盧 呼 舍 參 沙 伊 ' +
    '隸 麼 遮 闍 度 蒙 孕 薩 夷 他 姪 豆 特 逝 輸 楞 ' +
    '栗 寫 數 曳 諦 羅 故 實 訶 知 三 藐 耨 依 槃 涅 ' +
    '竟 究 想 夢 倒 顛 遠 怖 恐 礙 以 亦 智 盡 老 至 ' +
    '吼 足 幽 王 告 须 弥 灯 护 金 刚 游 戏 宝 胜 通 ' +
    '药 师 琉 璃 普 功 德 山 善 住 过 去 七 未 来 贤 ' +
    '劫 千 五 百 万 花 亿 定 六 方 名 号 东 月 殿 妙 ' +
    '尊 树 根 西 皂 焰 北 清 数 精 进 首 下 寂 量 诸 ' +
    '多 释 迦 牟 尼 勒 阿 閦 陀 中 央 众 生 在 界 者 ' +
    '行 于 及 虚 空 慈 忧 各 令 安 稳 休 息 昼 夜 修 ' +
    '持 心 求 诵 此 经 能 灭 死 消 除 毒 害 高 开 文 ' +
    '殊 利 凉 如 念 即 说 曰 帝 毘 真 陵 乾 梭 哈 敬 ' +
    '禮 奉 祖 先 孝 雙 親 守 重 師 愛 兄 弟 信 朋 友 ' +
    '睦 宗 族 和 鄉 夫 婦 教 孫 時 便 廣 積 陰 難 濟 ' +
    '急 恤 孤 憐 貧 創 廟 宇 印 造 經 捨 藥 施 茶 戒 ' +
    '殺 放 橋 路 矜 寡 拔 困 粟 惜 福 排 解 紛 捐 資').split(' ');

  const KEY = (function () { const s = 'XDXDtudou@KeyFansClub^_^Encode!!'; const a = new Uint8Array(32); for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i); return a; })();
  const IV = (function () { const s = 'Potato@Key@_@=_='; const a = new Uint8Array(16); for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i); return a; })();
  const HEAD1 = '佛曰：', HEAD2 = '如是我闻：';

  function utf16le(str) {
    const b = new Uint8Array(str.length * 2);
    for (let i = 0; i < str.length; i++) { const c = str.charCodeAt(i); b[2 * i] = c & 0xff; b[2 * i + 1] = (c >>> 8) & 0xff; }
    return b;
  }
  function fromUtf16le(b) {
    let s = '';
    for (let i = 0; i + 1 < b.length; i += 2) s += String.fromCharCode(b[i] | (b[i + 1] << 8));
    return s;
  }
  function utf8(str) {
    if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
    const s = unescape(encodeURIComponent(str)); const b = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
    return b;
  }
  function fromUtf8(b) {
    if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8').decode(b);
    let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return decodeURIComponent(escape(s));
  }

  /* ============================ 对外接口 ============================ */
  function encodeV1(text, rnd) {
    const enc = cbcEncrypt(utf16le(text), KEY, IV);
    const r = rnd || (() => Math.floor(Math.random() * MARK.length));
    let s = '';
    for (let i = 0; i < enc.length; i++) {
      if (enc[i] >= 0x80) s += MARK[r()] + TABLE1[enc[i] ^ 0x80];
      else s += TABLE1[enc[i]];
    }
    return HEAD1 + s;
  }
  function decodeV1(body) {
    const bytes = [];
    for (let i = 0; i < body.length; i++) {
      if (MARK.indexOf(body[i]) >= 0) { i++; const idx = TABLE1.indexOf(body[i]); if (idx < 0) throw new Error('佛语中含未知字符：' + body[i]); bytes.push(idx + 128); }
      else { const idx = TABLE1.indexOf(body[i]); if (idx < 0) throw new Error('佛语中含未知字符：' + body[i]); bytes.push(idx); }
    }
    const dec = cbcDecrypt(new Uint8Array(bytes), KEY, IV);
    return fromUtf16le(dec);
  }
  function encodeV2(text, useLzma) {
    const z = build7z(utf8(text), 'default', !!useLzma);
    const enc = cbcEncrypt(z, KEY, IV);
    let s = '';
    for (let i = 0; i < enc.length; i++) s += TABLE2[enc[i]];
    return HEAD2 + s;
  }
  function decodeV2(body) {
    const bytes = new Uint8Array(body.length);
    for (let i = 0; i < body.length; i++) {
      const idx = TABLE2.indexOf(body[i]);
      if (idx < 0) throw new Error('佛语中含未知字符：' + body[i]);
      bytes[i] = idx;
    }
    const z = cbcDecrypt(bytes, KEY, IV);
    return fromUtf8(parse7z(z));
  }
  function detect(text) {
    const t = text.trim();
    if (t.startsWith(HEAD1) || t.startsWith('佛曰:') || t.startsWith('佛曰')) return 1;
    if (t.startsWith(HEAD2) || t.startsWith('如是我闻:') || t.startsWith('如是我闻')) return 2;
    return 0;
  }
  function stripHead(text) {
    const t = text.trim();
    for (const h of [HEAD1, '佛曰:', '佛曰', HEAD2, '如是我闻:', '如是我闻']) if (t.startsWith(h)) return t.slice(h.length);
    return t;
  }
  function encode(text, version, useLzma) {
    return version === 2 ? encodeV2(text, useLzma) : encodeV1(text);
  }
  function decode(text) {
    const v = detect(text);
    if (!v) throw new Error('请带上「佛曰：」或「如是我闻：」开头');
    const body = stripHead(text).replace(/[\s\n\r]/g, '');
    return v === 1 ? decodeV1(body) : decodeV2(body);
  }

  return {
    TABLE1, TABLE2, MARK, KEY, IV, HEAD1, HEAD2,
    encode, decode, encodeV1, decodeV1, encodeV2, decodeV2, detect, stripHead,
    _internal: { AES256, cbcEncrypt, cbcDecrypt, crc32, build7z, parse7z, lzmaDecode, utf16le, fromUtf16le }
  };
});
