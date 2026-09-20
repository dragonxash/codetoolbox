/* =========================================================================
 * 10-legacy.js —— 老式 / 冷门编码层   CT.legacy
 *
 * 收录现代 BASE64 之外仍在 CTF、历史资料、特定协议里出没的编码：
 *   UUencode、XXencode、Ascii85(Adobe)、Base92、yEnc、Punycode(IDN)、
 *   EBCDIC、hexdump、盲文、DNA、Bubble Babble、敲敲码、北约音标、T9 九宫格
 *
 * 对拍来源：
 *   UU       -> Python binascii.b2a_uu
 *   Ascii85  -> Python base64.a85encode / a85decode（含 foldspaces / adobe）
 *   XX/Z85   -> RFC 规范手写参考实现
 *   Base92   -> thenoviceoof/base92 官方 Python 实现（test/oracle/ref）
 *   EBCDIC   -> Python cp037 码表（test/oracle/ebcdic_hex.txt）
 *   Bubble   -> OpenSSH sshkey.c / Digest::BubbleBabble 公开向量
 * ========================================================================= */
CT.legacy = (function () {
  const U = CT.util;

  /* =================== 1. UUencode =================== */

  function uuEncode(bytes, opts) {
    opts = opts || {};
    const b = U.asBytes(bytes);
    const out = [];
    if (opts.filename) {
      out.push('begin ' + (opts.mode || '644') + ' ' + opts.filename + '\n');
    }
    for (let i = 0; i < b.length; i += 45) {
      const len = Math.min(45, b.length - i);
      out.push(String.fromCharCode(32 + len));       // 长度字符（0 长度时为空格）
      for (let j = 0; j < len; j += 3) {
        const n = (b[i + j] << 16) | ((b[i + j + 1] || 0) << 8) | (b[i + j + 2] || 0);
        out.push(String.fromCharCode(32 + ((n >> 18) & 63)));
        out.push(String.fromCharCode(32 + ((n >> 12) & 63)));
        out.push(String.fromCharCode(32 + ((n >> 6) & 63)));
        out.push(String.fromCharCode(32 + (n & 63)));
      }
      out.push('\n');
    }
    // 空输入仍输出一行「长度 0」的占位行，与 binascii.b2a_uu 一致
    if (!b.length) out.push(' \n');
    if (opts.filename) out.push('`\nend\n');
    return out.join('');
  }

  function uuDecode(str) {
    const lines = String(str).split(/\r?\n/);
    const out = [];
    for (let li = 0; li < lines.length; li++) {
      const line = lines[li];
      if (/^begin\s/.test(line)) continue;
      if (/^end\b/.test(line)) break;
      if (!line.length) continue;
      let len = (line.charCodeAt(0) - 32) & 63;
      if (len === 0) continue;
      let rem = len;
      for (let j = 1; j < line.length && rem > 0; j += 4) {
        let n = 0;
        for (let k = 0; k < 4; k++) {
          // 兼容两种「0」写法：空格(32) 与反引号(96)，两者 (c-32)&63 均为 0
          const c = line.charCodeAt(j + k);
          n = (n << 6) | (isNaN(c) ? 0 : ((c - 32) & 63));
        }
        const take = Math.min(3, rem);
        if (take >= 1) out.push((n >> 16) & 255);
        if (take >= 2) out.push((n >> 8) & 255);
        if (take >= 3) out.push(n & 255);
        rem -= take;
      }
    }
    return Uint8Array.from(out);
  }

  /* =================== 2. XXencode =================== */
  // 字母表：+ - 0-9 A-Z a-z，长度字符也取自该表
  const XX_A = '+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

  function xxEncode(bytes) {
    const b = U.asBytes(bytes);
    const out = [];
    for (let i = 0; i < b.length; i += 45) {
      const len = Math.min(45, b.length - i);
      out.push(XX_A[len]);
      for (let j = 0; j < len; j += 3) {
        const n = (b[i + j] << 16) | ((b[i + j + 1] || 0) << 8) | (b[i + j + 2] || 0);
        const take = Math.min(3, len - j) + 1;      // XX 只输出 (字节数+1) 个字符
        for (let k = 0; k < take; k++) out.push(XX_A[(n >> (18 - 6 * k)) & 63]);
      }
      out.push('\n');
    }
    return out.join('');
  }

  function xxDecode(str) {
    const out = [];
    const lines = String(str).split(/\r?\n/);
    for (const line of lines) {
      if (!line.length) continue;
      const rest = line.slice(1);
      for (let j = 0; j < rest.length; j += 4) {
        const grp = rest.substr(j, 4);
        if (grp.length < 2) break;
        let n = 0;
        for (let k = 0; k < 4; k++) {
          const v = k < grp.length ? XX_A.indexOf(grp[k]) : 0;
          if (v < 0) throw new Error('非法 XXencode 字符: ' + grp[k]);
          n = (n << 6) | v;
        }
        const take = grp.length - 1;
        if (take >= 1) out.push((n >> 16) & 255);
        if (take >= 2) out.push((n >> 8) & 255);
        if (take >= 3) out.push(n & 255);
      }
    }
    return Uint8Array.from(out);
  }

  /* =================== 3. Ascii85（含 Adobe 变体） =================== */

  function a85Encode(bytes, opts) {
    opts = opts || {};
    const b = U.asBytes(bytes);
    const adobe = !!opts.adobe, fold = !!opts.foldspaces;
    const out = [];
    for (let i = 0; i < b.length; i += 4) {
      const n = Math.min(4, b.length - i);        // 本组实际字节数（1..4）
      if (n === 4 && b[i] === 0 && b[i + 1] === 0 && b[i + 2] === 0 && b[i + 3] === 0) {
        out.push('z'); continue;
      }
      if (fold && n === 4 && b[i] === 32 && b[i + 1] === 32 && b[i + 2] === 32 && b[i + 3] === 32) {
        out.push('y'); continue;
      }
      // 用乘法而非 v<<8：JS 位运算是 32 位有符号，字节值大时会溢出成负数
      let v = 0;
      for (let k = 0; k < 4; k++) v = v * 256 + (k < n ? b[i + k] : 0);
      const c = [];
      for (let k = 4; k >= 0; k--) { c[k] = v % 85; v = Math.floor(v / 85); }
      for (let k = 0; k < n + 1; k++) out.push(String.fromCharCode(33 + c[k]));
    }
    const body = out.join('');
    return adobe ? '<~' + body + '~>' : body;
  }

  function a85Decode(str, opts) {
    opts = opts || {};
    let s = String(str).trim();
    if (s.startsWith('<~')) s = s.slice(2);
    if (s.endsWith('~>')) s = s.slice(0, -2);
    s = s.replace(/\s+/g, '');
    const out = [];
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === 'z') { out.push(0, 0, 0, 0); continue; }
      if (c === 'y') { out.push(32, 32, 32, 32); continue; }
      const grp = s.substr(i, 5);
      if (grp.length < 2) throw new Error('Ascii85 尾部不完整');
      let v = 0;
      for (let k = 0; k < 5; k++) {
        const code = k < grp.length ? grp.charCodeAt(k) - 33 : 0;
        if (code < 0 || code > 84) throw new Error('非法 Ascii85 字符');
        v = v * 85 + (k < grp.length ? code : 84);
      }
      const take = grp.length - 1;
      // v 最大 85^5 ≈ 4.44e9，超过 32 位；用除法取字节，不能用 >>> 移位
      if (take >= 1) out.push(Math.floor(v / 0x1000000) & 255);
      if (take >= 2) out.push(Math.floor(v / 0x10000) & 255);
      if (take >= 3) out.push(Math.floor(v / 0x100) & 255);
      if (take >= 4) out.push(v & 255);
      i += grp.length - 1;
    }
    return Uint8Array.from(out);
  }

  /* =================== 4. Base92 =================== */
  // 13 bit -> 2 字符；剩余不足 7 bit 补到 6 bit 出 1 字符，否则补到 13 bit 出 2 字符
  const B92 = (function () {
    const a = [];
    a.push(0x21);                                   // '!'
    for (let i = 0; i < 61; i++) a.push(0x23 + i);  // '#'(35) .. '{'? (35+60=95='_')
    for (let i = 0; i < 29; i++) a.push(0x61 + i);  // 'a' .. '{'? (97+28=125='}')
    return String.fromCharCode.apply(null, a);
  })();

  function b92Encode(bytes) {
    const b = U.asBytes(bytes);
    if (!b.length) return '~';
    let buf = 0, bits = 0;
    const out = [];
    for (let i = 0; i < b.length; i++) {
      buf = (buf << 8) | b[i];
      bits += 8;
      while (bits >= 13) {
        const chunk = buf >> (bits - 13);
        buf &= (1 << (bits - 13)) - 1;
        bits -= 13;
        out.push(B92[Math.floor(chunk / 91)], B92[chunk % 91]);
      }
    }
    if (bits > 0) {
      if (bits < 7) {
        out.push(B92[buf << (6 - bits)]);
      } else {
        const chunk = buf << (13 - bits);
        out.push(B92[Math.floor(chunk / 91)], B92[chunk % 91]);
      }
    }
    return out.join('');
  }

  function b92Decode(str) {
    let s = String(str).trim();
    if (s === '~') return new Uint8Array(0);
    if (s.length === 1) throw new Error('单个字符不是合法 base92');
    let buf = 0, bits = 0;
    const out = [];
    let i = 0;
    for (; i < s.length - 1; i += 2) {
      const v1 = B92.indexOf(s[i]), v2 = B92.indexOf(s[i + 1]);
      if (v1 < 0 || v2 < 0) throw new Error('非法 base92 字符');
      const chunk = v1 * 91 + v2;
      if (chunk >= 8192) throw new Error('base92 分组超界');
      buf = (buf << 13) | chunk;
      bits += 13;
      while (bits >= 8) {
        out.push(buf >> (bits - 8));
        buf &= (1 << (bits - 8)) - 1;
        bits -= 8;
      }
    }
    if (i < s.length) {
      const v = B92.indexOf(s[i]);
      if (v < 0) throw new Error('非法 base92 字符');
      buf = (buf << 6) | v;
      bits += 6;
      while (bits >= 8) {
        out.push(buf >> (bits - 8));
        buf &= (1 << (bits - 8)) - 1;
        bits -= 8;
      }
    }
    return Uint8Array.from(out);
  }

  /* =================== 5. yEnc =================== */
  // 每字节 +42 取模；遇 0x00/0x0A/0x0D/0x3D(=) 用 '=' 转义并再 +64
  function yEncEncode(bytes, opts) {
    opts = opts || {};
    const b = U.asBytes(bytes);
    const line = opts.line || 0;      // 0 = 不折行
    const out = [];
    let col = 0;
    for (let i = 0; i < b.length; i++) {
      let v = (b[i] + 42) & 255;
      if (v === 0 || v === 0x0A || v === 0x0D || v === 0x3D) {
        out.push('=');
        v = (v + 64) & 255;
        col++;
      }
      out.push(String.fromCharCode(v));
      col++;
      if (line && col >= line) { out.push('\r\n'); col = 0; }
    }
    return out.join('');
  }

  function yEncDecode(str) {
    const s = String(str);
    const out = [];
    let esc = false;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c === 10 || c === 13) continue;
      if (esc) { out.push((c - 64 - 42) & 255); esc = false; continue; }
      if (c === 0x3D) { esc = true; continue; }
      out.push((c - 42) & 255);
    }
    return Uint8Array.from(out);
  }

  /* =================== 6. Punycode (RFC 3492) =================== */
  const PC_BASE = 36, PC_TMIN = 1, PC_TMAX = 26, PC_SKEW = 38, PC_DAMP = 700;
  const PC_INIT_N = 128, PC_INIT_BIAS = 72, PC_DELIM = '-';

  /* RFC 3492 §6：t(k, bias) = tmin if k <= bias+tmin; tmax if k >= bias+tmax; k-bias 否则 */
  function pcT(k, bias) {
    if (k <= bias + PC_TMIN) return PC_TMIN;
    if (k >= bias + PC_TMAX) return PC_TMAX;
    return k - bias;
  }

  function pcAdapt(delta, numPoints, firstTime) {
    delta = Math.floor(firstTime ? delta / PC_DAMP : delta / 2);
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((PC_BASE - PC_TMIN) * PC_TMAX) / 2) {
      delta = Math.floor(delta / (PC_BASE - PC_TMIN));
      k += PC_BASE;
    }
    return k + Math.floor(((PC_BASE - PC_TMIN + 1) * delta) / (delta + PC_SKEW));
  }

  function pcDigitToChar(d) {
    return String.fromCharCode(d + 22 + 75 * (d < 26 ? 1 : 0));
  }

  function pcCharToDigit(c) {
    const v = c.charCodeAt(0);
    if (v >= 48 && v <= 57) return v - 22;          // '0'-'9' -> 26..35
    if (v >= 65 && v <= 90) return v - 65;          // 'A'-'Z' -> 0..25
    if (v >= 97 && v <= 122) return v - 97;         // 'a'-'z' -> 0..25
    return PC_BASE;
  }

  function punycodeEncode(str) {
    const input = Array.from(String(str), c => c.codePointAt(0));
    const out = [];
    let n = PC_INIT_N, delta = 0, bias = PC_INIT_BIAS;
    let h = 0;
    for (const c of input) if (c < 0x80) { out.push(String.fromCharCode(c)); h++; }
    const b = h;
    if (b > 0) out.push(PC_DELIM);
    while (h < input.length) {
      let m = 0x110000;
      for (const c of input) if (c >= n && c < m) m = c;
      delta += (m - n) * (h + 1);
      if (delta > 0x7FFFFFFF) throw new Error('Punycode 溢出');
      n = m;
      for (const c of input) {
        if (c < n) { delta++; if (delta > 0x7FFFFFFF) throw new Error('Punycode 溢出'); }
        if (c === n) {
          let q = delta;
          for (let k = PC_BASE; ; k += PC_BASE) {
            const t = pcT(k, bias);
            if (q < t) break;
            out.push(pcDigitToChar(t + ((q - t) % (PC_BASE - t))));
            q = Math.floor((q - t) / (PC_BASE - t));
          }
          out.push(pcDigitToChar(q));
          bias = pcAdapt(delta, h + 1, h === b);
          delta = 0;
          h++;
        }
      }
      delta++; n++;
    }
    return out.join('');
  }

  function punycodeDecode(str) {
    let s = String(str);
    let n = PC_INIT_N, bias = PC_INIT_BIAS;
    const out = [];
    const d = s.lastIndexOf(PC_DELIM);
    if (d >= 0) {
      for (let i = 0; i < d; i++) {
        if (s.charCodeAt(i) >= 0x80) throw new Error('分隔符左侧含非 ASCII 字符');
        out.push(s.charCodeAt(i));
      }
      s = s.slice(d + 1);
    }
    // 注意：RFC 的 i（这里叫 acc）跨轮次保持，不重置；oldi 用于取本轮 delta
    let idx = 0, acc = 0;
    while (idx < s.length) {
      const oldi = acc;
      let w = 1;
      for (let k = PC_BASE; ; k += PC_BASE) {
        if (idx >= s.length) throw new Error('Punycode 输入不完整');
        const digit = pcCharToDigit(s[idx++]);
        if (digit >= PC_BASE) throw new Error('非法 Punycode 字符');
        acc += digit * w;
        if (acc > 0x7FFFFFFF) throw new Error('Punycode 溢出');
        const t = pcT(k, bias);
        if (digit < t) break;
        w *= (PC_BASE - t);
      }
      const cnt = out.length + 1;
      bias = pcAdapt(acc - oldi, cnt, oldi === 0);
      n += Math.floor(acc / cnt);
      acc = acc % cnt;
      if (n >= 0xD800 && n <= 0xDFFF) throw new Error('Punycode 解出代理区码位');
      out.splice(acc, 0, n);
      acc++;
    }
    return out.map(c => {
      if (c > 0xFFFF) {
        const v = c - 0x10000;
        return String.fromCharCode(0xD800 + (v >> 10), 0xDC00 + (v & 0x3FF));
      }
      return String.fromCharCode(c);
    }).join('');
  }

  /* 域名级 IDNA：逐标签编码，便于同形字（homograph）分析 */
  function idnaEncode(host) {
    return String(host).split('.').map(lbl => {
      if (/^[\x00-\x7F]*$/.test(lbl)) return lbl;
      return 'xn--' + punycodeEncode(lbl);
    }).join('.');
  }

  function idnaDecode(host) {
    return String(host).split('.').map(lbl => {
      if (lbl.toLowerCase().startsWith('xn--')) {
        return punycodeDecode(lbl.slice(4)) || lbl;
      }
      return lbl;
    }).join('.');
  }

  /* =================== 7. EBCDIC (cp037) =================== */
  const EBCDIC_HEX =
    '00010203372d2e2f1605250b0c0d0e0f101112133c3d322618193f271c1d1e1f' +
    '405a7f7b5b6c507d4d5d5c4e6b604b61f0f1f2f3f4f5f6f7f8f97a5e4c7e6e6f' +
    '7cc1c2c3c4c5c6c7c8c9d1d2d3d4d5d6d7d8d9e2e3e4e5e6e7e8e9bae0bbb06d' +
    '79818283848586878889919293949596979899a2a3a4a5a6a7a8a9c04fd0a107' +
    '202122232415061728292a2b2c090a1b30311a333435360838393a3b04143eff' +
    '41aa4ab19fb26ab5bdb49a8a5fcaafbc908feafabea0b6b39dda9b8bb7b8b9ab' +
    '6465626663679e687471727378757677ac69edeeebefecbf80fdfefbfcadae59' +
    '4445424643479c4854515253585556578c49cdcecbcfcce170dddedbdc8d8edf';
  const E2A = U.unhex(EBCDIC_HEX);                 // latin1 -> EBCDIC
  const A2E = (function () {
    const t = new Uint8Array(256);
    for (let i = 0; i < 256; i++) t[E2A[i]] = i;
    return t;
  })();

  function ebcdicEncode(text) {
    const b = U.latin1Enc(String(text));
    const o = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) o[i] = E2A[b[i]];
    return U.latin1Dec(o);
  }

  function ebcdicDecode(text) {
    const b = U.latin1Enc(String(text));
    const o = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) o[i] = A2E[b[i]];
    return U.latin1Dec(o);
  }

  /* =================== 8. hexdump =================== */

  function hexdump(bytes, opts) {
    opts = opts || {};
    const b = U.asBytes(bytes);
    const w = opts.width || 16;
    const lines = [];
    for (let i = 0; i < b.length; i += w) {
      const ch = b.subarray(i, i + w);
      // 与 Python 参考一致：hex 栏右填充到 w*3-1 列，再两空格接 |ASCII|
      let hexPart = Array.prototype.map.call(ch, x => ('0' + x.toString(16)).slice(-2)).join(' ');
      while (hexPart.length < w * 3 - 1) hexPart += ' ';
      let asc = '';
      for (let k = 0; k < ch.length; k++) asc += (ch[k] >= 32 && ch[k] < 127) ? String.fromCharCode(ch[k]) : '.';
      lines.push(i.toString(16).padStart(8, '0') + '  ' + hexPart + '  |' + asc + '|');
    }
    return lines.join('\n');
  }

  function hexdumpReverse(text) {
    const out = [];
    for (const raw of String(text).split(/\r?\n/)) {
      const line = raw.trim();
      if (!line) continue;
      let rest = line;
      const bar = rest.indexOf('|');
      if (bar >= 0) rest = rest.slice(0, bar);
      // 去掉行首偏移字段（形如 "00000000  " 或 "0000: "），要求偏移后跟 2 个以上空格
      rest = rest.replace(/^[0-9a-fA-F]{4,}:?\s{2,}/, '');
      for (const tok of rest.split(/\s+/)) {
        if (/^[0-9a-fA-F]{2}$/.test(tok)) out.push(parseInt(tok, 16));
      }
    }
    return Uint8Array.from(out);
  }

  /* 兼容无偏移、无 ASCII 栏的纯 hex 文本 */
  function hexdumpReverseLoose(text) {
    const t = String(text);
    try { return hexdumpReverse(t); } catch (e) { /* fallthrough */ }
    return U.unhex(t);
  }

  /* =================== 9. 盲文 (Braille, U+2800 区) =================== */
  // 点位：dot1=1 dot2=2 dot3=4 dot4=8 dot5=16 dot6=32（Unicode 顺序）
  const BRAILLE = {
    'a': 0x01, 'b': 0x03, 'c': 0x09, 'd': 0x19, 'e': 0x11, 'f': 0x0B,
    'g': 0x1B, 'h': 0x13, 'i': 0x0A, 'j': 0x1A, 'k': 0x05, 'l': 0x07,
    'm': 0x0D, 'n': 0x1D, 'o': 0x15, 'p': 0x0F, 'q': 0x1F, 'r': 0x17,
    's': 0x0E, 't': 0x1E, 'u': 0x25, 'v': 0x27, 'w': 0x3A, 'x': 0x2D,
    'y': 0x3D, 'z': 0x35, ' ': 0x00,
    ',': 0x02, ';': 0x06, ':': 0x12, '.': 0x32, '!': 0x16, '?': 0x26,
    '-': 0x24, "'": 0x04
  };
  const BRAILLE_INV = (function () {
    const m = {};
    for (const k in BRAILLE) if (!(BRAILLE[k] in m)) m[BRAILLE[k]] = k;
    return m;
  })();

  function brailleEncode(text) {
    // 表外字符（含 CJK、控制符）统一映射为空白盲符 U+2800，与 Python 参考一致
    let out = '';
    for (const ch of String(text)) {
      const v = BRAILLE[ch.toLowerCase()];
      out += String.fromCharCode(0x2800 + (v === undefined ? 0 : v));
    }
    return out;
  }

  function brailleDecode(text) {
    let out = '';
    for (const ch of String(text)) {
      const cp = ch.codePointAt(0);
      if (cp >= 0x2800 && cp < 0x2900) {
        const v = cp & 0xFF;
        out += (v in BRAILLE_INV) ? BRAILLE_INV[v] : '?';
      } else out += ch;
    }
    return out;
  }

  /* =================== 10. DNA 编码 =================== */
  // 2 bit -> 碱基：00=A 01=T 10=C 11=G
  const DNA_F = { '00': 'A', '01': 'T', '10': 'C', '11': 'G' };
  const DNA_R = { 'A': '00', 'T': '01', 'C': '10', 'G': '11' };

  function dnaEncode(bytes) {
    const b = U.asBytes(bytes);
    let out = '';
    for (let i = 0; i < b.length; i++) {
      const s = b[i].toString(2).padStart(8, '0');
      for (let k = 0; k < 8; k += 2) out += DNA_F[s.substr(k, 2)];
    }
    return out;
  }

  function dnaDecode(text) {
    const s = String(text).toUpperCase().replace(/[^ATCG]/g, '');
    const out = [];
    // 1 字节 = 8 bit = 4 个碱基（每碱基 2 bit）
    for (let i = 0; i + 4 <= s.length; i += 4) {
      let bits = '';
      for (let k = 0; k < 4; k++) bits += DNA_R[s[i + k]];
      out.push(parseInt(bits, 2));
    }
    return Uint8Array.from(out);
  }

  /* =================== 11. Bubble Babble =================== */
  // 源自 OpenSSH sshkey.c / Digest::BubbleBabble；输出形如 xesef-disof-...-baxux
  const BB_V = 'aeiouy';
  const BB_C = 'bcdfghklmnprstvzx';   // 索引 16 = 'x'，用作末尾哨音

  function bubbleBabble(bytes) {
    const b = U.asBytes(bytes);
    const rounds = Math.floor(b.length / 2) + 1;
    let seed = 1, out = 'x';
    for (let i = 0; i < rounds; i++) {
      const p = 2 * i;
      let a, bb, c;
      if (p < b.length) {
        const x = b[p];
        a = (((x >> 6) & 3) + seed) % 6;
        bb = (x >> 2) & 15;
        c = ((x & 3) + Math.floor(seed / 6)) % 6;
      } else {
        a = seed % 6; bb = 16; c = Math.floor(seed / 6);
      }
      out += BB_V[a] + BB_C[bb] + BB_V[c];
      if (p + 1 < b.length) {
        const y = b[p + 1];
        out += BB_C[(y >> 4) & 15] + '-' + BB_C[y & 15];
        seed = (seed * 5 + b[p] * 7 + y) % 36;
      }
    }
    return out + 'x';
  }

  function bubbleBabbleDecode(str) {
    const s = String(str).trim();
    if (s.length < 2 || s[0] !== 'x' || s[s.length - 1] !== 'x') {
      throw new Error('Bubble Babble 必须以 x 开头结尾');
    }
    // 注意 '-' 夹在一对辅音中间（C-C），不能按 '-' 切词；须按 VCV[C-C] 位置推进
    const inner = s.slice(1, -1);
    const out = [];
    let seed = 1, p = 0;
    while (p + 3 <= inner.length) {
      const a = BB_V.indexOf(inner[p]);
      const bb = BB_C.indexOf(inner[p + 1]);
      const c = BB_V.indexOf(inner[p + 2]);
      if (a < 0 || bb < 0 || c < 0) throw new Error('非法 Bubble Babble 字符');
      p += 3;
      let y = -1;
      if (p + 2 < inner.length && inner[p + 1] === '-') {
        const d = BB_C.indexOf(inner[p]);
        const e = BB_C.indexOf(inner[p + 2]);
        if (d < 0 || e < 0) throw new Error('非法 Bubble Babble 字符');
        y = (d << 4) | e;
        p += 3;
      }
      if (bb === 16) {
        // 末尾哨音：只校验 seed，不产出字节
        if (a !== seed % 6 || c !== Math.floor(seed / 6)) throw new Error('Bubble Babble 校验失败');
        break;
      }
      // 由 a/c 反推字节高低位：a=((x>>6&3)+seed)%6，c=((x&3)+floor(seed/6))%6
      let hi = -1, lo = -1;
      for (let t = 0; t < 4; t++) if (((t + seed) % 6) === a) { hi = t; break; }
      for (let t = 0; t < 4; t++) if (((t + Math.floor(seed / 6)) % 6) === c) { lo = t; break; }
      if (hi < 0 || lo < 0) throw new Error('Bubble Babble 校验失败');
      const x = (hi << 6) | (bb << 2) | lo;
      out.push(x);
      if (y >= 0) { out.push(y); seed = (seed * 5 + x * 7 + y) % 36; }
    }
    return Uint8Array.from(out);
  }

  /* =================== 12. 敲敲码 / Tap Code =================== */
  // 5×5 方阵（I/J 同位）。分隔约定（避免歧义）：
  //   字母内 行/列 用 '/'  例 H(2,3) -> '../...'
  //   字母之间用空格；单词之间用 ' | '
  const TAP = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';

  function tapEncode(text) {
    return String(text).toUpperCase().split(/\s+/).filter(Boolean).map(word => {
      const letters = [];
      for (const ch of word) {
        const i = TAP.indexOf(ch === 'J' ? 'I' : ch);
        if (i < 0) continue;                       // 表外字符（数字、标点）跳过
        letters.push('.'.repeat(Math.floor(i / 5) + 1) + '/' + '.'.repeat((i % 5) + 1));
      }
      return letters.join(' ');
    }).filter(Boolean).join(' | ');
  }

  function tapDecode(text) {
    return String(text).split('|').map(word => {
      return word.trim().split(/\s+/).filter(Boolean).map(tok => {
        const parts = tok.split('/');
        if (parts.length !== 2) return '';
        const r = (parts[0].match(/\./g) || []).length - 1;
        const c = (parts[1].match(/\./g) || []).length - 1;
        if (r < 0 || r > 4 || c < 0 || c > 4) return '';
        return TAP[r * 5 + c];
      }).join('');
    }).join(' ').trim();
  }

  /* =================== 13. 北约音标字母 =================== */
  const NATO = {
    A: 'ALFA', B: 'BRAVO', C: 'CHARLIE', D: 'DELTA', E: 'ECHO', F: 'FOXTROT',
    G: 'GOLF', H: 'HOTEL', I: 'INDIA', J: 'JULIETT', K: 'KILO', L: 'LIMA',
    M: 'MIKE', N: 'NOVEMBER', O: 'OSCAR', P: 'PAPA', Q: 'QUEBEC', R: 'ROMEO',
    S: 'SIERRA', T: 'TANGO', U: 'UNIFORM', V: 'VICTOR', W: 'WHISKEY',
    X: 'XRAY', Y: 'YANKEE', Z: 'ZULU',
    '0': 'ZERO', '1': 'ONE', '2': 'TWO', '3': 'TREE', '4': 'FOWER',
    '5': 'FIFE', '6': 'SIX', '7': 'SEVEN', '8': 'AIT', '9': 'NINER'
  };
  const NATO_INV = (function () {
    const m = {};
    for (const k in NATO) m[NATO[k]] = k;
    return m;
  })();

  function natoEncode(text) {
    const out = [];
    for (const ch of String(text).toUpperCase()) {
      if (ch in NATO) out.push(NATO[ch]);
      else if (ch === ' ' || ch === '\n' || ch === '\t') out.push('');
      else out.push(ch);
    }
    return out.filter(x => x !== '' || true).join(' ').replace(/ {2,}/g, ' ').trim();
  }

  function natoDecode(text) {
    const toks = String(text).toUpperCase().split(/[\s,.;!?-]+/).filter(Boolean);
    let out = '';
    for (const t of toks) {
      if (t in NATO_INV) out += NATO_INV[t];
      else out += t.length === 1 ? t : '[' + t + ']';
    }
    return out;
  }

  /* =================== 14. T9 九宫格 =================== */
  const T9_MAP = {
    a: '2', b: '2', c: '2', d: '3', e: '3', f: '3',
    g: '4', h: '4', i: '4', j: '5', k: '5', l: '5',
    m: '6', n: '6', o: '6', p: '7', q: '7', r: '7', s: '7',
    t: '8', u: '8', v: '8', w: '9', x: '9', y: '9', z: '9',
    ' ': '0'
  };

  function t9Encode(text) {
    let out = '';
    for (const ch of String(text).toLowerCase()) if (ch in T9_MAP) out += T9_MAP[ch];
    return out;
  }

  // T9 不可逆，这里做「按键盘分组的候选展开」：给出每个数字串对应的字母集
  function t9Candidates(digits) {
    const G = { '2': 'ABC', '3': 'DEF', '4': 'GHI', '5': 'JKL', '6': 'MNO',
                '7': 'PQRS', '8': 'TUV', '9': 'WXYZ', '0': ' ' };
    return String(digits).split('').map(d => G[d] || '?');
  }

  /* =================== 工具表 =================== */
  // enc/dec 统一以「文本」为输入输出；字节型编码内部走 UTF-8
  const TOOLS = {
    'UUencode':        { enc: s => uuEncode(U.utf8Enc(s)),              dec: s => U.utf8Dec(uuDecode(s)) },
    'XXencode':        { enc: s => xxEncode(U.utf8Enc(s)),              dec: s => U.utf8Dec(xxDecode(s)) },
    'Ascii85':         { enc: s => a85Encode(U.utf8Enc(s)),             dec: s => U.utf8Dec(a85Decode(s)) },
    'Ascii85(Adobe)':  { enc: s => a85Encode(U.utf8Enc(s), { adobe: true }), dec: s => U.utf8Dec(a85Decode(s)) },
    'Ascii85(折叠空格)': { enc: s => a85Encode(U.utf8Enc(s), { foldspaces: true }), dec: s => U.utf8Dec(a85Decode(s)) },
    'Base92':          { enc: s => b92Encode(U.utf8Enc(s)),             dec: s => U.utf8Dec(b92Decode(s)) },
    'yEnc':            { enc: s => yEncEncode(U.utf8Enc(s)),            dec: s => U.utf8Dec(yEncDecode(s)) },
    'Punycode':        { enc: s => punycodeEncode(s),                   dec: s => punycodeDecode(s) },
    'IDNA 域名':       { enc: s => idnaEncode(s),                       dec: s => idnaDecode(s) },
    'EBCDIC':          { enc: s => ebcdicEncode(s),                     dec: s => ebcdicDecode(s) },
    'Hexdump':         { enc: s => hexdump(U.utf8Enc(s)),               dec: s => U.utf8Dec(hexdumpReverse(s)) },
    '盲文':            { enc: s => brailleEncode(s),                    dec: s => brailleDecode(s) },
    'DNA 编码':        { enc: s => dnaEncode(U.utf8Enc(s)),             dec: s => U.utf8Dec(dnaDecode(s)) },
    'BubbleBabble':    { enc: s => bubbleBabble(U.utf8Enc(s)),          dec: s => U.utf8Dec(bubbleBabbleDecode(s)) },
    '敲敲码':          { enc: s => tapEncode(s),                        dec: s => tapDecode(s) },
    '北约音标':        { enc: s => natoEncode(s),                       dec: s => natoDecode(s) },
    'T9 九宫格':       { enc: s => t9Encode(s),                         dec: s => t9Encode(s), selfInverse: false, oneWay: true }
  };

  return {
    uuEncode, uuDecode,
    xxEncode, xxDecode, XX_A,
    a85Encode, a85Decode,
    b92Encode, b92Decode, B92,
    yEncEncode, yEncDecode,
    punycodeEncode, punycodeDecode, idnaEncode, idnaDecode,
    ebcdicEncode, ebcdicDecode, E2A, A2E,
    hexdump, hexdumpReverse, hexdumpReverseLoose,
    brailleEncode, brailleDecode, BRAILLE,
    dnaEncode, dnaDecode,
    bubbleBabble, bubbleBabbleDecode,
    tapEncode, tapDecode,
    natoEncode, natoDecode, NATO,
    t9Encode, t9Candidates,
    TOOLS
  };
})();
