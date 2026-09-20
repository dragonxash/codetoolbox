/* ===========================================================================
 * 编码工具箱 · 实用工具层
 *   CT.misc ——
 *     转义类：URL、HTML 实体、Unicode 转义（\uXXXX / \u{XXXXX} / %uXXXX / U+XXXX）、
 *             Quoted-Printable、C 风格字符串转义
 *     进制类：任意 2~36 进制互转（BigInt）、文本 ↔ 二进制/八进制/十进制
 *     生成类：UUID（v1/v4/nil）、随机密码/随机串、时间戳
 *     文本类：统计、大小写、命名风格、行操作、反转、去重排序
 *     识别类：编码类型自动嗅探
 * =========================================================================== */

CT.misc = (function () {
  const U = CT.util;

  /* ======================= 随机源 ======================= */
  function randBytes(n) {
    const out = new Uint8Array(n);
    const g = (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues)
      ? globalThis.crypto : null;
    if (g) { g.getRandomValues(out); return out; }
    for (let i = 0; i < n; i++) out[i] = (Math.random() * 256) | 0;
    return out;
  }

  /* ======================= URL ======================= */
  const urlEncodeComponent = s => encodeURIComponent(String(s));
  const urlDecodeComponent = s => decodeURIComponent(String(s));
  const urlEncodeFull = s => encodeURI(String(s));
  const urlDecodeFull = s => decodeURI(String(s));
  /** 保留 + 号语义的 www-form 变体 */
  const formEncode = s => encodeURIComponent(String(s)).replace(/%20/g, '+');
  const formDecode = s => decodeURIComponent(String(s).replace(/\+/g, ' '));

  /* ======================= HTML 实体 ======================= */
  function htmlEncode(s, all) {
    const t = String(s);
    if (all) {
      let out = '';
      for (const ch of t) out += '&#' + ch.codePointAt(0) + ';';
      return out;
    }
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', ' ': '&nbsp;' };
    return t.replace(/[&<>"' ]/g, c => map[c]);
  }
  function htmlDecode(s) {
    return String(s)
      .replace(/&#x([0-9a-fA-F]+);/g, (m, h) => String.fromCodePoint(parseInt(h, 16)))
      .replace(/&#(\d+);/g, (m, d) => String.fromCodePoint(parseInt(d, 10)))
      .replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&apos;/g, "'")
      .replace(/&amp;/g, '&');
  }

  /* ======================= Unicode / 转义 ======================= */
  const escUnicode = s => Array.from(String(s)).map(c => {
    const cp = c.codePointAt(0);
    return cp <= 0xffff ? '\\u' + cp.toString(16).padStart(4, '0') : '\\u{' + cp.toString(16) + '}';
  }).join('');
  const unescUnicode = s => String(s)
    .replace(/\\u\{([0-9a-fA-F]+)\}/g, (m, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/\\u([0-9a-fA-F]{4})/g, (m, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/%u([0-9a-fA-F]{4})/g, (m, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/(?:U\+|u\+)([0-9a-fA-F]{4,6})/g, (m, h) => String.fromCodePoint(parseInt(h, 16)));
  const escC = s => String(s)
    .replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/\r/g, '\\r')
    .replace(/\t/g, '\\t').replace(/"/g, '\\"').replace(/'/g, "\\'")
    .replace(/[\u0000-\u001f\u007f]/g, c => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'));
  const unescC = s => String(s).replace(/\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|.)/g, (m, e) => {
    if (e[0] === 'x') return String.fromCharCode(parseInt(e.slice(1), 16));
    if (e[0] === 'u') return String.fromCharCode(parseInt(e.slice(1), 16));
    return { n: '\n', r: '\r', t: '\t', '0': '\0', b: '\b', f: '\f', v: '\v' }[e] || e;
  });

  /** Quoted-Printable（RFC 2045；换行统一用 \n，软换行在解码时会去掉） */
  function qpEncode(s, softBreak) {
    const bytes = U.utf8Enc(String(s));
    const limit = softBreak || 76;
    let out = '', lineLen = 0;
    const push = tok => {
      if (lineLen + tok.length > limit) { out += '=\n'; lineLen = 0; }
      out += tok; lineLen += tok.length;
    };
    for (const b of bytes) {
      if (b === 0x0a) { out += '\n'; lineLen = 0; continue; }
      const printable = (b >= 0x21 && b <= 0x7e && b !== 0x3d) || b === 0x20 || b === 0x09;
      if (printable) push(String.fromCharCode(b));
      else push('=' + b.toString(16).toUpperCase().padStart(2, '0'));
    }
    return out;
  }
  function qpDecode(s) {
    const t = String(s).replace(/=\r?\n/g, '').replace(/=([0-9a-fA-F]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16)));
    return U.utf8Dec(U.latin1Enc(t), true);
  }

  /* ======================= 进制 ======================= */
  const DIGITS = '0123456789abcdefghijklmnopqrstuvwxyz';

  function bigFromString(str, base) {
    const s = String(str).trim().toLowerCase().replace(/[\s_,]/g, '');
    if (!s) throw new Error('空字符串无法解析');
    let neg = false, t = s;
    if (t[0] === '-') { neg = true; t = t.slice(1); }
    if (t.slice(0, 2) === '0x' && base === 16) t = t.slice(2);
    if (!t.length) throw new Error('缺少数字位');
    let v = 0n;
    for (const ch of t) {
      const d = DIGITS.indexOf(ch);
      if (d < 0 || d >= base) throw new Error(`字符「${ch}」不是 ${base} 进制的合法数字`);
      v = v * BigInt(base) + BigInt(d);
    }
    return neg ? -v : v;
  }
  function bigToString(v, base, upper) {
    const neg = v < 0n;
    let x = neg ? -v : v;
    const B = BigInt(base);
    if (x === 0n) return '0';
    let out = '';
    while (x > 0n) { out = DIGITS[Number(x % B)] + out; x /= B; }
    if (upper) out = out.toUpperCase();
    return (neg ? '-' : '') + out;
  }
  /** 任意进制互转 */
  function convertBase(str, from, to, upper) {
    return bigToString(bigFromString(str, from), to, upper);
  }

  const textToBinary = (s, sep) => [...U.utf8Enc(String(s))].map(b => b.toString(2).padStart(8, '0')).join(sep === undefined ? ' ' : sep);
  const textToOctal  = (s, sep) => [...U.utf8Enc(String(s))].map(b => b.toString(8).padStart(3, '0')).join(sep === undefined ? ' ' : sep);
  const textToDecimal = (s, sep) => [...U.utf8Enc(String(s))].map(b => String(b)).join(sep === undefined ? ' ' : sep);
  function binaryToText(s) {
    const bits = String(s).replace(/[^01]/g, '');
    const out = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
    return U.utf8Dec(Uint8Array.from(out), true);
  }
  function octalToText(s) {
    const g = String(s).match(/\d{1,3}/g) || [];
    return U.utf8Dec(Uint8Array.from(g.map(x => parseInt(x, 8) & 0xff)), true);
  }
  function decimalToText(s) {
    const g = String(s).match(/\d{1,3}/g) || [];
    return U.utf8Dec(Uint8Array.from(g.map(x => parseInt(x, 10) & 0xff)), true);
  }
  /** 十进制大数 → 字节串（用于把超大整数还原成文本） */
  function bigIntToText(str) {
    let v = bigFromString(str, 10);
    if (v === 0n) return '\0';
    const bytes = [];
    while (v > 0n) { bytes.unshift(Number(v & 0xffn)); v >>= 8n; }
    return U.utf8Dec(Uint8Array.from(bytes), true);
  }

  /* ======================= 生成 ======================= */
  const hex2 = n => n.toString(16).padStart(2, '0');

  function uuidV4() {
    const b = randBytes(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = U.hex(b, false);
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }
  function uuidV1() {
    // 100 纳秒间隔从 1582-10-15 起算
    const GREG = 122192928000000000n;
    const now = BigInt(Date.now()) * 10000n + GREG;
    const timeLow = now & 0xffffffffn;
    const timeMid = (now >> 32n) & 0xffffn;
    const timeHi = ((now >> 48n) & 0x0fffn) | 0x1000n;
    const clockSeq = ((randBytes(2)[0] & 0x3f) << 8) | randBytes(1)[0];
    const node = randBytes(6);
    const g = (x, n) => x.toString(16).padStart(n, '0');
    return `${g(timeLow, 8)}-${g(timeMid, 4)}-${g(timeHi, 4)}-${g(clockSeq, 4)}-${U.hex(node, false)}`;
  }
  const uuidNil = () => '00000000-0000-0000-0000-000000000000';

  function randomString(len, charset) {
    const cs = charset || 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    if (!cs.length) throw new Error('字符集不能为空');
    const b = randBytes(len);
    let out = '';
    for (let i = 0; i < len; i++) out += cs[b[i] % cs.length];
    return out;
  }
  const CHARSETS = {
    '数字': '0123456789',
    '小写': 'abcdefghijklmnopqrstuvwxyz',
    '大写': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    '字母': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
    '字母数字': 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    '十六进制': '0123456789abcdef',
    'Base64': 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
    '可打印ASCII': Array.from({ length: 94 }, (_, i) => String.fromCharCode(33 + i)).join(''),
    '密码(无易混字符)': 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+'
  };

  function timestamp(ts, unit) {
    let ms;
    if (ts === undefined || ts === '' || ts === null) ms = Date.now();
    else {
      const n = Number(ts);
      if (isNaN(n)) { const d = new Date(ts); if (isNaN(d.getTime())) throw new Error('无法解析的时间：' + ts); ms = d.getTime(); }
      else {
        const u = unit || (String(ts).replace('-', '').length >= 13 ? 'ms' : 's');
        ms = u === 'ms' ? n : n * 1000;
      }
    }
    const d = new Date(ms);
    const p = (x, n) => String(x).padStart(n || 2, '0');
    const local = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
    return {
      ms, seconds: Math.floor(ms / 1000),
      local, iso: d.toISOString(),
      utc: d.toUTCString(),
      date: `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`,
      time: `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
    };
  }

  /* ======================= 文本处理 ======================= */
  function stats(s) {
    const t = String(s);
    const bytes = U.utf8Enc(t);
    let cjk = 0, ascii = 0, other = 0;
    for (const ch of t) {
      const cp = ch.codePointAt(0);
      if (cp >= 0x4e00 && cp <= 0x9fff) cjk++;
      else if (cp < 128) ascii++;
      else other++;
    }
    return {
      chars: Array.from(t).length,
      bytes: bytes.length,
      lines: t === '' ? 0 : t.split(/\r\n|\r|\n/).length,
      words: (t.match(/[A-Za-z0-9_\u4e00-\u9fff]+/g) || []).length,
      cjk, ascii, other,
      hasNonAscii: bytes.some(b => b > 127)
    };
  }

  const toUpper = s => String(s).toUpperCase();
  const toLower = s => String(s).toLowerCase();
  const swapCase = s => String(s).replace(/[A-Za-z]/g, c => c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase());
  const reverse = s => Array.from(String(s)).reverse().join('');
  const reverseLines = s => String(s).split(/\r?\n/).reverse().join('\n');
  const sortLines = s => String(s).split(/\r?\n/).sort().join('\n');
  const uniqueLines = s => Array.from(new Set(String(s).split(/\r?\n/))).join('\n');
  const trimLines = s => String(s).split(/\r?\n/).map(x => x.trim()).join('\n');
  const removeEmptyLines = s => String(s).split(/\r?\n/).filter(x => x.trim() !== '').join('\n');
  function numberLines(s, start, sep) {
    const st = start || 1, sp = sep === undefined ? '. ' : sep;
    return String(s).split(/\r?\n/).map((x, i) => (st + i) + sp + x).join('\n');
  }
  function stripNumbering(s) {
    return String(s).split(/\r?\n/).map(x => x.replace(/^\s*\d+\s*[.、:)\]]?\s*/, '')).join('\n');
  }
  const removeWhitespace = s => String(s).replace(/\s+/g, '');
  const collapseSpaces = s => String(s).replace(/[ \t]+/g, ' ').trim();
  /** 命名风格转换 */
  function toNaming(s, style) {
    const words = String(s)
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
      .replace(/[_\-.\s]+/g, ' ')
      .trim().toLowerCase().split(/\s+/).filter(Boolean);
    const cap = w => w.charAt(0).toUpperCase() + w.slice(1);
    switch (style) {
      case 'camel': return words.map((w, i) => i ? cap(w) : w).join('');
      case 'pascal': return words.map(cap).join('');
      case 'snake': return words.join('_');
      case 'constant': return words.join('_').toUpperCase();
      case 'kebab': return words.join('-');
      case 'dot': return words.join('.');
      case 'title': return words.map(cap).join(' ');
      case 'upper': return words.join(' ').toUpperCase();
      default: return words.join(' ');
    }
  }

  /* ======================= 编码嗅探 ======================= */
  function detect(text) {
    const t = String(text).trim();
    const hits = [];
    const add = (name, conf, note) => hits.push({ name, conf, note: note || '' });

    if (!t) return hits;

    // 中文趣味
    if (/[富强民主文明和谐自由平等公正法治爱国敬业诚信友善]{4,}/.test(t) &&
        [...t].every(c => CT.cncode.CV_VALUES.includes(c) || /\s/.test(c))) add('核心价值观', 0.95);
    if (/^佛曰[:：]/.test(t)) add('与佛论禅 V1（佛曰）', 0.99);
    if (/^如是我闻[:：]/.test(t)) add('与佛论禅 V2（如是我闻）', 0.99);
    if (/^[\u200b\u200c\u200d\ufeff]+$/.test(t)) add('零宽字符隐写', 0.99);
    if (/^[嗷呜\s]+$/.test(t) && /[嗷呜]/.test(t)) add('嗷呜（兽语）', 0.9);
    if (/^[☰☱☲☳☴☵☶☷\s]+$/.test(t)) add('八卦', 0.95);
    if (/^[\u4dc0-\u4dff\s0-5]+$/.test(t) && /[\u4dc0-\u4dff]/.test(t)) add('六十四卦', 0.95);
    if (/^(Ook[.!?]\s*)+$/.test(t)) add('Ook!', 0.99);
    if (/^[><+\-.,\[\]\s]+$/.test(t) && /[<>+\-.,\[\]]/.test(t)) add('Brainfuck', 0.8);
    if (/^[┌┬┐├┼┤└┴┘◤◥◣◢\u0323\s]+$/.test(t)) add('猪圈密码', 0.9);
    if (/^[.\-/\s]+$/.test(t) && /[.-]/.test(t)) add('摩斯电码', 0.85);
    if (/^\s*(?:\d{1,2}[\s\-]+){3,}\d{1,2}\s*$/.test(t)) add('A1Z26 / 数字串', 0.6);
    if (/^[ABab\s]{10,}$/.test(t)) add('培根密码', 0.7);
    if (/^[\d\s]{10,}$/.test(t) && /[12]\d?\s/.test(t)) add('Polybius 坐标', 0.4);

    // 通用编码
    if (/^[0-9a-fA-F\s]+$/.test(t) && t.replace(/\s/g, '').length % 2 === 0 && t.replace(/\s/g, '').length >= 4)
      add('十六进制', 0.85);
    if (/^[01\s]+$/.test(t) && t.replace(/\s/g, '').length >= 8 && t.replace(/\s/g, '').length % 8 === 0)
      add('二进制', 0.9);
    if (/^[0-7\s]+$/.test(t) && t.replace(/\s/g,'').length >= 3 && t.replace(/\s/g,'').length % 3 === 0)
      add('八进制', 0.5);
    if (/^[A-Z2-7=\s]+$/i.test(t) && t.replace(/[\s=]/g, '').length % 8 === 0 && t.replace(/[\s=]/g,'').length >= 8)
      add('Base32', 0.6);
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(t.replace(/\s/g, '')) && t.replace(/\s/g,'').length % 4 === 0 && t.replace(/\s/g,'').length >= 8)
      add('Base64', 0.7);
    if (/^[A-Za-z0-9\-_]+={0,2}$/.test(t.replace(/\s/g, '')) && /[-_]/.test(t)) add('Base64URL', 0.6);
    if (/^[1-9A-HJ-NP-Za-km-z]+$/.test(t) && t.length >= 6) add('Base58 / Base58Check', 0.5);
    if (/^[!-u]+$/.test(t) && /[z~]/.test(t)) add('Base85 / Base91', 0.4);
    if (/^[\u4e00-\u9fff]{2,}$/.test(t) && t.length % 2 === 0 && [...t].every(c => CT.cncode.CV_VALUES.includes(c) || true)) {
      // 已在上方判定核心价值观
    }
    if (/^(?:\{[\s\S]*\}|\[[\s\S]*\])$/.test(t)) {
      try { JSON.parse(t); add('JSON', 0.95); } catch (e) { /* ignore */ }
    }
    if (/%[0-9a-fA-F]{2}/.test(t)) add('URL 编码', 0.85);
    if (/&#\d+;|&[a-z]+;/.test(t)) add('HTML 实体', 0.85);
    if (/\\u[0-9a-fA-F]{4}/.test(t)) add('Unicode 转义', 0.9);
    if (/=\r?\n|=[0-9A-F]{2}/.test(t)) add('Quoted-Printable', 0.5);
    if (/^[a-zA-Z0-9+/]{100,}$/.test(t.replace(/\s/g, ''))) add('可能是压缩/加密数据', 0.3);
    // 时间戳
    if (/^\d{10}$/.test(t)) add('Unix 时间戳（秒）', 0.8);
    if (/^\d{13}$/.test(t)) add('Unix 时间戳（毫秒）', 0.8);
    // 哈希
    const hexOnly = /^[0-9a-fA-F]+$/.test(t);
    if (hexOnly) {
      const map = { 32: 'MD5 / MD4 / NT-Hash（16 字节）', 40: 'SHA-1（20 字节）', 56: 'SHA-224', 64: 'SHA-256 / SM3 / Keccak-256', 96: 'SHA-384', 128: 'SHA-512 / Keccak-512', 8: 'CRC-32', 16: 'CRC-64 / xxHash64 / FNV-1a-64' };
      if (map[t.length]) add('哈希值：' + map[t.length], 0.85);
    }
    // UUID
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(t)) add('UUID', 0.99);

    return hits.sort((a, b) => b.conf - a.conf);
  }

  /* ======================= 统一入口 ======================= */
  const TOOLS = {
    'URL 编码':        { enc: s => urlEncodeComponent(s), dec: s => urlDecodeComponent(s) },
    'URL 编码(整体)':  { enc: s => urlEncodeFull(s),      dec: s => urlDecodeFull(s) },
    '表单编码':        { enc: s => formEncode(s),         dec: s => formDecode(s) },
    'HTML 实体':       { enc: s => htmlEncode(s, false),  dec: s => htmlDecode(s) },
    'HTML 实体(全)':   { enc: s => htmlEncode(s, true),   dec: s => htmlDecode(s) },
    'Unicode 转义':    { enc: s => escUnicode(s),         dec: s => unescUnicode(s) },
    'C 风格转义':      { enc: s => escC(s),               dec: s => unescC(s) },
    'Quoted-Printable':{ enc: s => qpEncode(s),           dec: s => qpDecode(s) },
    '文本→二进制':     { enc: s => textToBinary(s),       dec: s => binaryToText(s) },
    '文本→八进制':     { enc: s => textToOctal(s),        dec: s => octalToText(s) },
    '文本→十进制':     { enc: s => textToDecimal(s),      dec: s => decimalToText(s) },
    '进制互转': {
      enc: (s, p) => convertBase(s, (p && p.from) || 10, (p && p.to) || 16, p && p.upper),
      dec: (s, p) => convertBase(s, (p && p.to) || 16, (p && p.from) || 10, false),
      params: [{ k: 'from', label: '源进制', type: 'int', def: 10 }, { k: 'to', label: '目标进制', type: 'int', def: 16 }],
      numeric: true
    },
    '反转':            { enc: s => reverse(s),            dec: s => reverse(s), selfInverse: true },
    '大小写反转':      { enc: s => swapCase(s),           dec: s => swapCase(s), selfInverse: true }
  };

  return {
    randBytes,
    urlEncodeComponent, urlDecodeComponent, urlEncodeFull, urlDecodeFull, formEncode, formDecode,
    htmlEncode, htmlDecode,
    escUnicode, unescUnicode, escC, unescC, qpEncode, qpDecode,
    DIGITS, bigFromString, bigToString, convertBase,
    textToBinary, textToOctal, textToDecimal, binaryToText, octalToText, decimalToText, bigIntToText,
    uuidV4, uuidV1, uuidNil, randomString, CHARSETS, timestamp,
    stats, toUpper, toLower, swapCase, reverse, reverseLines, sortLines, uniqueLines,
    trimLines, removeEmptyLines, numberLines, stripNumbering, removeWhitespace, collapseSpaces, toNaming,
    detect, TOOLS
  };
})();
