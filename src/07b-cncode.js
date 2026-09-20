/* ===========================================================================
 * 编码工具箱 · 中文趣味 / 网络流行编码层
 *   CT.cncode ——
 *     · 社会主义核心价值观编码（逐位对齐 sym233/core-values-encoder）
 *     · 与佛论禅「佛曰」V1 /「如是我闻」V2（复用已验证的 Buddha 核心）
 *     · Brainfuck 文本编译 + 解释器，以及 Ook! 互转
 *     · 零宽字符隐写
 *     · 八卦（八进制）/ 六十四卦（Base64）
 *     · 嗷呜（兽语）二进制编码
 * =========================================================================== */

CT.cncode = (function () {
  const U = CT.util;

  /* =============== 1. 社会主义核心价值观编码 =============== */
  //  原始实现：str → UTF-8 大写 hex → 十二进制（A~F 随机拆成两段）→ 24 字词库
  const CV_VALUES = '富强民主文明和谐自由平等公正法治爱国敬业诚信友善';

  /** 与原始实现 str2utf8 等价：UTF-8 字节的大写十六进制 */
  function str2utf8(str) {
    return U.hex(U.utf8Enc(String(str)), true).toUpperCase();
  }
  function utf82str(hex) {
    if (hex.length % 2) throw new Error('十六进制串长度必须是偶数');
    // 原实现逐对插 '%' 后交给 decodeURIComponent，这里等价地直接解字节
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    return U.utf8Dec(bytes, true);
  }
  /** hex 串 → 12 进制数组；random=false 时固定用 [10, n-10] 分支（可复现） */
  function hex2duo(hexs, random) {
    const duo = [];
    for (const c of hexs) {
      const n = parseInt(c, 16);
      if (isNaN(n)) continue;
      if (n < 10) duo.push(n);
      else if (random ? Math.random() >= 0.5 : true) { duo.push(10); duo.push(n - 10); }
      else { duo.push(11); duo.push(n - 6); }
    }
    return duo;
  }
  function duo2hex(duo) {
    const hex = [];
    let i = 0;
    while (i < duo.length) {
      if (duo[i] < 10) hex.push(duo[i].toString(16));
      else {
        if (i + 1 >= duo.length) throw new Error('十二进制序列末尾出现了不完整的 A~F 拆分');
        if (duo[i] === 10) { i++; hex.push((duo[i] + 10).toString(16)); }
        else { i++; hex.push((duo[i] + 6).toString(16)); }
      }
      i++;
    }
    return hex.join('').toUpperCase();
  }
  const duo2values = duo => duo.map(d => CV_VALUES[2 * d] + CV_VALUES[2 * d + 1]).join('');

  function coreValuesEncode(str, random) {
    return duo2values(hex2duo(str2utf8(str), random));
  }
  function coreValuesDecode(encoded) {
    const duo = [];
    for (const c of String(encoded)) {
      const i = CV_VALUES.indexOf(c);
      if (i === -1) continue;
      if (i & 1) continue;
      duo.push(i >> 1);
    }
    const hexs = duo2hex(duo);
    if (hexs.length & 1) throw new Error('解码得到的十六进制长度为奇数，密文可能不完整');
    return utf82str(hexs);
  }

  /* =============== 2. 与佛论禅 =============== */
  // 07a-buddha.js 是 UMD，会挂到全局；这里不要用同名局部变量遮蔽
  const Bud = (typeof Buddha !== 'undefined' && Buddha)
    ? Buddha
    : (typeof globalThis !== 'undefined' ? globalThis.Buddha : null);

  const buddha = {
    available: !!Bud,
    version: 2,
    encode(text, version) {
      if (!Bud) throw new Error('与佛论禅核心未加载');
      return Bud.encode(String(text), version || 2);
    },
    decode(text) {
      if (!Bud) throw new Error('与佛论禅核心未加载');
      return Bud.decode(String(text));
    },
    detect(text) { return Bud ? Bud.detect(String(text)) : 0; },
    core: Bud
  };

  /* =============== 3. Brainfuck / Ook! =============== */

  const BF_CHARS = '><+-.,[]';

  /** 文本 → Brainfuck 程序（按相邻字符差值走最短方向） */
  function bfEncode(text, options) {
    const bytes = U.utf8Enc(String(text));
    const opt = options || {};
    const width = opt.width || 256;          // 单元位宽（按字节取模）
    let out = '';
    let cur = 0;
    for (const b of bytes) {
      let diff = (b - cur + width) % width;
      if (diff <= width / 2) out += '+'.repeat(diff);
      else out += '-'.repeat(width - diff);
      out += '.';
      cur = b;
    }
    return out;
  }

  /** 执行 Brainfuck；返回输出文本 */
  function bfRun(code, input, options) {
    const opt = options || {};
    const limit = opt.limit || 2e7;
    const tapeSize = opt.tapeSize || 65536;
    const src = String(code).replace(/[^><+\-.,[\]]/g, '');
    const tape = new Uint8Array(tapeSize);
    const inputBytes = U.asBytes(input || new Uint8Array(0));
    const out = [];
    // 预编译跳转表
    const stack = [], jump = new Int32Array(src.length).fill(-1);
    for (let i = 0; i < src.length; i++) {
      if (src[i] === '[') stack.push(i);
      else if (src[i] === ']') {
        if (!stack.length) throw new Error('Brainfuck 括号不匹配：多余的 ]');
        const j = stack.pop();
        jump[i] = j; jump[j] = i;
      }
    }
    if (stack.length) throw new Error('Brainfuck 括号不匹配：缺少 ]');
    let p = 0, ip = 0, inPos = 0, steps = 0;
    while (ip < src.length) {
      if (++steps > limit) throw new Error('Brainfuck 执行步数超过上限 ' + limit + '（可能是死循环）');
      switch (src[ip]) {
        case '>': p = (p + 1) % tapeSize; break;
        case '<': p = (p - 1 + tapeSize) % tapeSize; break;
        case '+': tape[p] = (tape[p] + 1) & 0xff; break;
        case '-': tape[p] = (tape[p] - 1) & 0xff; break;
        case '.': out.push(tape[p]); break;
        case ',': tape[p] = inPos < inputBytes.length ? inputBytes[inPos++] : 0; break;
        case '[': if (tape[p] === 0) ip = jump[ip]; break;
        case ']': if (tape[p] !== 0) ip = jump[ip]; break;
      }
      ip++;
    }
    return Uint8Array.from(out);
  }
  const bfRunText = (code, input) => U.utf8Dec(bfRun(code, input ? U.utf8Enc(input) : new Uint8Array(0)));

  const OOK_MAP = [
    ['>', 'Ook. Ook?'], ['<', 'Ook? Ook.'],
    ['+', 'Ook. Ook.'], ['-', 'Ook! Ook!'],
    ['.', 'Ook! Ook.'], [',', 'Ook. Ook!'],
    ['[', 'Ook! Ook?'], [']', 'Ook? Ook!']
  ];
  function bfToOok(bf) {
    const map = {};
    for (const [cmd, ook] of OOK_MAP) map[cmd] = ook;
    const cmds = String(bf).replace(/[^><+\-.,[\]]/g, '').split('');
    if (cmds.length % 2) throw new Error('Ook! 需要成对出现，Brainfuck 指令数为奇数时无法转换');
    const parts = [];
    for (let i = 0; i < cmds.length; i += 2) parts.push(map[cmds[i]], map[cmds[i + 1]]);
    return parts.join(' ');
  }
  function ookToBf(ook) {
    const map = {};
    for (const [cmd, o] of OOK_MAP) map[o] = cmd;
    const tokens = String(ook).trim().split(/\s+/).filter(Boolean);
    if (tokens.length % 2) throw new Error('Ook! 指令必须成对出现');
    let out = '';
    for (let i = 0; i < tokens.length; i += 2) {
      const key = tokens[i] + ' ' + tokens[i + 1];
      const cmd = map[key];
      if (!cmd) throw new Error('无法识别的 Ook! 片段：' + key);
      out += cmd;
    }
    return out;
  }
  /** 文本 → Ook! 程序（经 Brainfuck 中转，指令数补一个空操作凑偶） */
  function textToOok(text) {
    let bf = bfEncode(text);
    if (bf.length % 2) bf += '+';      // 补一个不影响输出的 +
    return bfToOok(bf);
  }

  /* =============== 4. 零宽字符隐写 =============== */
  const ZW0 = '\u200b';   // ZERO WIDTH SPACE
  const ZW1 = '\u200c';   // ZERO WIDTH NON-JOINER
  const ZWS = '\u200d';   // ZERO WIDTH JOINER（作字节分隔）
  const ZWHEAD = '\ufeff';

  function zwEncode(text, options) {
    const opt = options || {};
    const bytes = U.utf8Enc(String(text));
    let out = opt.marker === false ? '' : ZWHEAD;
    for (const b of bytes) {
      for (let k = 7; k >= 0; k--) out += (b >> k) & 1 ? ZW1 : ZW0;
      out += ZWS;
    }
    return opt.marker === false ? out : out + ZWHEAD;
  }
  function zwDecode(text) {
    const s = String(text);
    let bits = '';
    const bytes = [];
    for (const ch of s) {
      if (ch === ZW0) bits += '0';
      else if (ch === ZW1) bits += '1';
      else if (ch === ZWS) {
        while (bits.length >= 8) { bytes.push(parseInt(bits.slice(0, 8), 2)); bits = bits.slice(8); }
        bits = '';
      }
    }
    while (bits.length >= 8) { bytes.push(parseInt(bits.slice(0, 8), 2)); bits = bits.slice(8); }
    return U.utf8Dec(Uint8Array.from(bytes), true);
  }
  const zwHide = (cover, secret, marker) => String(cover) + zwEncode(secret, { marker: marker !== false });
  const zwExtract = cover => zwDecode(String(cover).replace(/[^\u200b\u200c\u200d\ufeff]/g, ''));

  /* =============== 5. 八卦 / 六十四卦 =============== */
  const TRIGRAM = ['☰', '☱', '☲', '☳', '☴', '☵', '☶', '☷'];   // 乾兑离震巽坎艮坤
  const TRIGRAM_NAME = ['乾', '兑', '离', '震', '巽', '坎', '艮', '坤'];
  const hexagramChar = i => String.fromCharCode(0x4dc0 + i);      // ䷀… 文王卦序

  /** 八卦：UTF-8 字节 → 八进制 → 卦象 */
  function baguaEncode(text) {
    const bytes = U.utf8Enc(String(text));
    let out = '';
    for (const b of bytes) {
      out += TRIGRAM[(b >> 6) & 7] + TRIGRAM[(b >> 3) & 7] + TRIGRAM[b & 7];
    }
    return out;
  }
  function baguaDecode(s) {
    const src = String(s);
    const idx = [];
    for (const ch of src) {
      const i = TRIGRAM.indexOf(ch);
      if (i >= 0) idx.push(i);
      else {
        const j = TRIGRAM_NAME.indexOf(ch);
        if (j >= 0) idx.push(j);
      }
    }
    const full = idx.slice(0, idx.length - (idx.length % 3));
    const bytes = [];
    for (let i = 0; i < full.length; i += 3) {
      bytes.push(((full[i] << 6) | (full[i + 1] << 3) | full[i + 2]) & 0xff);
    }
    return U.utf8Dec(Uint8Array.from(bytes), true);
  }

  /** 六十四卦：UTF-8 字节流按 6 bit 分组 → 卦符 */
  function hexagramEncode(text) {
    const bytes = U.utf8Enc(String(text));
    let bits = '';
    for (const b of bytes) bits += b.toString(2).padStart(8, '0');
    const padLen = (6 - (bits.length % 6)) % 6;
    bits += '0'.repeat(padLen);
    let out = '';
    for (let i = 0; i < bits.length; i += 6) out += hexagramChar(parseInt(bits.slice(i, i + 6), 2));
    return out + (padLen ? ' ' + padLen : '');     // 末尾附上补位数
  }
  function hexagramDecode(s) {
    const src = String(s).trim();
    let padLen = 0;
    const m = /\s([0-5])$/.exec(src);
    let body = src;
    if (m) { padLen = +m[1]; body = src.slice(0, m.index); }
    let bits = '';
    for (const ch of body) {
      const cp = ch.codePointAt(0);
      if (cp >= 0x4dc0 && cp <= 0x4dff) bits += (cp - 0x4dc0).toString(2).padStart(6, '0');
    }
    if (padLen) bits = bits.slice(0, bits.length - padLen);
    bits = bits.slice(0, bits.length - (bits.length % 8));
    const bytes = [];
    for (let i = 0; i < bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
    return U.utf8Dec(Uint8Array.from(bytes), true);
  }

  /* =============== 6. 嗷呜（兽语） =============== */
  //  约定：按位编码，0 → 嗷，1 → 呜，字节之间用空格分隔（便于阅读）
  const BEAST0 = '嗷';
  const BEAST1 = '呜';
  function beastEncode(text, options) {
    const opt = options || {};
    const bytes = U.utf8Enc(String(text));
    const words = [];
    for (const b of bytes) {
      let w = '';
      for (let k = 7; k >= 0; k--) w += (b >> k) & 1 ? BEAST1 : BEAST0;
      words.push(w);
    }
    return words.join(opt.sep === undefined ? ' ' : opt.sep);
  }
  function beastDecode(s) {
    const src = String(s);
    let bits = '';
    for (const ch of src) {
      if (ch === BEAST0) bits += '0';
      else if (ch === BEAST1) bits += '1';
    }
    bits = bits.slice(0, bits.length - (bits.length % 8));
    const bytes = [];
    for (let i = 0; i < bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
    return U.utf8Dec(Uint8Array.from(bytes), true);
  }

  /* =============== 7. 统一入口 =============== */
  const TOOLS = {
    '核心价值观': {
      enc: (s, p) => coreValuesEncode(s, p && p.random),
      dec: s => coreValuesDecode(s),
      params: [{ k: 'random', label: '随机化 A~F 分支', type: 'bool', def: false }]
    },
    '与佛论禅': {
      enc: (s, p) => buddha.encode(s, p && p.version === 1 ? 1 : 2),
      dec: s => buddha.decode(s),
      params: [{ k: 'version', label: '1=佛曰 2=如是我闻', type: 'int', def: 2 }]
    },
    '文本转Ook': {
      enc: s => textToOok(s),
      dec: s => bfRunText(ookToBf(s))
    },
    '文本转BF': {
      enc: s => bfEncode(s),
      dec: s => bfRunText(s)
    },
    '零宽隐写': {
      enc: s => zwEncode(s),
      dec: s => zwExtract(s)
    },
    '八卦': {
      enc: s => baguaEncode(s),
      dec: s => baguaDecode(s)
    },
    '六十四卦': {
      enc: s => hexagramEncode(s),
      dec: s => hexagramDecode(s)
    },
    '嗷呜兽语': {
      enc: s => beastEncode(s),
      dec: s => beastDecode(s)
    }
  };

  return {
    CV_VALUES, coreValuesEncode, coreValuesDecode,
    str2utf8, utf82str, hex2duo, duo2hex, duo2values,
    buddha,
    BF_CHARS, bfEncode, bfRun, bfRunText, bfToOok, ookToBf, textToOok,
    zwEncode, zwDecode, zwHide, zwExtract, ZW0, ZW1, ZWS, ZWHEAD,
    TRIGRAM, TRIGRAM_NAME, baguaEncode, baguaDecode, hexagramEncode, hexagramDecode,
    beastEncode, beastDecode,
    TOOLS
  };
})();
