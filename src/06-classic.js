/* ===========================================================================
 * 编码工具箱 · 古典密码层
 *   CT.classic —— CTF / 逆向常见的一整套经典密码
 *     位移类：凯撒（含 25 位移爆破）、ROT5/ROT13/ROT18/ROT47、Atbash、
 *             仿射（含爆破）、QWERTY 键盘位移
 *     多表类：维吉尼亚（含自动密钥 / Beaufort / 变体 Beaufort / Gronsfeld）、Porta
 *     置换类：栅栏（锯齿型 / 分组型，含爆破）、列移位（含爆破）
 *     方块类：Playfair、Polybius、Bifid、Hill 2×2 / 3×3、猪圈
 *     符号类：摩斯电码、A1Z26、培根（含 24/26 字母表与载体隐写）、
 *             简单替换（密钥字母表）、ADFGX/ADFGVX
 * =========================================================================== */

CT.classic = (function () {
  const U = CT.util;

  const isUpper = c => c >= 'A' && c <= 'Z';
  const isLower = c => c >= 'a' && c <= 'z';
  const isAlpha = c => isUpper(c) || isLower(c);
  const keep = (c, base) => String.fromCharCode(base + c);

  /* ======================= 位移类 ======================= */

  function rot5(s) {
    return String(s).replace(/[0-9]/g, c => String.fromCharCode(48 + (c.charCodeAt(0) - 48 + 5) % 10));
  }
  function rot13(s) {
    return String(s).replace(/[A-Za-z]/g, c => {
      const b = isUpper(c) ? 65 : 97;
      return String.fromCharCode(b + (c.charCodeAt(0) - b + 13) % 26);
    });
  }
  const rot18 = s => rot13(rot5(s));
  function rot47(s) {
    return String(s).replace(/[!-~]/g, c => String.fromCharCode(33 + (c.charCodeAt(0) - 33 + 47) % 94));
  }

  /** 凯撒位移，shift 可正可负；只动字母，保留大小写 */
  function caesar(s, shift) {
    shift = ((shift % 26) + 26) % 26;
    return String(s).replace(/[A-Za-z]/g, c => {
      const b = isUpper(c) ? 65 : 97;
      return String.fromCharCode(b + (c.charCodeAt(0) - b + shift) % 26);
    });
  }
  /** 返回 1..25 全部位移结果 */
  function caesarBrute(s) {
    const out = [];
    for (let k = 1; k <= 25; k++) out.push({ shift: k, text: caesar(s, k) });
    return out;
  }

  function atbash(s) {
    return String(s).replace(/[A-Za-z]/g, c => {
      const b = isUpper(c) ? 65 : 97;
      return String.fromCharCode(b + 25 - (c.charCodeAt(0) - b));
    });
  }

  /** 仿射：E(x) = (a·x + b) mod 26，a 必须与 26 互素 */
  function affine(s, a, b) {
    a = ((a % 26) + 26) % 26; b = ((b % 26) + 26) % 26;
    if (gcd(a, 26) !== 1) throw new Error('仿射密码要求 a 与 26 互素，当前 a=' + a);
    return String(s).replace(/[A-Za-z]/g, c => {
      const base = isUpper(c) ? 65 : 97;
      const x = c.charCodeAt(0) - base;
      return String.fromCharCode(base + (a * x + b) % 26);
    });
  }
  function affineDecode(s, a, b) {
    a = ((a % 26) + 26) % 26; b = ((b % 26) + 26) % 26;
    const ai = modInv(a, 26);
    return String(s).replace(/[A-Za-z]/g, c => {
      const base = isUpper(c) ? 65 : 97;
      const y = c.charCodeAt(0) - base;
      return String.fromCharCode(base + (((y - b) % 26 + 26) % 26 * ai) % 26);
    });
  }
  /** a 取遍 12 个可逆值 × b 取遍 26 的 312 种组合（按解密方向尝试） */
  function affineBrute(s) {
    const out = [];
    for (let a = 0; a < 26; a++) {
      if (gcd(a, 26) !== 1) continue;
      for (let b = 0; b < 26; b++) out.push({ a, b, text: affineDecode(s, a, b) });
    }
    return out;
  }

  const QWERTY = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
  /** QWERTY 键盘左右位移：dir = -1 左移，1 右移 */
  function keyboardShift(s, dir) {
    const map = {};
    for (const row of QWERTY) {
      for (let i = 0; i < row.length; i++) {
        const j = i + dir;
        if (j >= 0 && j < row.length) {
          map[row[i]] = row[j];
          map[row[i].toUpperCase()] = row[j].toUpperCase();
        }
      }
    }
    return String(s).replace(/[a-zA-Z]/g, c => map[c] || c);
  }

  /* ======================= 多表类 ======================= */

  const letters = s => String(s).replace(/[^A-Za-z]/g, '').toUpperCase();

  function vigenereShift(cipher, s, key, mode) {
    const k = letters(key);
    if (!k.length) throw new Error('维吉尼亚/博福特需要一个含字母的密钥');
    let ki = 0;
    return String(s).replace(/[A-Za-z]/g, c => {
      const base = isUpper(c) ? 65 : 97;
      const p = c.charCodeAt(0) - base;
      const kv = k.charCodeAt(ki++ % k.length) - 65;
      let v;
      if (mode === 'vigenere')      v = (p + kv) % 26;
      else if (mode === 'beaufort') v = ((kv - p) % 26 + 26) % 26;
      else                          v = ((p - kv) % 26 + 26) % 26;   // variant beaufort
      return String.fromCharCode(base + v);
    });
  }
  const vigenere        = (s, key) => vigenereShift('enc', s, key, 'vigenere');
  const vigenereDecode  = (s, key) => vigenereShift('dec', s, key, 'variant');
  const beaufort        = (s, key) => vigenereShift('enc', s, key, 'beaufort');
  const beaufortDecode  = (s, key) => vigenereShift('dec', s, key, 'beaufort');
  const variantBeaufort = (s, key) => vigenereShift('enc', s, key, 'variant');
  const variantBeaufortDecode = (s, key) => vigenereShift('dec', s, key, 'vigenere');

  /** 自动密钥（Autokey）：密钥 + 明文自身 */
  function autokey(s, key, decrypt) {
    const k0 = letters(key);
    if (!k0.length) throw new Error('自动密钥需要一个含字母的密钥');
    const src = String(s);
    const plain = decrypt ? null : letters(src);
    const stream = k0.split('');
    const out = [];
    let li = 0;
    for (const c of src) {
      if (!isAlpha(c)) { out.push(c); continue; }
      const base = isUpper(c) ? 65 : 97;
      const v = c.charCodeAt(0) - base;
      const kv = stream[li].charCodeAt(0) - 65;
      let r;
      if (!decrypt) { r = (v + kv) % 26; stream.push(String.fromCharCode(65 + v)); }
      else { r = ((v - kv) % 26 + 26) % 26; stream.push(String.fromCharCode(65 + r)); }
      out.push(String.fromCharCode(base + r));
      li++;
    }
    return out.join('');
  }
  const autokeyEncode = (s, key) => autokey(s, key, false);
  const autokeyDecode = (s, key) => autokey(s, key, true);

  /** Gronsfeld：数字密钥 0~9 */
  function gronsfeld(s, digits) {
    const d = String(digits).replace(/\D/g, '');
    if (!d.length) throw new Error('Gronsfeld 需要数字密钥');
    let i = 0;
    return String(s).replace(/[A-Za-z]/g, c => {
      const base = isUpper(c) ? 65 : 97;
      return String.fromCharCode(base + (c.charCodeAt(0) - base + (+d[i++ % d.length])) % 26);
    });
  }
  function gronsfeldDecode(s, digits) {
    const d = String(digits).replace(/\D/g, '');
    if (!d.length) throw new Error('Gronsfeld 需要数字密钥');
    let i = 0;
    return String(s).replace(/[A-Za-z]/g, c => {
      const base = isUpper(c) ? 65 : 97;
      return String.fromCharCode(base + ((c.charCodeAt(0) - base - (+d[i++ % d.length])) % 26 + 26) % 26);
    });
  }

  /**
   * Porta 码表（13 行，每行都是对合置换）。
   * 构造规则（与标准表逐行一致）：
   *   i = 1..13，第一段取 12+i..25，中段为 13..11+i 与 13-i+1..12，
   *   末段取 0..13-i。三种段长相加恒为 26。
   */
  const PORTA = (function () {
    const rows = [];
    for (let i = 1; i <= 13; i++) {
      const row = [];
      for (let v = 12 + i; v <= 25; v++) row.push(v);
      for (let v = 13; v <= 11 + i; v++) row.push(v);
      for (let v = 13 - i + 1; v <= 12; v++) row.push(v);
      for (let v = 0; v <= 13 - i; v++) row.push(v);
      rows.push(row);
    }
    return rows;
  })();

  function porta(s, key) {
    const k = letters(key);
    if (!k.length) throw new Error('Porta 需要一个含字母的密钥');
    let ki = 0, out = '';
    for (const c of String(s)) {
      if (!isAlpha(c)) { out += c; continue; }
      const base = isUpper(c) ? 65 : 97;
      const p = c.charCodeAt(0) - base;
      const half = (k.charCodeAt(ki++ % k.length) - 65) >> 1;   // 0..12，A/B→0, C/D→1 ...
      out += String.fromCharCode(base + PORTA[half][p]);
    }
    return out;
  }

  /* ======================= 置换类 ======================= */

  /** 锯齿型栅栏（标准）：明文按 Z 字写下，按行读出 */
  function railFenceEncode(s, rails) {
    rails = Math.max(2, rails | 0);
    const t = String(s);
    if (rails >= t.length) return t;
    const rows = Array.from({ length: rails }, () => []);
    let r = 0, dir = 1;
    for (const c of t) {
      rows[r].push(c);
      if (r === 0) dir = 1; else if (r === rails - 1) dir = -1;
      r += dir;
    }
    return rows.map(x => x.join('')).join('');
  }
  function railFenceDecode(s, rails) {
    rails = Math.max(2, rails | 0);
    const t = String(s);
    if (rails >= t.length) return t;
    // 求每行字符数
    const counts = new Array(rails).fill(0);
    let r = 0, dir = 1;
    for (let i = 0; i < t.length; i++) {
      counts[r]++;
      if (r === 0) dir = 1; else if (r === rails - 1) dir = -1;
      r += dir;
    }
    const rows = [];
    let p = 0;
    for (let i = 0; i < rails; i++) { rows.push(t.slice(p, p + counts[i]).split('')); p += counts[i]; }
    const idx = new Array(rails).fill(0);
    let out = '';
    r = 0; dir = 1;
    for (let i = 0; i < t.length; i++) {
      out += rows[r][idx[r]++];
      if (r === 0) dir = 1; else if (r === rails - 1) dir = -1;
      r += dir;
    }
    return out;
  }
  /** 中国 CTF 常见的「简单栅栏」：按 rails 切成等长块后逐列读出 */
  function railFenceSimpleEncode(s, rails) {
    rails = Math.max(2, rails | 0);
    const t = String(s);
    const per = Math.ceil(t.length / rails);
    const rows = [];
    for (let i = 0; i < rails; i++) rows.push(t.slice(i * per, (i + 1) * per));
    let out = '';
    for (let c = 0; c < per; c++) for (const row of rows) if (c < row.length) out += row[c];
    return out;
  }
  function railFenceSimpleDecode(s, rails) {
    rails = Math.max(2, rails | 0);
    const t = String(s);
    const per = Math.ceil(t.length / rails);
    const rows = Array.from({ length: rails }, () => []);
    let p = 0;
    for (let c = 0; c < per; c++) {
      for (let r = 0; r < rails; r++) {
        if (r * per + c < t.length) rows[r][c] = t[p++];
      }
    }
    return rows.map(row => row.join('')).join('');
  }
  function railFenceBrute(s, maxRails) {
    maxRails = maxRails || Math.min(12, String(s).length);
    const out = [];
    for (let r = 2; r <= maxRails; r++) {
      out.push({ rails: r, text: railFenceDecode(s, r) });
      out.push({ rails: r, text: railFenceSimpleDecode(s, r), simple: true });
    }
    return out;
  }

  /** 列移位：E = 按密钥字母序读出各列 */
  function colOrder(key) {
    const k = String(key);
    const idx = Array.from({ length: k.length }, (_, i) => i);
    idx.sort((a, b) => {
      const x = k.charCodeAt(a), y = k.charCodeAt(b);
      return x === y ? a - b : x - y;
    });
    return idx;
  }
  function columnarEncode(s, key) {
    const t = String(s);
    const n = String(key).length;
    if (!n) throw new Error('列移位需要密钥');
    const rows = Math.ceil(t.length / n);
    const grid = Array.from({ length: rows }, () => new Array(n).fill(''));
    for (let i = 0; i < t.length; i++) grid[(i / n) | 0][i % n] = t[i];
    const order = colOrder(key);
    let out = '';
    for (const c of order) for (let r = 0; r < rows; r++) out += grid[r][c];
    return out;
  }
  /** 按给定列序把密文还原成原始顺序（order = 各列被读出的次序） */
  function columnarDecodeWithOrder(s, order) {
    const t = String(s);
    const n = order.length;
    const rows = Math.ceil(t.length / n);
    const grid = Array.from({ length: rows }, () => new Array(n).fill(''));
    let p = 0;
    for (const c of order) {
      for (let r = 0; r < rows; r++) {
        if (r * n + c < t.length) grid[r][c] = t[p++];
      }
    }
    let out = '';
    for (let r = 0; r < rows; r++) for (let c = 0; c < n; c++) if (grid[r][c]) out += grid[r][c];
    return out;
  }
  function columnarDecode(s, key) {
    return columnarDecodeWithOrder(s, colOrder(key));
  }
  const columnarBrute = (s, maxKeyLen) => {
    maxKeyLen = maxKeyLen || 7;
    const out = [];
    for (let n = 2; n <= maxKeyLen; n++) {
      // 枚举 n! 种列读取次序
      const perms = [];
      const used = new Array(n).fill(false);
      const rec = cur => {
        if (cur.length === n) { perms.push(cur.slice()); return; }
        for (let i = 0; i < n; i++) if (!used[i]) { used[i] = true; cur.push(i); rec(cur); cur.pop(); used[i] = false; }
      };
      rec([]);
      for (const p of perms) out.push({ len: n, order: p.join('-'), text: columnarDecodeWithOrder(s, p) });
    }
    return out;
  };

  /* ======================= 方块类 ======================= */

  const ALPHA25 = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';   // 5×5 合并 I/J

  function square5(key) {
    const seen = new Set();
    let s = '';
    for (const c of (letters(key) + ALPHA25)) {
      if (!seen.has(c)) { seen.add(c); s += c; }
    }
    return s.slice(0, 25);
  }
  const pos5 = (sq, ch) => {
    const i = sq.indexOf(ch === 'J' ? 'I' : ch);
    return [Math.floor(i / 5), i % 5];
  };

  function playfair(s, key, decrypt) {
    const sq = square5(key);
    const t = letters(s);
    if (decrypt) {
      if (t.length % 2) throw new Error('Playfair 密文长度必须为偶数，当前 ' + t.length);
      let out = '';
      for (let i = 0; i < t.length; i += 2) {
        const [r1, c1] = pos5(sq, t[i]);
        const [r2, c2] = pos5(sq, t[i + 1]);
        if (r1 === r2) {
          out += sq[r1 * 5 + (c1 + 4) % 5] + sq[r2 * 5 + (c2 + 4) % 5];
        } else if (c1 === c2) {
          out += sq[((r1 + 4) % 5) * 5 + c1] + sq[((r2 + 4) % 5) * 5 + c2];
        } else {
          out += sq[r1 * 5 + c2] + sq[r2 * 5 + c1];
        }
      }
      return out;
    }
    // 加密：按指针推进配对，同字母对之间插入填充 X，末尾奇数补 X
    let p = '';
    for (let i = 0; i < t.length;) {
      const a = t[i];
      if (i + 1 >= t.length) { p += a + 'X'; i += 1; }
      else if (t[i + 1] === a) { p += a + 'X'; i += 1; }
      else { p += a + t[i + 1]; i += 2; }
    }
    let out = '';
    for (let i = 0; i < p.length; i += 2) {
      const [r1, c1] = pos5(sq, p[i]);
      const [r2, c2] = pos5(sq, p[i + 1]);
      if (r1 === r2) {
        out += sq[r1 * 5 + (c1 + 1) % 5] + sq[r2 * 5 + (c2 + 1) % 5];
      } else if (c1 === c2) {
        out += sq[((r1 + 1) % 5) * 5 + c1] + sq[((r2 + 1) % 5) * 5 + c2];
      } else {
        out += sq[r1 * 5 + c2] + sq[r2 * 5 + c1];
      }
    }
    return out;
  }
  const playfairEncode = (s, key) => playfair(s, key, false);
  const playfairDecode = (s, key) => playfair(s, key, true);

  function polybius(s, key, decrypt) {
    if (!decrypt) {
      const t = letters(s);
      let out = [];
      for (const c of t) {
        const [r, c2] = pos5(ALPHA25, c);
        out.push(String(r + 1) + String(c2 + 1));
      }
      return out.join(' ');
    }
    const nums = String(s).replace(/[^0-9]/g, '');
    let out = '';
    for (let i = 0; i + 1 < nums.length; i += 2) {
      const r = +nums[i] - 1, c = +nums[i + 1] - 1;
      if (r < 0 || r > 4 || c < 0 || c > 4) throw new Error('Polybius 坐标越界：' + nums.slice(i, i + 2));
      out += ALPHA25[r * 5 + c];
    }
    return out;
  }

  /** Bifid：坐标先「先全部行、后全部列」串联，再两两一组还原为密文 */
  function bifid(s, period, decrypt) {
    const t = letters(s);
    const p = Math.max(1, period || t.length);
    let out = '';
    for (let off = 0; off < t.length; off += p) {
      const chunk = t.slice(off, off + p);
      const k = chunk.length;
      const rs = [], cs = [];
      for (const c of chunk) { const [r, cc] = pos5(ALPHA25, c); rs.push(r); cs.push(cc); }
      if (!decrypt) {
        const seq = rs.concat(cs);                      // 行在前、列在后
        for (let i = 0; i + 1 < seq.length; i += 2) out += ALPHA25[seq[i] * 5 + seq[i + 1]];
      } else {
        // 密文坐标先交错摊平，前一半是明文行、后一半是明文列
        const flat = [];
        for (let i = 0; i < k; i++) { flat.push(rs[i], cs[i]); }
        const pr = flat.slice(0, k), pc = flat.slice(k);
        for (let i = 0; i < k; i++) out += ALPHA25[pr[i] * 5 + pc[i]];
      }
    }
    return out;
  }
  const bifidEncode = (s, period) => bifid(s, period, false);
  const bifidDecode = (s, period) => bifid(s, period, true);

  /* ---- Hill 密码（Z26） ---- */
  function hillMatrix(key, n) {
    // key 为 n×n 个字母（按行）
    const k = letters(key);
    if (k.length < n * n) throw new Error(`Hill ${n}×${n} 需要 ${n * n} 个字母作密钥`);
    const m = [];
    for (let i = 0; i < n; i++) {
      const row = [];
      for (let j = 0; j < n; j++) row.push(k.charCodeAt(i * n + j) - 65);
      m.push(row);
    }
    return m;
  }
  function detMod(m) {
    const n = m.length;
    if (n === 1) return ((m[0][0] % 26) + 26) % 26;
    if (n === 2) return (((m[0][0] * m[1][1] - m[0][1] * m[1][0]) % 26) + 26) % 26;
    let d = 0;
    const cols = [[1, 2], [0, 2], [0, 1]];
    for (let c = 0; c < 3; c++) {
      const [c0, c1] = cols[c];
      const sub = m[1][c0] * m[2][c1] - m[1][c1] * m[2][c0];
      d += (c % 2 ? -1 : 1) * m[0][c] * sub;
    }
    return ((d % 26) + 26) % 26;
  }
  function invModMatrix(m) {
    const n = m.length;
    const det = detMod(m);
    const di = modInv(det, 26);
    if (n === 2) {
      return [[m[1][1] * di % 26, (-m[0][1] * di % 26 + 26 * 26) % 26],
              [(-m[1][0] * di % 26 + 26 * 26) % 26, m[0][0] * di % 26]];
    }
    // 3×3：伴随矩阵 / det
    const cof = (i, j) => {
      const r = [], c = [];
      for (let a = 0; a < 3; a++) if (a !== i) r.push(a);
      for (let b = 0; b < 3; b++) if (b !== j) c.push(b);
      const s = m[r[0]][c[0]] * m[r[1]][c[1]] - m[r[0]][c[1]] * m[r[1]][c[0]];
      return ((i + j) % 2 ? -s : s);
    };
    const out = [];
    for (let i = 0; i < 3; i++) {
      const row = [];
      for (let j = 0; j < 3; j++) row.push(((cof(j, i) * di) % 26 + 26) % 26);   // 转置
      out.push(row);
    }
    return out;
  }
  function hill(s, key, n, decrypt) {
    const m = hillMatrix(key, n);
    const use = decrypt ? invModMatrix(m) : m;
    const t = letters(s);
    let out = '';
    for (let off = 0; off < t.length; off += n) {
      const blk = [];
      for (let i = 0; i < n; i++) blk.push(off + i < t.length ? t.charCodeAt(off + i) - 65 : 23);  // 不足补 X
      for (let i = 0; i < n; i++) {
        let v = 0;
        for (let j = 0; j < n; j++) v += use[i][j] * blk[j];
        out += String.fromCharCode(65 + (v % 26 + 26) % 26);
      }
    }
    return out.slice(0, Math.ceil(t.length / n) * n);
  }
  const hill2Encode = (s, key) => hill(s, key, 2, false);
  const hill2Decode = (s, key) => hill(s, key, 2, true);
  const hill3Encode = (s, key) => hill(s, key, 3, false);
  const hill3Decode = (s, key) => hill(s, key, 3, true);

  /* ---- 猪圈密码（用 Unicode 图形表示，可逆） ---- */
  const PIG_CELL = ['┌', '┬', '┐', '├', '┼', '┤', '└', '┴', '┘'];
  const PIG_X = ['◤', '◥', '◣', '◢'];
  const DOT = '\u0323';   // 组合下加点
  function pigpenEncode(s) {
    let out = '';
    for (const ch of String(s)) {
      const c = ch.toUpperCase();
      if (c >= 'A' && c <= 'I') { out += PIG_CELL[c.charCodeAt(0) - 65]; continue; }
      if (c >= 'J' && c <= 'R') { out += PIG_CELL[c.charCodeAt(0) - 74] + DOT; continue; }
      if (c >= 'S' && c <= 'V') { out += PIG_X[c.charCodeAt(0) - 83]; continue; }
      if (c >= 'W' && c <= 'Z') { out += PIG_X[c.charCodeAt(0) - 87] + DOT; continue; }
      out += ch;
    }
    return out;
  }
  function pigpenDecode(s) {
    const src = String(s);
    const cellIdx = c => PIG_CELL.indexOf(c);
    const xIdx = c => PIG_X.indexOf(c);
    let out = '';
    for (let i = 0; i < src.length; i++) {
      const ch = src[i];
      let dotted = false;
      if (src[i + 1] === DOT) { dotted = true; i++; }
      let ci = cellIdx(ch);
      if (ci >= 0) { out += String.fromCharCode(65 + ci + (dotted ? 9 : 0)); continue; }
      const xi = xIdx(ch);
      if (xi >= 0) { out += String.fromCharCode(83 + xi + (dotted ? 4 : 0)); continue; }
      out += ch;
      if (dotted) out += DOT;
    }
    return out;
  }

  /* ======================= 符号类 ======================= */

  const MORSE = {
    A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....',
    I: '..', J: '.---', K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.',
    Q: '--.-', R: '.-.', S: '...', T: '-', U: '..-', V: '...-', W: '.--', X: '-..-',
    Y: '-.--', Z: '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--',
    '/': '-..-.', '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...',
    ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '-': '-....-', '_': '..--.-',
    '"': '.-..-.', '$': '...-..-', '@': '.--.-.'
  };
  const MORSE_REV = (() => { const m = {}; for (const k of Object.keys(MORSE)) m[MORSE[k]] = k; return m; })();

  function morseEncode(s) {
    const t = String(s).toUpperCase();
    return t.split(/\s+/).filter(Boolean).map(word =>
      word.split('').map(c => MORSE[c] || c).join(' ')
    ).join(' / ');
  }
  function morseDecode(s) {
    return String(s).trim().split(/\s*\/\s*|\s{3,}/).map(word =>
      word.trim().split(/\s+/).filter(Boolean).map(code => MORSE_REV[code] || code).join('')
    ).join(' ');
  }

  function a1z26Encode(s) {
    const t = String(s).toUpperCase();
    return t.split(/\s+/).filter(x => x !== '').map(word =>
      word.split('').map(c => isAlpha(c) ? String(c.charCodeAt(0) - 64) : c).join('-')
    ).join(' ');
  }
  function a1z26Decode(s) {
    return String(s).trim().split(/\s+/).map(word =>
      word.split(/[^0-9]+/).filter(Boolean).map(n => {
        const v = +n;
        if (v < 1 || v > 26) throw new Error('A1Z26 数值越界：' + n);
        return String.fromCharCode(64 + v);
      }).join('')
    ).join(' ');
  }

  const BACON24 = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';       // I/J、U/V 合并
  const BACON26 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  function baconEncode(s, variant) {
    const table = variant === 24 ? BACON24 : BACON26;
    let t = String(s).toUpperCase();
    if (variant === 24) t = t.replace(/J/g, 'I').replace(/U/g, 'V');
    let out = [];
    for (const c of t) {
      const i = table.indexOf(c);
      if (i < 0) { out.push('?'); continue; }
      out.push(i.toString(2).padStart(5, '0').replace(/0/g, 'A').replace(/1/g, 'B'));
    }
    return out.join(' ');
  }
  function baconDecode(s, variant) {
    const table = variant === 24 ? BACON24 : BACON26;
    const bits = String(s).toUpperCase().replace(/[^AB]/g, '');
    if (bits.length % 5) throw new Error('培根密码长度必须是 5 的倍数，当前 ' + bits.length);
    let out = '';
    for (let i = 0; i < bits.length; i += 5) {
      const chunk = bits.slice(i, i + 5);
      const v = parseInt(chunk.replace(/A/g, '0').replace(/B/g, '1'), 2);
      out += table[v] || '?';
    }
    return out;
  }
  /** 把密文藏进载体文本：按大小写承载 A/B */
  function baconHide(cover, secret, variant) {
    const bits = baconEncode(secret, variant).replace(/[^AB]/g, '');
    const lettersIdx = [];
    for (let i = 0; i < cover.length; i++) if (isAlpha(cover[i])) lettersIdx.push(i);
    if (lettersIdx.length < bits.length) throw new Error(`载体字母不足：需要 ${bits.length} 个，实际 ${lettersIdx.length} 个`);
    const arr = cover.split('');
    for (let i = 0; i < bits.length; i++) {
      const p = lettersIdx[i];
      arr[p] = bits[i] === 'B' ? arr[p].toUpperCase() : arr[p].toLowerCase();
    }
    return arr.join('');
  }
  /** 从载体中提取（count 为要还原的明文字母数，缺省则全部） */
  function baconExtract(cover, count) {
    let bits = '';
    for (const c of String(cover)) {
      if (isUpper(c)) bits += 'B';
      else if (isLower(c)) bits += 'A';
    }
    bits = count
      ? bits.slice(0, count * 5)
      : bits.slice(0, bits.length - (bits.length % 5));
    if (!bits.length) return '';
    let out = '';
    for (let i = 0; i < bits.length; i += 5) {
      out += BACON26[parseInt(bits.slice(i, i + 5).replace(/A/g, '0').replace(/B/g, '1'), 2)] || '?';
    }
    return out;
  }

  /** 简单替换：用密钥字母表（密钥字优先，其余字母按序补齐） */
  function keyedAlphabet(key, drop) {
    const dropSet = new Set((drop || '').toUpperCase());
    const seen = new Set();
    let s = '';
    for (const c of (letters(key) + BACON26)) {
      if (dropSet.has(c) || seen.has(c)) continue;
      seen.add(c); s += c;
    }
    return s;
  }
  /** 简单替换：明文第 x 个字母 → 密钥字母表第 x 个字母 */
  function substitutionEncode(s, key) {
    const tbl = keyedAlphabet(key);
    return String(s).replace(/[A-Za-z]/g, c => {
      const base = isUpper(c) ? 65 : 97;
      const x = c.charCodeAt(0) - base;
      return String.fromCharCode(base + (tbl.charCodeAt(x) - 65));
    });
  }
  function substitutionDecode(s, key) {
    const tbl = keyedAlphabet(key);
    return String(s).replace(/[A-Za-z]/g, c => {
      const base = isUpper(c) ? 65 : 97;
      const x = tbl.indexOf(String.fromCharCode(c.charCodeAt(0) - base + 65));
      return x < 0 ? c : String.fromCharCode(base + x);
    });
  }

  /* ---- ADFGX / ADFGVX（Polybius 6×6 + 列移位） ---- */
  const ADFGX6 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const ADFGVX_CH = 'ADFGVX';
  function makeSquare6(key) {
    const seen = new Set();
    let s = '';
    for (const c of (letters(key) + ADFGX6)) { if (!seen.has(c)) { seen.add(c); s += c; } }
    return s.slice(0, 36);
  }
  function adfgvx(s, key, colKey, decrypt) {
    const sq = makeSquare6(key);
    if (!decrypt) {
      const t = String(s).toUpperCase().replace(/[^A-Z0-9]/g, '');
      let mid = '';
      for (const c of t) {
        const i = sq.indexOf(c);
        if (i < 0) continue;
        mid += ADFGVX_CH[Math.floor(i / 6)] + ADFGVX_CH[i % 6];
      }
      return columnarEncode(mid, colKey);
    }
    const mid = columnarDecode(String(s).toUpperCase().replace(/[^ADFGVX]/g, ''), colKey);
    let out = '';
    for (let i = 0; i + 1 < mid.length; i += 2) {
      const r = ADFGVX_CH.indexOf(mid[i]), c = ADFGVX_CH.indexOf(mid[i + 1]);
      if (r < 0 || c < 0) throw new Error('ADFGVX 密文含非法字符');
      out += sq[r * 6 + c];
    }
    return out;
  }
  const adfgvxEncode = (s, key, colKey) => adfgvx(s, key, colKey, false);
  const adfgvxDecode = (s, key, colKey) => adfgvx(s, key, colKey, true);

  /* ======================= 小工具 ======================= */
  function gcd(a, b) { while (b) { [a, b] = [b, a % b]; } return a; }
  function modInv(a, m) {
    a = ((a % m) + m) % m;
    for (let x = 1; x < m; x++) if ((a * x) % m === 1) return x;
    throw new Error('模逆不存在：a=' + a + ', m=' + m);
  }

  /* ======================= 统一入口 ======================= */
  // 每个条目描述 UI 需要的参数
  const TOOLS = {
    'ROT5':        { enc: s => rot5(s),        dec: s => rot5(s),        selfInverse: true },
    'ROT13':       { enc: s => rot13(s),       dec: s => rot13(s),       selfInverse: true },
    'ROT18':       { enc: s => rot18(s),       dec: s => rot18(s),       selfInverse: true },
    'ROT47':       { enc: s => rot47(s),       dec: s => rot47(s),       selfInverse: true },
    'Atbash':      { enc: s => atbash(s),      dec: s => atbash(s),      selfInverse: true },
    '凯撒':        { enc: (s, p) => caesar(s, p.shift), dec: (s, p) => caesar(s, -p.shift), params: [{ k: 'shift', label: '位移', type: 'int', def: 3 }] },
    '仿射':        { enc: (s, p) => affine(s, p.a, p.b), dec: (s, p) => affineDecode(s, p.a, p.b),
                     params: [{ k: 'a', label: 'a（与 26 互素）', type: 'int', def: 5 }, { k: 'b', label: 'b', type: 'int', def: 8 }] },
    '键盘位移':    { enc: (s, p) => keyboardShift(s, -1), dec: (s, p) => keyboardShift(s, 1), selfInverse: false },
    '维吉尼亚':    { enc: (s, p) => vigenere(s, p.key), dec: (s, p) => vigenereDecode(s, p.key), params: [{ k: 'key', label: '密钥', type: 'text', def: 'LEMON' }] },
    '博福特':      { enc: (s, p) => beaufort(s, p.key), dec: (s, p) => beaufortDecode(s, p.key), params: [{ k: 'key', label: '密钥', type: 'text', def: 'FORTIFICATION' }] },
    '变体博福特':  { enc: (s, p) => variantBeaufort(s, p.key), dec: (s, p) => variantBeaufortDecode(s, p.key), params: [{ k: 'key', label: '密钥', type: 'text', def: 'KEY' }] },
    '自动密钥':    { enc: (s, p) => autokeyEncode(s, p.key), dec: (s, p) => autokeyDecode(s, p.key), params: [{ k: 'key', label: '启动密钥', type: 'text', def: 'QUEENLY' }] },
    'Gronsfeld':   { enc: (s, p) => gronsfeld(s, p.digits), dec: (s, p) => gronsfeldDecode(s, p.digits), params: [{ k: 'digits', label: '数字密钥', type: 'text', def: '31415926' }] },
    'Porta':       { enc: (s, p) => porta(s, p.key), dec: (s, p) => porta(s, p.key), params: [{ k: 'key', label: '密钥', type: 'text', def: 'KEY' }] },
    '栅栏(锯齿)':  { enc: (s, p) => railFenceEncode(s, p.rails), dec: (s, p) => railFenceDecode(s, p.rails), params: [{ k: 'rails', label: '栏数', type: 'int', def: 3 }] },
    '栅栏(分组)':  { enc: (s, p) => railFenceSimpleEncode(s, p.rails), dec: (s, p) => railFenceSimpleDecode(s, p.rails), params: [{ k: 'rails', label: '栏数', type: 'int', def: 3 }] },
    '列移位':      { enc: (s, p) => columnarEncode(s, p.key), dec: (s, p) => columnarDecode(s, p.key), params: [{ k: 'key', label: '密钥', type: 'text', def: 'ZEBRAS' }] },
    'Playfair':    { enc: (s, p) => playfairEncode(s, p.key), dec: (s, p) => playfairDecode(s, p.key), params: [{ k: 'key', label: '密钥', type: 'text', def: 'PLAYFAIR EXAMPLE' }] },
    'Polybius':    { enc: (s) => polybius(s, null, false), dec: (s) => polybius(s, null, true), selfInverse: false },
    'Bifid':       { enc: (s, p) => bifidEncode(s, p.period), dec: (s, p) => bifidDecode(s, p.period), params: [{ k: 'period', label: '周期', type: 'int', def: 5 }] },
    'Hill2':       { enc: (s, p) => hill2Encode(s, p.key), dec: (s, p) => hill2Decode(s, p.key), params: [{ k: 'key', label: '2×2 密钥(4 字母)', type: 'text', def: 'DDCF' }] },
    'Hill3':       { enc: (s, p) => hill3Encode(s, p.key), dec: (s, p) => hill3Decode(s, p.key), params: [{ k: 'key', label: '3×3 密钥(9 字母)', type: 'text', def: 'GYBNQKURP' }] },
    '猪圈':        { enc: s => pigpenEncode(s), dec: s => pigpenDecode(s), selfInverse: false },
    '摩斯电码':    { enc: s => morseEncode(s), dec: s => morseDecode(s), selfInverse: false },
    'A1Z26':       { enc: s => a1z26Encode(s), dec: s => a1z26Decode(s), selfInverse: false },
    '培根(26)':    { enc: s => baconEncode(s, 26), dec: s => baconDecode(s, 26), selfInverse: false },
    '培根(24)':    { enc: s => baconEncode(s, 24), dec: s => baconDecode(s, 24), selfInverse: false },
    '简单替换':    { enc: (s, p) => substitutionEncode(s, p.key), dec: (s, p) => substitutionDecode(s, p.key), params: [{ k: 'key', label: '密钥字', type: 'text', def: 'ZEBRAS' }] },
    'ADFGVX':      { enc: (s, p) => adfgvxEncode(s, p.key, p.col), dec: (s, p) => adfgvxDecode(s, p.key, p.col),
                     params: [{ k: 'key', label: '方阵密钥', type: 'text', def: 'PHQGIUMEAYLNOFDXKRCVBZTWSJ' },
                              { k: 'col', label: '列密钥', type: 'text', def: 'CARGO' }] }
  };

  return {
    // 位移
    rot5, rot13, rot18, rot47, caesar, caesarBrute, atbash, affine, affineDecode, affineBrute, keyboardShift,
    // 多表
    vigenere, vigenereDecode, beaufort, beaufortDecode, variantBeaufort, variantBeaufortDecode,
    autokeyEncode, autokeyDecode, gronsfeld, gronsfeldDecode, porta,
    // 置换
    railFenceEncode, railFenceDecode, railFenceSimpleEncode, railFenceSimpleDecode, railFenceBrute,
    columnarEncode, columnarDecode, columnarBrute,
    // 方块
    playfairEncode, playfairDecode, polybius, bifidEncode, bifidDecode,
    hill2Encode, hill2Decode, hill3Encode, hill3Decode, pigpenEncode, pigpenDecode,
    // 符号
    morseEncode, morseDecode, a1z26Encode, a1z26Decode,
    baconEncode, baconDecode, baconHide, baconExtract,
    substitutionEncode, substitutionDecode, keyedAlphabet,
    adfgvxEncode, adfgvxDecode,
    // 工具
    TOOLS, gcd, modInv, letters, square5, makeSquare6,
    _portaRow: i => PORTA[i - 1], _portaRows: PORTA
  };
})();
