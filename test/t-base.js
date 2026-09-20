/* ===========================================================================
 * BASE 层测试：与 BaseOracle.java（原 APP 源码 verbatim 移植）逐字节比对
 *   node test/t-base.js
 * =========================================================================== */
const fs = require('fs');
const path = require('path');
const { load } = require('./_load.js');

const CT = load();
const U = CT.util;
const B = CT.base;

let pass = 0, fail = 0;
const fails = [];
function eq(tag, got, exp) {
  if (got === exp) { pass++; return; }
  fail++;
  if (fails.length < 30) fails.push(`${tag}\n     got: ${JSON.stringify(got)}\n     exp: ${JSON.stringify(exp)}`);
}

/* ---------------- 解析 oracle ---------------- */
// 关键：以 latin1 读入。Java 的 stdout 是 GBK，纯 ASCII 行不受影响；
// 非 ASCII 只出现在 S 行（GBK 字节），我们不使用它。
const raw = fs.readFileSync(path.join(__dirname, 'oracle', 'base_oracle.txt'), 'latin1');
const lines = raw.split(/\r?\n/);

function unq(s) {
  // Java 侧 q() 只转义了 \ 和 "
  return s.replace(/\\(["\\])/g, '$1');
}

const DATA = {};          // n -> hex
const ALPH = {};          // name -> string
const ENC = {};           // tag -> { n -> value }
const DEC = {};           // tag -> { n -> value }
const SMP = {};           // tag -> { i -> value }
let nSamples = 0;

const ENC_TAGS = ['BASE16', 'BASE64', 'BASE32', 'BASE36', 'BASE58', 'BASE62', 'BASE85', 'BASE91'];
const DEC_TAGS = ['D16', 'D64', 'D32', 'D36', 'D58', 'D62', 'D85', 'D91'];
const SMP_TAGS = ['T16', 'T64', 'T32', 'T36', 'T58', 'T62', 'T85', 'T91'];
const H2T = { BASE16: 'D16', BASE64: 'D64', BASE32: 'D32', BASE36: 'D36', BASE58: 'D58', BASE62: 'D62', BASE85: 'D85', BASE91: 'D91' };
const S2T = { BASE16: 'T16', BASE64: 'T64', BASE32: 'T32', BASE36: 'T36', BASE58: 'T58', BASE62: 'T62', BASE85: 'T85', BASE91: 'T91' };

for (const line of lines) {
  const m = /^(DATA|ALPHABET|BASE\d+|D\d+|T\d+|SAMPLES|S) (.*)$/.exec(line);
  if (!m) continue;
  const kind = m[1], rest = m[2];
  if (kind === 'DATA') {
    const mm = /^(\d+) (.*)$/.exec(rest);
    if (mm) DATA[+mm[1]] = mm[2];
  } else if (kind === 'ALPHABET') {
    const mm = /^(\S+) "(.*)"$/.exec(rest);
    if (mm) ALPH[mm[1]] = unq(mm[2]);
  } else if (kind === 'SAMPLES') {
    nSamples = parseInt(rest, 10);
  } else {
    const mm = /^(\d+) (?:("(.*)")|(ERR.*))$/.exec(rest);
    if (!mm) continue;
    const idx = +mm[1];
    const val = mm[2] !== undefined ? unq(mm[3]) : ('ERR:' + mm[4]);
    if (ENC_TAGS.includes(kind)) (ENC[kind] = ENC[kind] || {})[idx] = val;
    else if (DEC_TAGS.includes(kind)) (DEC[kind] = DEC[kind] || {})[idx] = val;
    else if (SMP_TAGS.includes(kind)) (SMP[kind] = SMP[kind] || {})[idx] = val;
  }
}

/* ---------------- 工具 ---------------- */
const pat = (n) => {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 29 + n * 17 + 3) & 0xff;
  return b;
};
const call = (fn) => { try { return fn(); } catch (e) { return 'ERR:' + e.message; } };

/* 1. 校验输入数据本身 */
let nData = 0;
for (const nStr of Object.keys(DATA)) {
  const n = +nStr;
  eq(`DATA ${n}`, U.hex(pat(n)), DATA[n]);
  nData++;
}

/* 2. 校验字母表 */
const ALPH_MAP = { base32: 'base32', base58: 'base58', base62: 'base62', base91: 'base91' };
for (const k of Object.keys(ALPH)) {
  eq(`ALPHABET ${k}`, B.ALPHABET[ALPH_MAP[k]], ALPH[k]);
}

/* 3. 编码：所有 8 种 × 21 种长度 */
const ENC_FN = {
  BASE16: d => B.b16e(d),
  BASE64: d => B.b64e(d),
  BASE32: d => B.b32e(d),
  BASE36: d => B.b36e(d),
  BASE58: d => B.b58e(d),
  BASE62: d => B.b62e(d),
  BASE85: d => B.b85e(d),
  BASE91: d => B.b91e(d)
};
const DEC_FN = {
  D16: s => U.hex(B.b16d(s)),
  D64: s => U.hex(B.b64d(s)),
  D32: s => U.hex(B.b32d(s)),
  D36: s => U.hex(B.b36d(s)),
  D58: s => U.hex(B.b58d(s)),
  D62: s => U.hex(B.b62d(s)),
  D85: s => U.hex(B.b85d(s)),
  D91: s => U.hex(B.b91d(s))
};

for (const tag of ENC_TAGS) {
  const table = ENC[tag] || {};
  for (const nStr of Object.keys(table)) {
    const n = +nStr, exp = table[n];
    const got = call(() => ENC_FN[tag](pat(n)));
    // ERR 情况只比较类型
    if (exp.startsWith('ERR:')) eq(`${tag} ${n}`, got.startsWith('ERR:') ? 'ERR' : got, 'ERR');
    else eq(`${tag} ${n}`, got, exp);
  }
}

/* 4. 解码往返：decode(encode(x)) === x */
for (const tag of ENC_TAGS) {
  const dtag = H2T[tag];
  const table = DEC[dtag] || {};
  for (const nStr of Object.keys(table)) {
    const n = +nStr, exp = table[n];
    const got = call(() => DEC_FN[dtag](ENC_FN[tag](pat(n))));
    if (exp.startsWith('ERR:')) eq(`${dtag} ${n}`, got.startsWith('ERR:') ? 'ERR' : got, 'ERR');
    else eq(`${dtag} ${n}`, got, exp);
  }
}

/* 5. 文本样本（输入字节取自 oracle 的 T16 行，彻底绕开字符集问题） */
for (let i = 0; i < nSamples; i++) {
  const hexIn = SMP['T16'][i];
  if (hexIn === undefined) continue;
  const bytes = U.unhex(hexIn);
  for (const tag of ENC_TAGS) {
    const exp = (SMP[S2T[tag]] || {})[i];
    if (exp === undefined) continue;
    const got = call(() => ENC_FN[tag](bytes));
    if (exp.startsWith('ERR:')) eq(`${S2T[tag]} ${i}`, got.startsWith('ERR:') ? 'ERR' : got, 'ERR');
    else eq(`${S2T[tag]} ${i}`, got, exp);
  }
  // 往返：encode 抛异常时（如 BASE36 空输入）整个往返也应是 ERR
  for (const tag of ENC_TAGS) {
    const dtag = H2T[tag];
    const encThrew = (SMP[S2T[tag]] || {})[i] === undefined
      || String((SMP[S2T[tag]] || {})[i]).startsWith('ERR:');
    const got = call(() => DEC_FN[dtag](ENC_FN[tag](bytes)));
    if (encThrew) eq(`RT ${dtag} ${i}`, got.startsWith('ERR:') ? 'ERR' : got, 'ERR');
    else eq(`RT ${dtag} ${i}`, got, hexIn);
  }
}

/* ---------------- 扩展算法自检（无 oracle，用可逆性与已知向量） ---------------- */
const ext = [];
function check(name, cond, detail) { ext.push({ name, ok: !!cond, detail: detail || '' }); }

// BASE64URL：无填充、-_ 字母表
{
  const d = U.utf8Enc('龙000abc');
  const e = B.b64ue(d, false);
  check('BASE64URL 无填充且用 -_', !/[+/=]/.test(e) && U.hex(B.b64ud(e)) === U.hex(d), e);
  check('BASE64URL 带填充', /=$/.test(B.b64ue(U.utf8Enc('a'), true)) || B.b64ue(U.utf8Enc('a'), true) === 'YQ==', B.b64ue(U.utf8Enc('a'), true));
}
// BASE32HEX RFC4648
check('BASE32HEX "foobar"', B.b32hexe(U.utf8Enc('foobar')) === 'CPNMUOJ1E8======', B.b32hexe(U.utf8Enc('foobar')));
check('BASE32HEX 往返', U.hex(B.b32hexd(B.b32hexe(U.utf8Enc('hello world')))) === U.hex(U.utf8Enc('hello world')));
// Crockford
check('Crockford "hello"', B.crocke(U.utf8Enc('hello')) === 'D1JPRV3F', B.crocke(U.utf8Enc('hello')));
check('Crockford 宽容 I/L/O', U.hex(B.crockd('D1JPRV3F'.replace('1', 'I').replace('0', 'O'))) === U.hex(B.crockd('D1JPRV3F')));
// Z85 (ZeroMQ 官方测试向量)
check('Z85 官方向量', B.z85e(U.unhex('864fd26fb559f75b')) === 'HelloWorld', B.z85e(U.unhex('864fd26fb559f75b')));
check('Z85 往返', U.hex(B.z85d(B.z85e(U.unhex('0011223344556677')))) === '0011223344556677');
// BASE45 (RFC 9285 官方向量)
check('BASE45 RFC9285', B.b45e(U.utf8Enc('AB')) === 'BB8', B.b45e(U.utf8Enc('AB')));
check('BASE45 RFC9285 2', B.b45e(U.utf8Enc('Hello!!')) === '%69 VD92EX0', B.b45e(U.utf8Enc('Hello!!')));
check('BASE45 往返', U.hex(B.b45d(B.b45e(U.utf8Enc('base-45 测试')))) === U.hex(U.utf8Enc('base-45 测试')));
// BASE58Check（Bitcoin 向量：0x00 + 20 字节 0x00 → 1111111111111111111114oLvT2）
check('BASE58Check 全零向量', B.b58checke(new Uint8Array(21)) === '1111111111111111111114oLvT2', B.b58checke(new Uint8Array(21)));
check('BASE58Check 往返', U.hex(B.b58checkd(B.b58checke(U.utf8Enc('校验和')))) === U.hex(U.utf8Enc('校验和')));
check('BASE58Check 篡改检测', (() => {
  const s = B.b58checke(U.utf8Enc('abc'));
  const bad = s.slice(0, -1) + (s.slice(-1) === '1' ? '2' : '1');
  try { B.b58checkd(bad); return false; } catch (e) { return true; }
})());

/* ---------------- 输出 ---------------- */
console.log('='.repeat(64));
console.log(`BASE 层测试：oracle 向量 ${pass + fail - ext.length} 项，扩展自检 ${ext.length} 项`);
console.log(`  通过 ${pass} / 失败 ${fail}   (数据 ${nData} 组, 样本 ${nSamples} 个)`);
if (fails.length) { console.log('\n--- 失败明细（最多 30 条）---'); fails.forEach(f => console.log('  ✗ ' + f)); }
const extBad = ext.filter(e => !e.ok);
if (extBad.length) { console.log('\n--- 扩展自检失败 ---'); extBad.forEach(e => console.log('  ✗ ' + e.name + '  ' + e.detail)); }
console.log('='.repeat(64));
process.exit(fail === 0 && extBad.length === 0 ? 0 : 1);
