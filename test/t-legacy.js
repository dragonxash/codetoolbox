/* 老式/冷门编码层对拍：CT.legacy vs Python 独立参考实现（legacy_oracle.json） */
const fs = require('fs');
const path = require('path');
const { load } = require('./_load.js');
const CT = load();
const U = CT.util;
const L = CT.legacy;

let pass = 0, fail = 0;
const fails = [];
function eq(name, got, exp) {
  if (got === exp) pass++;
  else { fail++; if (fails.length < 30) fails.push(`FAIL ${name}\n     got ${JSON.stringify(got)}\n     exp ${JSON.stringify(exp)}`); }
}
function ok(name, cond) { eq(name, String(!!cond), 'true'); }

const ora = JSON.parse(fs.readFileSync(path.join(__dirname, 'oracle', 'legacy_oracle.json'), 'utf8'));
const SAMPLES = ora.samples.map(h => U.unhex(h));

/* 判断样本是否为「合法 UTF-8 文本」（Punycode / 盲文只对文本比对） */
function isText(b) {
  const s = U.utf8Dec(b);
  return U.hex(U.utf8Enc(s)) === U.hex(b);
}

/* ---------------- 1. 对拍 Python 参考 ---------------- */
const MAPFN = {
  uu:             b => L.uuEncode(b),
  xx:             b => L.xxEncode(b),
  ascii85:        b => L.a85Encode(b),
  ascii85adobe:   b => L.a85Encode(b, { adobe: true }),
  base92:         b => L.b92Encode(b),
  yenc:           b => L.yEncEncode(b),
  ebcdic:         b => L.ebcdicEncode(U.latin1Dec(b)),
  hexdump:        b => L.hexdump(b),
  dna:            b => L.dnaEncode(b),
  z85:            b => CT.base.z85e(b),
  punycode:       b => L.punycodeEncode(U.utf8Dec(b)),
  braille:        b => L.brailleEncode(U.utf8Dec(b))
};

for (const name of Object.keys(MAPFN)) {
  const fn = MAPFN[name];
  const exp = ora.results[name];
  if (!exp) { fails.push('缺对拍数据：' + name); fail++; continue; }
  for (let i = 0; i < SAMPLES.length; i++) {
    const b = SAMPLES[i];
    // Python 的 binascii.b2a_uu 单次最多 45 字节，超长样本是参考侧限制而非规范要求 → 跳过
    if (name === 'uu' && b.length > 45) continue;
    // yEnc：Python 参考按 128 列折行，本库默认不折行 → 长样本单独往返测
    if (name === 'yenc' && b.length >= 128) continue;
    if ((name === 'punycode' || name === 'braille') && !isText(b)) continue;
    let got;
    try { got = fn(b); } catch (e) { got = 'ERR:' + e.message; }
    // Z85 要求 4 字节倍数：只比对「是否报错」，两侧文案不必一致
    if (String(exp[i].enc).startsWith('ERR:')) {
      ok(`${name}[${i}] len=${b.length} 应报错`, String(got).startsWith('ERR:'));
      continue;
    }
    eq(`${name}[${i}] len=${b.length}`, got, exp[i].enc);
  }
}

/* ---------------- 2. Ascii85 缩写与定界的单独核对 ---------------- */
// 取自 Python base64 实测：'z'=四零字节（恒生效），'y'=四空格（仅 foldspaces）
eq('a85 四零字节 -> z', L.a85Encode(new Uint8Array([0, 0, 0, 0])), 'z');
eq('a85 四零字节(Adobe)', L.a85Encode(new Uint8Array([0, 0, 0, 0]), { adobe: true }), '<~z~>');
eq('a85 四空格(默认不折叠)', L.a85Encode(U.latin1Enc('    ')), '+<VdL');
eq('a85 四空格(foldspaces) -> y', L.a85Encode(U.latin1Enc('    '), { foldspaces: true }), 'y');
eq('a85 四空格(Adobe+fold)', L.a85Encode(U.latin1Enc('    '), { adobe: true, foldspaces: true }), '<~y~>');
eq('a85 解码 z', U.hex(L.a85Decode('z')), '00000000');
eq('a85 解码 y', U.hex(L.a85Decode('y')), '20202020');
eq('a85 解码 Adobe 定界', U.hex(L.a85Decode('<~BOu!rD]j7BEbo7~>')), '68656c6c6f20776f726c64');

/* ---------------- 3. Bubble Babble 公开向量 ---------------- */
// 来源：OpenSSH sshkey.c / Digest::BubbleBabble / thenoviceoof 参考实现的 doctest
eq("Bubble('')", L.bubbleBabble(U.utf8Enc('')), 'xexax');
eq("Bubble('1234567890')", L.bubbleBabble(U.utf8Enc('1234567890')), 'xesef-disof-gytuf-katof-movif-baxux');
eq("Bubble('Pineapple')", L.bubbleBabble(U.utf8Enc('Pineapple')), 'xigak-nyryk-humil-bosek-sonax');
eq("Bubble('lol')", L.bubbleBabble(U.utf8Enc('lol')), 'xirak-zorex');
eq('Bubble([70,85,129,199])', L.bubbleBabble(new Uint8Array([70, 85, 129, 199])), 'xicih-habes-laxex');
eq('Bubble([0])', L.bubbleBabble(new Uint8Array([0])), 'xebax');
eq('Bubble(md5-like 16B)',
   L.bubbleBabble(U.unhex('432cc46b5c67c9adaabdcc6c69e23d6d')),
   'xibod-sycik-rilak-lydap-tipur-tifyk-sipuv-dazok-tixox');
// 反向解码必须还原（含末尾 seed 校验）
eq('Bubble 解码 1234567890', U.utf8Dec(L.bubbleBabbleDecode('xesef-disof-gytuf-katof-movif-baxux')), '1234567890');
eq('Bubble 解码 Pineapple', U.utf8Dec(L.bubbleBabbleDecode('xigak-nyryk-humil-bosek-sonax')), 'Pineapple');
eq('Bubble 解码 [70,85,129,199]', U.hex(L.bubbleBabbleDecode('xicih-habes-laxex')), '465581c7');
let threw = false;
try { L.bubbleBabbleDecode('xesef-disof-gytuf-katof-movif-baxux'.replace('baxux', 'zazux')); } catch (e) { threw = true; }
ok('Bubble 篡改末尾应被校验拒绝', threw);

/* ---------------- 4. Punycode / IDNA ---------------- */
eq('Punycode bücher', L.punycodeEncode('bücher'), 'bcher-kva');
eq('Punycode 解码 bcher-kva', L.punycodeDecode('bcher-kva'), 'bücher');
eq('Punycode  München', L.punycodeEncode('München'), 'Mnchen-3ya');
eq('Punycode 解码 Mnchen-3ya', L.punycodeDecode('Mnchen-3ya'), 'München');
eq('Punycode 中文', L.punycodeEncode('中国'), 'fiqs8s');
eq('Punycode 解码 fiqs8s', L.punycodeDecode('fiqs8s'), '中国');
eq('Punycode emoji', L.punycodeEncode('😀'), 'e28h');
eq('Punycode 解码 emoji', L.punycodeDecode('e28h'), '😀');
eq('IDNA 域名', L.idnaEncode('中国.example.com'), 'xn--fiqs8s.example.com');
eq('IDNA 域名还原', L.idnaDecode('xn--fiqs8s.example.com'), '中国.example.com');
// 同形字攻击场景：西里尔 а (U+0430) 冒充拉丁 a
eq('IDNA 同形字', L.idnaEncode('раypal.com'), 'xn--ypal-43d9g.com');

/* ---------------- 5. 往返一致性（含长样本与折行） ---------------- */
const RT = [
  ['UU',       b => L.uuEncode(b),       s => L.uuDecode(s)],
  ['XX',       b => L.xxEncode(b),       s => L.xxDecode(s)],
  ['Ascii85',  b => L.a85Encode(b),      s => L.a85Decode(s)],
  ['A85Adobe', b => L.a85Encode(b, { adobe: true }), s => L.a85Decode(s)],
  ['Base92',   b => L.b92Encode(b),      s => L.b92Decode(s)],
  ['yEnc',     b => L.yEncEncode(b),     s => L.yEncDecode(s)],
  ['EBCDIC',   b => L.ebcdicEncode(U.latin1Dec(b)), s => U.latin1Enc(L.ebcdicDecode(s))],
  ['Hexdump',  b => L.hexdump(b),        s => L.hexdumpReverse(s)],
  ['DNA',      b => L.dnaEncode(b),      s => L.dnaDecode(s)],
  ['Bubble',   b => L.bubbleBabble(b),   s => L.bubbleBabbleDecode(s)]
];
const RT_SAMPLES = [];
for (let n = 0; n <= 40; n++) RT_SAMPLES.push(U.unhex('00'.repeat(0) + Array.from({ length: n }, (_, i) => (i * 37 + 11) & 255).map(x => ('0' + x.toString(16)).slice(-2)).join('')));
RT_SAMPLES.push(U.unhex('0000000000000000'));
RT_SAMPLES.push(U.unhex('2020202020202020'));
RT_SAMPLES.push(U.utf8Enc('The quick brown fox jumps over the lazy dog 0123456789'));
for (const [nm, enc, dec] of RT) {
  for (let i = 0; i < RT_SAMPLES.length; i++) {
    let back;
    try { back = U.hex(dec(enc(RT_SAMPLES[i]))); } catch (e) { back = 'ERR:' + e.message; }
    eq(`${nm} 往返[${i}] len=${RT_SAMPLES[i].length}`, back, U.hex(RT_SAMPLES[i]));
  }
}
// yEnc 带折行
{
  const big = U.utf8Enc('x'.repeat(300));
  eq('yEnc 折行往返', U.hex(L.yEncDecode(L.yEncEncode(big, { line: 128 }))), U.hex(big));
}

/* ---------------- 6. UUencode 文件头/尾 ---------------- */
{
  const body = U.utf8Enc('hello uu');
  const full = L.uuEncode(body, { filename: 'a.txt', mode: '644' });
  ok('UU 带 begin 头', full.startsWith('begin 644 a.txt\n'));
  ok('UU 带 end 尾', full.trim().endsWith('end'));
  eq('UU 带头尾可解码', U.utf8Dec(L.uuDecode(full)), 'hello uu');
  // 反引号写法（0 用 '`' 表示）也应能解
  eq('UU 反引号零值可解', U.utf8Dec(L.uuDecode('#0V%T\n')), 'Cat');
}

/* ---------------- 7. 敲敲码 / 北约 / T9 / 盲文 ---------------- */
{
  eq('敲敲码 H(2,3)', L.tapEncode('H'), '../...');
  eq('敲敲码 全串往返', L.tapDecode(L.tapEncode('HELLO WORLD')), 'HELLO WORLD');
  eq('敲敲码 I/J 同位', L.tapDecode(L.tapEncode('JILL')), 'IILL');
  eq('北约 SOS', L.natoEncode('SOS'), 'SIERRA OSCAR SIERRA');
  eq('北约 往返', L.natoDecode(L.natoEncode('HELLO')), 'HELLO');
  eq('北约 数字', L.natoEncode('007'), 'ZERO ZERO SEVEN');
  eq('T9 hello', L.t9Encode('hello'), '43556');
  eq('T9 候选 43556', L.t9Candidates('43556').join('/'), 'GHI/DEF/JKL/JKL/MNO');
  eq('盲文 hello', L.brailleEncode('hello'), '⠓⠑⠇⠇⠕');
  eq('盲文往返', L.brailleDecode(L.brailleEncode('Hello, World!')), 'hello, world!');
}

/* ---------------- 8. 工具表自检 ---------------- */
// 通用样本；对「字符集受限」的工具另给专属样本（这些变换本身不可能无损承载任意 Unicode）
const DEFAULT_RT = 'Hello, 世界! 123';
const RT_CASE = {
  'EBCDIC':    ['Hello, World! 123', 'Hello, World! 123'],   // cp037 只覆盖 Latin-1
  '盲文':      ['hello world', 'hello world'],               // 仅字母与少量标点
  '敲敲码':    ['HELLO WORLD', 'HELLO WORLD'],               // 仅字母
  '北约音标':  ['HELLO 123', 'HELLO123'],                    // 词间空格不保留
  'T9 九宫格': null                                          // 单向，无 dec
};
{
  const names = Object.keys(L.TOOLS);
  for (const nm of names) {
    const t = L.TOOLS[nm];
    const spec = RT_CASE[nm];
    if (spec === null) { ok(`TOOLS[${nm}] 有 enc`, typeof t.enc === 'function'); continue; }
    const [inp, exp] = spec || [DEFAULT_RT, null];
    let got;
    try { got = t.dec(t.enc(inp)); } catch (e) { got = 'ERR:' + e.message; }
    eq(`TOOLS[${nm}] 文本往返`, got, exp !== null ? exp : (t.selfInverse ? t.enc(inp) : inp));
  }
}

console.log('='.repeat(64));
console.log(`老式编码层：${pass} 通过 / ${fail} 失败    (工具 ${Object.keys(L.TOOLS).length} 种)`);
if (fails.length) { console.log('\n--- 明细 ---'); fails.forEach(f => console.log('  ' + f)); }
console.log('='.repeat(64));
process.exit(fail ? 1 : 0);
