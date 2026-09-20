/* ===========================================================================
 * 古典密码层测试
 *   · 公开标准向量（Wikipedia / RFC / 教材经典例子）
 *   · 全量加解密回环（覆盖所有工具与参数组合）
 *   node test/t-classic.js
 * =========================================================================== */
const { load } = require('./_load.js');
const CT = load();
const C = CT.classic;

let pass = 0, fail = 0;
const fails = [];
function eq(name, got, exp) {
  if (String(got) === String(exp)) pass++;
  else { fail++; if (fails.length < 30) fails.push(`FAIL ${name}\n     got ${JSON.stringify(got)}\n     exp ${JSON.stringify(exp)}`); }
}
function rt(name, encFn, decFn, input) {
  let e;
  try { e = encFn(input); } catch (err) { fail++; fails.push(`THROW ${name} 加密: ${err.message}`); return; }
  try { eq(name + ' 回环', decFn(e), input); }
  catch (err) { fail++; fails.push(`THROW ${name} 解密: ${err.message}  (密文 ${e})`); }
}

/* ---------------- 1. 公开标准向量 ---------------- */
// 位移类
eq('ROT13',            C.rot13('Hello, World!'), 'Uryyb, Jbeyq!');
eq('ROT13 自反',       C.rot13(C.rot13('Hello, World!')), 'Hello, World!');
eq('ROT5',             C.rot5('0123456789'), '5678901234');
eq('ROT47',            C.rot47('Hello'), 'w6==@');
eq('ROT47 自反',       C.rot47(C.rot47('Hello, World!')), 'Hello, World!');
eq('凯撒 shift=3',     C.caesar('abcXYZ', 3), 'defABC');
eq('凯撒 shift=-3',    C.caesar('defABC', -3), 'abcXYZ');
eq('Atbash',           C.atbash('abcXYZ'), 'zyxCBA');
eq('Atbash 自反',      C.atbash(C.atbash('The quick brown fox')), 'The quick brown fox');
eq('仿射(5,8)',        C.affine('AFFINECIPHER', 5, 8), 'IHHWVCSWFRCP');
eq('仿射解密(5,8)',    C.affineDecode('IHHWVCSWFRCP', 5, 8), 'AFFINECIPHER');
eq('仿射爆破条目数',   String(C.affineBrute('abc').length), '312');
eq('凯撒爆破条目数',   String(C.caesarBrute('abc').length), '25');

// 多表类
eq('维吉尼亚 LEMON',   C.vigenere('ATTACKATDAWN', 'LEMON'), 'LXFOPVEFRNHR');
eq('维吉尼亚解密',     C.vigenereDecode('LXFOPVEFRNHR', 'LEMON'), 'ATTACKATDAWN');
eq('博福特自反',       C.beaufort(C.beaufort('DEFENDTHEEASTWALLOFTHECASTLE', 'FORTIFICATION'), 'FORTIFICATION'), 'DEFENDTHEEASTWALLOFTHECASTLE');
eq('变体博福特往返',   C.variantBeaufortDecode(C.variantBeaufort('HELLO', 'KEY'), 'KEY'), 'HELLO');
eq('自动密钥往返',     C.autokeyDecode(C.autokeyEncode('ATTACKATDAWN', 'QUEENLY'), 'QUEENLY'), 'ATTACKATDAWN');
eq('Gronsfeld 往返',   C.gronsfeldDecode(C.gronsfeld('HELLO', '3141'), '3141'), 'HELLO');
eq('Porta 自反',       C.porta(C.porta('HELLO WORLD', 'KEY'), 'KEY'), 'HELLO WORLD');
//  Porta 码表前 5 行须与标准表逐字一致，且每一行都是对合置换
{
  const rows = C._portaRows.map(r => r.map(v => String.fromCharCode(65 + v)).join(''));
  const known = [
    'NOPQRSTUVWXYZABCDEFGHIJKLM',
    'OPQRSTUVWXYZNMABCDEFGHIJKL',
    'PQRSTUVWXYZNOLMABCDEFGHIJK',
    'QRSTUVWXYZNOPKLMABCDEFGHIJ',
    'RSTUVWXYZNOPQJKLMABCDEFGHI'
  ];
  for (let i = 0; i < known.length; i++) eq(`Porta 第 ${i + 1} 行`, rows[i], known[i]);
  eq('Porta 共 13 行', String(rows.length), '13');
  eq('Porta 每行 26 字母', String(rows.every(r => r.length === 26)), 'true');
  eq('Porta 每行均为对合置换',
     String(rows.every(r => Array.from({ length: 26 }, (_, x) => r.charCodeAt(r.charCodeAt(x) - 65) - 65 === x).every(Boolean))),
     'true');
  eq('Porta 每行是 26 个字母的排列',
     String(rows.every(r => new Set(r).size === 26)), 'true');
}

// 置换类
eq('栅栏(锯齿) 3 栏',  C.railFenceEncode('WEAREDISCOVEREDFLEEATONCE', 3), 'WECRLTEERDSOEEFEAOCAIVDEN');
eq('栅栏(锯齿) 解密',  C.railFenceDecode('WECRLTEERDSOEEFEAOCAIVDEN', 3), 'WEAREDISCOVEREDFLEEATONCE');
eq('栅栏(分组) 3 栏',  C.railFenceSimpleEncode('WEAREDISCOVEREDFLEEATONCE', 3), 'WOEEVAAETRROEENDDCIFESLCE');
eq('列移位 ZEBRAS',    C.columnarEncode('WEAREDISCOVEREDFLEEATONCE', 'ZEBRAS'), 'EVLNACDTESEAROFODEECWIREE');

// 方块类
//  Wikipedia Hill 3×3：GYBNQKURP，ACT → POH
eq('Hill3 GYBNQKURP',  C.hill3Encode('ACT', 'GYBNQKURP'), 'POH');
eq('Hill3 解密',       C.hill3Decode('POH', 'GYBNQKURP'), 'ACT');
//  经典 Hill 2×2：[[3,3],[2,5]] = DDCF，HELP → HIAT
eq('Hill2 DDCF',       C.hill2Encode('HELP', 'DDCF'), 'HIAT');
eq('Hill2 解密',       C.hill2Decode('HIAT', 'DDCF'), 'HELP');
//  Wikipedia Playfair：key = PLAYFAIR EXAMPLE
eq('Playfair 加密',    C.playfairEncode('Hide the gold in the tree stump', 'PLAYFAIR EXAMPLE'), 'BMODZBXDNABEKUDMUIXMMOUVIF');
eq('Playfair 解密',    C.playfairDecode('BMODZBXDNABEKUDMUIXMMOUVIF', 'PLAYFAIR EXAMPLE'), 'HIDETHEGOLDINTHETREXESTUMP');
eq('Polybius',         C.polybius('ABC', null, false), '11 12 13');
eq('Polybius 解密',    C.polybius('11 12 13', null, true), 'ABC');
eq('猪圈图形',         C.pigpenEncode('ABC'), '┌┬┐');
eq('猪圈解密',         C.pigpenDecode('┌┬┐'), 'ABC');

// 符号类
eq('摩斯 SOS',         C.morseEncode('SOS'), '... --- ...');
eq('摩斯解密',         C.morseDecode('... --- ...'), 'SOS');
eq('摩斯含空格',       C.morseEncode('HELLO WORLD'), '.... . .-.. .-.. --- / .-- --- .-. .-.. -..');
eq('摩斯数字',         C.morseEncode('123'), '.---- ..--- ...--');
eq('A1Z26',            C.a1z26Encode('ABC'), '1-2-3');
eq('A1Z26 解密',       C.a1z26Decode('1-2-3'), 'ABC');
eq('培根 26 字母表',   C.baconDecode(C.baconEncode('ABC', 26), 26), 'ABC');
eq('培根 A=AAAAA',     C.baconEncode('A', 26), 'AAAAA');
eq('培根 B=AAAAB',     C.baconEncode('B', 26), 'AAAAB');
eq('培根 C=AAABA',     C.baconEncode('C', 26), 'AAABA');

/* ---------------- 2. 回环全覆盖 ---------------- */
const PLAIN = 'Attack at dawn, we ride at first light!';
const PLAIN_U = 'ATTACKATDAWN';

// 无参数工具
rt('ROT13',  s => C.rot13(s), s => C.rot13(s), PLAIN);
rt('ROT47',  s => C.rot47(s), s => C.rot47(s), PLAIN);
rt('Atbash', s => C.atbash(s), s => C.atbash(s), PLAIN);
rt('凯撒',   s => C.caesar(s, 7), s => C.caesar(s, -7), PLAIN);
rt('仿射',   s => C.affine(s, 7, 11), s => C.affineDecode(s, 7, 11), PLAIN);
rt('维吉尼亚', s => C.vigenere(s, 'SECRET'), s => C.vigenereDecode(s, 'SECRET'), PLAIN);
rt('博福特',   s => C.beaufort(s, 'SECRET'), s => C.beaufortDecode(s, 'SECRET'), PLAIN);
rt('变体博福特', s => C.variantBeaufort(s, 'SECRET'), s => C.variantBeaufortDecode(s, 'SECRET'), PLAIN);
rt('自动密钥', s => C.autokeyEncode(s, 'SECRET'), s => C.autokeyDecode(s, 'SECRET'), PLAIN);
rt('Gronsfeld', s => C.gronsfeld(s, '2718'), s => C.gronsfeldDecode(s, '2718'), PLAIN);
rt('Porta',   s => C.porta(s, 'SECRET'), s => C.porta(s, 'SECRET'), PLAIN);
rt('列移位',  s => C.columnarEncode(s, 'ZEBRAS'), s => C.columnarDecode(s, 'ZEBRAS'), PLAIN);
rt('简单替换', s => C.substitutionEncode(s, 'ZEBRAS'), s => C.substitutionDecode(s, 'ZEBRAS'), PLAIN);

// 只对字母敏感的（会丢掉标点/大小写），单独用纯字母与固定大写
rt('栅栏(锯齿)', s => C.railFenceEncode(s, 4), s => C.railFenceDecode(s, 4), PLAIN);
rt('栅栏(分组)', s => C.railFenceSimpleEncode(s, 4), s => C.railFenceSimpleDecode(s, 4), PLAIN);
for (const r of [2, 3, 5, 7]) {
  eq(`栅栏(锯齿) ${r} 栏回环`, C.railFenceDecode(C.railFenceEncode(PLAIN_U, r), r), PLAIN_U);
  eq(`栅栏(分组) ${r} 栏回环`, C.railFenceSimpleDecode(C.railFenceSimpleEncode(PLAIN_U, r), r), PLAIN_U);
}
for (const k of ['ZEBRAS', 'AB', 'SECRETKEY']) {
  eq(`列移位 ${k} 回环`, C.columnarDecode(C.columnarEncode(PLAIN_U, k), k), PLAIN_U);
}
rt('Playfair', s => C.playfairEncode(s, 'MONARCHY'), s => C.playfairDecode(s, 'MONARCHY'), PLAIN_U);
for (const pd of [3, 5, 7]) {
  eq(`Bifid period=${pd} 回环`, C.bifidDecode(C.bifidEncode(PLAIN_U, pd), pd), PLAIN_U);
}
eq('Polybius 回环', C.polybius(C.polybius(PLAIN_U, null, false), null, true), PLAIN_U.replace(/J/g, 'I'));
eq('Hill2 回环', C.hill2Decode(C.hill2Encode(PLAIN_U, 'DDCF'), 'DDCF'), PLAIN_U);
eq('Hill3 回环', C.hill3Decode(C.hill3Encode(PLAIN_U, 'GYBNQKURP'), 'GYBNQKURP'), PLAIN_U);
eq('猪圈回环', C.pigpenDecode(C.pigpenEncode(PLAIN_U)), PLAIN_U);
eq('培根26 回环', C.baconDecode(C.baconEncode(PLAIN_U, 26), 26), PLAIN_U);
eq('培根24 回环', C.baconDecode(C.baconEncode(PLAIN_U, 24), 24), PLAIN_U.replace(/J/g, 'I').replace(/U/g, 'V'));
eq('ADFGVX 回环', C.adfgvxDecode(C.adfgvxEncode(PLAIN_U, 'PHQGIUMEAYLNOFDXKRCVBZTWSJ', 'CARGO'), 'PHQGIUMEAYLNOFDXKRCVBZTWSJ', 'CARGO'), PLAIN_U);
eq('摩斯回环', C.morseDecode(C.morseEncode('HELLO WORLD 123')), 'HELLO WORLD 123');
eq('A1Z26 回环', C.a1z26Decode(C.a1z26Encode('HELLO WORLD')), 'HELLO WORLD');

/* ---------------- 3. 培根隐写 ---------------- */
{
  const cover = 'The quick brown fox jumps over the lazy dog and then runs away quickly today';
  const hidden = C.baconHide(cover, 'SECRET', 26);
  eq('培根隐写提取', C.baconExtract(hidden, 6), 'SECRET');
  eq('培根隐写载体未变（忽略大小写）', hidden.toLowerCase(), cover.toLowerCase());
}

/* ---------------- 4. 爆破器 ---------------- */
{
  const enc = C.caesar('hello world', 13);
  const hit = C.caesarBrute(enc).filter(x => x.text === 'hello world');
  eq('凯撒爆破命中', String(hit.length), '1');
  eq('凯撒爆破命中位移', String(hit[0].shift), '13');

  const rf = C.railFenceEncode('WEAREDISCOVEREDFLEEATONCE', 3);
  const hit2 = C.railFenceBrute(rf).filter(x => x.text === 'WEAREDISCOVEREDFLEEATONCE');
  eq('栅栏爆破命中', String(hit2.length >= 1), 'true');

  const co = C.columnarEncode('ATTACKATDAWN', 'KEY');
  const hit3 = C.columnarBrute(co, 3).filter(x => x.text === 'ATTACKATDAWN');
  eq('列移位爆破命中', String(hit3.length >= 1), 'true');

  const ab = C.affine('ATTACKATDAWN', 9, 4);
  const hit4 = C.affineBrute(ab).filter(x => x.text === 'ATTACKATDAWN');
  eq('仿射爆破命中唯一', String(hit4.length), '1');
  eq('仿射爆破命中参数', hit4.length ? `${hit4[0].a},${hit4[0].b}` : '', '9,4');
}

/* ---------------- 5. TOOLS 表自洽 ---------------- */
{
  const names = Object.keys(C.TOOLS);
  eq('TOOLS 条目数 >= 28', String(names.length >= 28), 'true');
  let bad = 0;
  for (const n of names) {
    const t = C.TOOLS[n];
    if (typeof t.enc !== 'function' || typeof t.dec !== 'function') { bad++; fails.push(`TOOLS ${n} 缺 enc/dec`); }
  }
  eq('TOOLS 全部可调用', String(bad), '0');
}

/* ---------------- 输出 ---------------- */
console.log('='.repeat(64));
console.log(`古典密码层：${pass} 通过 / ${fail} 失败   (工具 ${Object.keys(C.TOOLS).length} 种)`);
if (fails.length) { console.log('\n--- 明细 ---'); fails.forEach(f => console.log('  ' + f)); }
console.log('='.repeat(64));
process.exit(fail ? 1 : 0);
