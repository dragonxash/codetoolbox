/* ===========================================================================
 * 实用工具层测试：node test/t-misc.js
 * =========================================================================== */
const { load } = require('./_load.js');
const CT = load();
const M = CT.misc;

let pass = 0, fail = 0;
const fails = [];
function eq(name, got, exp) {
  if (String(got) === String(exp)) pass++;
  else { fail++; if (fails.length < 30) fails.push(`FAIL ${name}\n     got ${JSON.stringify(got)}\n     exp ${JSON.stringify(exp)}`); }
}
function ok(name, cond, detail) { eq(name + (detail !== undefined ? `  [${detail}]` : ''), String(!!cond), 'true'); }
function has(list, kw) { return list.some(x => x.name.includes(kw)); }

/* ---------------- URL ---------------- */
eq('URL 组件编码 中文', M.urlEncodeComponent('中文'), '%E4%B8%AD%E6%96%87');
eq('URL 组件编码 a b', M.urlEncodeComponent('a b&c'), 'a%20b%26c');
eq('URL 组件回环', M.urlDecodeComponent(M.urlEncodeComponent('龙000 ?&=/+')), '龙000 ?&=/+');
eq('URL 整体编码不转义 /', M.urlEncodeFull('a/b?c=1'), 'a/b?c=1');
eq('表单编码 空格→+', M.formEncode('a b'), 'a+b');
eq('表单解码 +→空格', M.formDecode('a+b'), 'a b');

/* ---------------- HTML / Unicode ---------------- */
eq('HTML 实体', M.htmlEncode('<a href="x">&\''), '&lt;a&nbsp;href=&quot;x&quot;&gt;&amp;&#39;');
eq('HTML 实体(全)', M.htmlEncode('AB', true), '&#65;&#66;');
eq('HTML 解码 十进制', M.htmlDecode('&#65;&#66;'), 'AB');
eq('HTML 解码 十六进制', M.htmlDecode('&#x41;&#x4e2d;'), 'A中');
eq('HTML 解码 命名', M.htmlDecode('&lt;br&gt;&amp;&nbsp;'), '<br>& ');
eq('HTML 回环', M.htmlDecode(M.htmlEncode('<a>&"\'')), '<a>&"\'');

eq('Unicode 转义 中', M.escUnicode('中'), '\\u4e2d');
eq('Unicode 转义 表情', M.escUnicode('😀'), '\\u{1f600}');
eq('Unicode 反转义', M.unescUnicode('\\u4e2d\\u6587'), '中文');
eq('Unicode 反转义 %u', M.unescUnicode('%u4e2d'), '中');
eq('Unicode 反转义 U+', M.unescUnicode('U+4E2D'), '中');
eq('Unicode 回环', M.unescUnicode(M.escUnicode('abc中😀')), 'abc中😀');

eq('C 转义', M.escC('a\t"b"\\'), 'a\\t\\"b\\"\\\\');
eq('C 反转义', M.unescC('a\\n\\x41\\u4e2d'), 'a\nA中');
eq('C 转义回环', M.unescC(M.escC('a\tb\n"c"\\d')), 'a\tb\n"c"\\d');

eq('QP 编码 等号', M.qpEncode('='), '=3D');
eq('QP 编码 普通文本', M.qpEncode('Hello world'), 'Hello world');
eq('QP 回环', M.qpDecode(M.qpEncode('中文=test 测试')), '中文=test 测试');

/* ---------------- 进制 ---------------- */
eq('10→16', M.convertBase('255', 10, 16), 'ff');
eq('16→10', M.convertBase('ff', 16, 10), '255');
eq('16→10 deadbeef', M.convertBase('DEADBEEF', 16, 10), '3735928559');
eq('2→10', M.convertBase('11111111', 2, 10), '255');
eq('10→2', M.convertBase('255', 10, 2), '11111111');
eq('10→8', M.convertBase('511', 10, 8), '777');
eq('36 进制', M.convertBase('zz', 36, 10), '1295');
eq('大写输出', M.convertBase('255', 10, 16, true), 'FF');
eq('大数 2^64 → 16', M.convertBase('18446744073709551616', 10, 16), '10000000000000000');
eq('大数 16 → 10', M.convertBase('ffffffffffffffff', 16, 10), '18446744073709551615');
eq('负数处理', M.convertBase('-255', 10, 16), '-ff');
eq('0x 前缀', M.convertBase('0xff', 16, 10), '255');
let threw = false;
try { M.convertBase('xyz', 10, 16); } catch (e) { threw = true; }
eq('非法数字报错', String(threw), 'true');

eq('文本→二进制', M.textToBinary('AB'), '01000001 01000010');
eq('二进制→文本', M.binaryToText('01000001 01000010'), 'AB');
eq('文本→八进制', M.textToOctal('AB'), '101 102');
eq('八进制→文本', M.octalToText('101 102'), 'AB');
eq('文本→十进制', M.textToDecimal('AB'), '65 66');
eq('十进制→文本', M.decimalToText('65 66'), 'AB');
eq('二进制回环 中文', M.binaryToText(M.textToBinary('中文')), '中文');
eq('大整数→文本 可执行', typeof M.bigIntToText('98955458163654'), 'string');
eq('大整数→文本 已知值', M.bigIntToText(M.convertBase('414243', 16, 10)), 'ABC');
eq('大整数→文本 中文', M.bigIntToText(M.convertBase(new TextEncoder().encode('中文').reduce((a, b) => a + b.toString(16).padStart(2, '0'), ''), 16, 10)), '中文');

/* ---------------- 生成 ---------------- */
eq('UUID v4 格式', /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(M.uuidV4()), 'true');
eq('UUID v1 格式', /^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(M.uuidV1()), 'true');
eq('UUID nil', M.uuidNil(), '00000000-0000-0000-0000-000000000000');
eq('随机串长度', M.randomString(32).length, 32);
eq('随机串字符集', /^[0-9]+$/.test(M.randomString(64, M.CHARSETS['数字'])), 'true');
eq('随机串两次不同', String(M.randomString(24) !== M.randomString(24)), 'true');

{
  const t = M.timestamp(1600000000000);
  eq('时间戳 秒', t.seconds, '1600000000');
  eq('时间戳 ISO', t.iso, '2020-09-13T12:26:40.000Z');
  const t2 = M.timestamp(1600000000, 's');
  eq('秒级时间戳等价毫秒', t2.ms, '1600000000000');
  const t3 = M.timestamp('2020-09-13T12:26:40Z');
  eq('日期串解析', t3.ms, '1600000000000');
}

/* ---------------- 文本处理 ---------------- */
{
  const s = '第一行\n第二行 abc\n\n第三行';
  const st = M.stats(s);
  eq('统计 行数', st.lines, 4);
  eq('统计 汉字数', st.cjk, 9);
  eq('统计 字节数', st.bytes, new TextEncoder().encode(s).length);
  eq('统计 非 ASCII', String(st.hasNonAscii), 'true');
  eq('统计 空串', M.stats('').lines, 0);

  eq('大小写反转', M.swapCase('AbC'), 'aBc');
  eq('反转', M.reverse('abc中'), '中cba');
  eq('反转行序', M.reverseLines('a\nb\nc'), 'c\nb\na');
  eq('去重行', M.uniqueLines('a\nb\na'), 'a\nb');
  eq('排序行', M.sortLines('c\na\nb'), 'a\nb\nc');
  eq('去掉空行', M.removeEmptyLines('a\n\n\nb'), 'a\nb');
  eq('加行号', M.numberLines('a\nb'), '1. a\n2. b');
  eq('去行号', M.stripNumbering('1. a\n2、b'), 'a\nb');
  eq('去空白', M.removeWhitespace(' a b\t c '), 'abc');
  eq('压缩空格', M.collapseSpaces('a   b'), 'a b');

  eq('驼峰', M.toNaming('hello world foo-bar', 'camel'), 'helloWorldFooBar');
  eq('大驼峰', M.toNaming('hello_world', 'pascal'), 'HelloWorld');
  eq('下划线', M.toNaming('helloWorld', 'snake'), 'hello_world');
  eq('常量', M.toNaming('helloWorld', 'constant'), 'HELLO_WORLD');
  eq('短横线', M.toNaming('helloWorld', 'kebab'), 'hello-world');
}

/* ---------------- 编码嗅探 ---------------- */
ok('嗅探 佛曰', has(M.detect('佛曰：啊啊啊'), '与佛论禅'));
ok('嗅探 如是我闻', has(M.detect('如是我闻：啊啊'), '与佛论禅'));
ok('嗅探 MD5', has(M.detect('5d41402abc4b2a76b9719d911017c592'), 'MD5'));
ok('嗅探 SHA-256', has(M.detect('a'.repeat(64)), 'SHA-256'));
ok('嗅探 二进制', has(M.detect('01000001 01000010'), '二进制'));
ok('嗅探 URL', has(M.detect('%E4%B8%AD%E6%96%87'), 'URL'));
ok('嗅探 JSON', has(M.detect('{"a":1}'), 'JSON'));
ok('嗅探 零宽', has(M.detect('\u200b\u200c\u200b'), '零宽'));
ok('嗅探 UUID', has(M.detect('550e8400-e29b-41d4-a716-446655440000'), 'UUID'));
ok('嗅探 时间戳(秒)', has(M.detect('1600000000'), '时间戳'));
ok('嗅探 核心价值观', has(M.detect('富强民主文明和谐自由平等公正法治爱国敬业诚信友善'), '核心价值观'));
ok('嗅探 Ook', has(M.detect('Ook. Ook? Ook! Ook!'), 'Ook'));
ok('嗅探 Unicode 转义', has(M.detect('\\u4e2d\\u6587'), 'Unicode'));
ok('嗅探 摩斯', has(M.detect('... --- ...'), '摩斯'));
ok('嗅探 空串无结果', M.detect('').length === 0);
ok('嗅探 按置信度降序', (() => { const l = M.detect('%E4%B8%AD%E6%96%87 中文'); return l.every((x, i) => i === 0 || l[i - 1].conf >= x.conf); })());

function ok(name, cond, detail) { eq(name + (detail !== undefined ? `  [${detail}]` : ''), String(!!cond), 'true'); }
  const list = M.detect('%E4%B8%AD%E6%96%87 中文');
  eq('嗅探 URL 置信度降序', String(list.every((x, i) => i === 0 || list[i - 1].conf >= x.conf)), 'true');

/* ---------------- TOOLS 全量回环 ---------------- */
{
  const samples = ['Hello 龙000 测试!', 'a b&c=d', '<tag>&"\'', 'line1\nline2'];
  let bad = 0;
  for (const name of Object.keys(M.TOOLS)) {
    const t = M.TOOLS[name];
    if (typeof t.enc !== 'function' || typeof t.dec !== 'function') { bad++; fails.push(`TOOLS ${name} 缺 enc/dec`); continue; }
    if (t.numeric) continue;                    // 需要数字输入，单独测
    const params = {};
    for (const p of (t.params || [])) params[p.k] = p.def;
    for (const s of samples) {
      let e;
      try { e = t.enc(s, params); } catch (err) { bad++; fails.push(`THROW ${name} 加密「${s}」: ${err.message}`); continue; }
      try { eq(`TOOLS ${name} 回环「${s.slice(0, 12)}」`, t.dec(e, params), s); }
      catch (err) { bad++; fails.push(`THROW ${name} 解密「${s}」: ${err.message}`); }
    }
  }
  eq('TOOLS 全部可用', String(bad), '0');
}

/* ---------------- 输出 ---------------- */
console.log('='.repeat(64));
console.log(`实用工具层：${pass} 通过 / ${fail} 失败   (工具 ${Object.keys(M.TOOLS).length} 种)`);
if (fails.length) { console.log('\n--- 明细 ---'); fails.forEach(f => console.log('  ' + f)); }
console.log('='.repeat(64));
process.exit(fail ? 1 : 0);
