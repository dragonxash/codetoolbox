/* ===========================================================================
 * 中文趣味 / 网络流行编码层测试
 *   node test/t-cncode.js
 * =========================================================================== */
const { load } = require('./_load.js');
const CT = load();
const N = CT.cncode;

let pass = 0, fail = 0;
const fails = [];
function eq(name, got, exp) {
  if (String(got) === String(exp)) pass++;
  else { fail++; if (fails.length < 30) fails.push(`FAIL ${name}\n     got ${JSON.stringify(got)}\n     exp ${JSON.stringify(exp)}`); }
}
function ok(name, cond, detail) { eq(name + (detail !== undefined ? `  [${detail}]` : ''), String(!!cond), 'true'); }

/* ---------------- 1. 核心价值观：真实 CTF 向量 ---------------- */
{
  const ct = '公正公正公正诚信文明公正民主公正法治法治友善平等和谐敬业和谐富强和谐富强和谐文明和谐平等公正公正和谐法治公正公正公正文明和谐民主和谐敬业和谐平等和谐敬业和谐敬业和谐和谐和谐公正法治友善法治';
  eq('核心价值观 解密真实 CTF 密文', N.coreValuesDecode(ct), 'flag{90025f7fb1959936}');

  // str2utf8 与标准十六进制等价
  eq('str2utf8 中文', N.str2utf8('中文'), 'E4B8ADE69687');
  eq('str2utf8 ASCII', N.str2utf8('abc'), '616263');
  eq('str2utf8 混排', N.str2utf8('a中'), '61E4B8AD');

  // 回环（固定分支 + 随机分支都要能解回来）
  for (const s of ['', 'a', 'hello world', '龙000の编码工具箱', 'flag{test_123}', '!@#$%^&*()']) {
    eq(`核心价值观 固定分支回环 ${JSON.stringify(s)}`, N.coreValuesDecode(N.coreValuesEncode(s, false)), s);
    eq(`核心价值观 随机分支回环 ${JSON.stringify(s)}`, N.coreValuesDecode(N.coreValuesEncode(s, true)), s);
  }
  // 编码结果只由 24 字词库构成
  const enc = N.coreValuesEncode('测试TEST', false);
  ok('核心价值观 编码字符全部来自词库', [...enc].every(c => N.CV_VALUES.includes(c)), enc.slice(0, 20));
  ok('核心价值观 词库为 24 字', N.CV_VALUES.length === 24, N.CV_VALUES.length);
}

/* ---------------- 2. 与佛论禅 ---------------- */
{
  ok('与佛论禅 核心已加载', N.buddha.available);
  for (const v of [1, 2]) {
    const s = 'hello 龙000 与佛论禅 ' + v;
    let e;
    try { e = N.buddha.encode(s, v); } catch (err) { fail++; fails.push(`THROW 与佛论禅 V${v} 加密: ${err.message}`); continue; }
    eq(`与佛论禅 V${v} 探测`, N.buddha.detect(e), v);
    eq(`与佛论禅 V${v} 回环`, N.buddha.decode(e), s);
  }
  eq('与佛论禅 V1 开头', N.buddha.encode('x', 1).slice(0, 3), '佛曰：'.slice(0, 3));
}

/* ---------------- 3. Brainfuck / Ook! ---------------- */
{
  // 经典 Hello World 程序（公开向量）
  const HW = '++++++++++[>+++++++>++++++++++>+++>+<<<<-]>++.>+.+++++++..+++.>++.<<+++++++++++++++.>.+++.------.--------.>+.>.';
  eq('Brainfuck 经典 Hello World', N.bfRunText(HW), 'Hello World!\n');

  eq('Brainfuck 编译回环 ASCII', N.bfRunText(N.bfEncode('Hello, World!')), 'Hello, World!');
  eq('Brainfuck 编译回环中文', N.bfRunText(N.bfEncode('龙000测试')), '龙000测试');
  eq('Brainfuck 编译回环空串', N.bfRunText(N.bfEncode('')), '');

  // Ook! 往返
  const ook = N.textToOok('Hi!');
  eq('Ook! 执行 → 原文', N.bfRunText(N.ookToBf(ook)), 'Hi!');
  eq('Ook! 片段数成对', String(N.textToOok('Hi!').trim().split(/\s+/).length % 2), '0');
  eq('Ook!←→BF 往返', N.ookToBf(N.bfToOok('+++[>+<-]>.+')), '+++[>+<-]>.+');
  ok('Ook! 只含 Ook. 与 Ook!', /^(Ook[.!?]\s*)+$/.test(ook), ook.slice(0, 40));

  // 括号不匹配要报错
  let threw = false;
  try { N.bfRun('+++[>+'); } catch (e) { threw = true; }
  eq('Brainfuck 括号不匹配报错', String(threw), 'true');
  // 死循环有步数上限
  threw = false;
  try { N.bfRun('+[]', null, { limit: 1000 }); } catch (e) { threw = true; }
  eq('Brainfuck 死循环保护', String(threw), 'true');

  // 输入指令 ,
  eq('Brainfuck 读入字符', N.bfRunText(',.,.', 'AB'), 'AB');
}

/* ---------------- 4. 零宽字符隐写 ---------------- */
{
  for (const s of ['', 'a', 'secret 消息', 'long '.repeat(20)]) {
    eq(`零宽 回环 len=${s.length}`, N.zwDecode(N.zwEncode(s)), s);
  }
  const hidden = N.zwHide('这是看起来完全正常的一句话。', '隐藏内容');
  eq('零宽 载体可见文本不变', hidden.replace(/[\u200b\u200c\u200d\ufeff]/g, ''), '这是看起来完全正常的一句话。');
  eq('零宽 从载体提取', N.zwExtract(hidden), '隐藏内容');
  ok('零宽 不可见字符占比 > 0', /[\u200b\u200c\u200d]/.test(hidden));
}

/* ---------------- 5. 八卦 / 六十四卦 ---------------- */
{
  for (const s of ['', 'a', 'hello 世界', '☯阴阳☯']) {
    eq(`八卦 回环 ${JSON.stringify(s)}`, N.baguaDecode(N.baguaEncode(s)), s);
    eq(`六十四卦 回环 ${JSON.stringify(s)}`, N.hexagramDecode(N.hexagramEncode(s)), s);
  }
  // 八卦按位还原：'a' = 0x61 = 141(八进制) = 1,4,1
  eq('八卦 单字节编码', N.baguaEncode('a'), N.TRIGRAM[1] + N.TRIGRAM[4] + N.TRIGRAM[1]);
  // 六十四卦首卦为 U+4DC0；单字节 0x00 → 8 位数据 + 补 4 位 = 两卦
  eq('六十四卦 首字符', N.hexagramEncode('\u0000'), String.fromCharCode(0x4dc0).repeat(2) + ' 4');
}

/* ---------------- 6. 嗷呜兽语 ---------------- */
{
  for (const s of ['', 'a', 'hello', '龙000']) {
    eq(`嗷呜 回环 ${JSON.stringify(s)}`, N.beastDecode(N.beastEncode(s)), s);
  }
  eq('嗷呜 只含嗷呜', /^[嗷呜\s]*$/.test(N.beastEncode('test')), 'true');
  eq('嗷呜 每字节 8 位', N.beastEncode('a').length, 8);
}

/* ---------------- 7. TOOLS 全量回环 ---------------- */
{
  const text = 'Hello 龙000 测试';
  let bad = 0;
  for (const name of Object.keys(N.TOOLS)) {
    const t = N.TOOLS[name];
    if (typeof t.enc !== 'function' || typeof t.dec !== 'function') { bad++; fails.push(`TOOLS ${name} 缺 enc/dec`); continue; }
    const params = {};
    for (const p of (t.params || [])) params[p.k] = p.def;
    let e;
    try { e = t.enc(text, params); } catch (err) { bad++; fails.push(`THROW ${name} 加密: ${err.message}`); continue; }
    try { eq(`TOOLS ${name} 回环`, t.dec(e, params), text); }
    catch (err) { bad++; fails.push(`THROW ${name} 解密: ${err.message}`); }
  }
  eq('TOOLS 全部可用', String(bad), '0');
  eq('TOOLS 条目数 >= 8', String(Object.keys(N.TOOLS).length >= 8), 'true');
}

/* ---------------- 输出 ---------------- */
console.log('='.repeat(64));
console.log(`中文趣味编码层：${pass} 通过 / ${fail} 失败   (工具 ${Object.keys(N.TOOLS).length} 种)`);
if (fails.length) { console.log('\n--- 明细 ---'); fails.forEach(f => console.log('  ' + f)); }
console.log('='.repeat(64));
process.exit(fail ? 1 : 0);
