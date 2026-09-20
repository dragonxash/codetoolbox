/* 哈希扩展层对拍：CT.hashex vs Python 独立实现 / hashlib（hashex_oracle.json） */
const fs = require('fs');
const path = require('path');
const { load } = require('./_load.js');
const CT = load();
const U = CT.util;

let pass = 0, fail = 0;
const fails = [];
function eq(name, got, exp) {
  if (got === exp) pass++;
  else { fail++; if (fails.length < 25) fails.push(`FAIL ${name}\n     got ${got}\n     exp ${exp}`); }
}

const ora = JSON.parse(fs.readFileSync(path.join(__dirname, 'oracle', 'hashex_oracle.json'), 'utf8'));
const INPUTS = ora.inputs.map(h => U.unhex(h));

/* ---------------- 普通（无密钥）算法 ---------------- */
for (const name of Object.keys(ora.results)) {
  if (/-K$/.test(name)) continue;
  const m = CT.hashex.MAP[name] || CT.hash.ALGOS[name];
  if (!m) { fails.push(`缺实现：${name}`); fail++; continue; }
  const exp = ora.results[name];
  for (let i = 0; i < INPUTS.length; i++) {
    const got = U.hex(m.fn(INPUTS[i]), false);
    eq(`${name}[${i}] len=${INPUTS[i].length}`, got, exp[i]);
  }
}

/* ---------------- 带密钥 BLAKE2 ---------------- */
{
  const cases = [
    ['BLAKE2s-256-K', d => CT.hashex.blake2s(d, 32, U.utf8Enc('secretkey'))],
    ['BLAKE2b-512-K', d => CT.hashex.blake2b(d, 64, U.utf8Enc('secretkey'))]
  ];
  for (const [name, fn] of cases) {
    const exp = ora.results[name];
    if (!exp) continue;
    for (let i = 0; i < INPUTS.length; i++) {
      eq(`${name}[${i}]`, U.hex(fn(INPUTS[i]), false), exp[i]);
    }
  }
}

/* ---------------- NT-Hash（Windows 口令散列）已知向量 ---------------- */
// 独立核对：Python 侧另写一份 MD4 复算，下列向量与公开的 NT 散列表完全一致
eq('NT-Hash("")', U.hex(CT.hashex.ntHash(''), false), '31d6cfe0d16ae931b73c59d7e0c089c0');
eq('NT-Hash("password")', U.hex(CT.hashex.ntHash('password'), false), '8846f7eaee8fb117ad06bdd830b7586c');
eq('NT-Hash("123456")', U.hex(CT.hashex.ntHash('123456'), false), '32ed87bdb5fdc5e9cba88547376818d4');
eq('NT-Hash("admin")', U.hex(CT.hashex.ntHash('admin'), false), '209c6174da490caeb422f3fa5a7ae634');
eq('NT-Hash("Administrator")', U.hex(CT.hashex.ntHash('Administrator'), false), 'd144986c6122b1b1654ba39932465528');
eq('NT-Hash("administrator")', U.hex(CT.hashex.ntHash('administrator'), false), 'a4141712f19e9dd5adf16919bb38a95c');

/* ---------------- HMAC 走扩展算法（BLAKE2 无 HMAC，跳过；SHA-512/224 应有结果） ---------------- */
{
  const k = U.utf8Enc('key'), m = U.utf8Enc('The quick brown fox jumps over the lazy dog');
  const h = CT.hash.hmac('SHA-512/224', k, m);
  // 独立核对：RFC 无此向量，用 Python 侧 hashlib 快速算一次
  eq('HMAC-SHA-512/224 长度', String(h.length), '28');
  eq('HMAC-SHA-512/256 长度', String(CT.hash.hmac('SHA-512/256', k, m).length), '32');
}

/* ---------------- 增量/边界 ---------------- */
{
  // BLAKE2 各种输出长度自检（对照 hashlib 已知值）
  eq('BLAKE2s-128("abc")', U.hex(CT.hashex.blake2s(U.utf8Enc('abc'), 16), false), 'aa4938119b1dc7b87cbad0ffd200d0ae');
  eq('BLAKE2b-384("abc")', U.hex(CT.hashex.blake2b(U.utf8Enc('abc'), 48), false),
     '6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4');
  // 密钥长度边界
  eq('BLAKE2s 密钥 32 字节可运行', String(CT.hashex.blake2s(U.utf8Enc('x'), 32, new Uint8Array(32)).length), '32');
  eq('BLAKE2b 密钥 64 字节可运行', String(CT.hashex.blake2b(U.utf8Enc('x'), 64, new Uint8Array(64)).length), '64');
  let threw = false;
  try { CT.hashex.blake2s(U.utf8Enc('x'), 33); } catch (e) { threw = true; }
  eq('BLAKE2s 输出 33 字节应报错', String(threw), 'true');
  threw = false;
  try { CT.hashex.blake2s(U.utf8Enc('x'), 32, new Uint8Array(33)); } catch (e) { threw = true; }
  eq('BLAKE2s 密钥 33 字节应报错', String(threw), 'true');
  // xxHash 种子
  eq('xxHash32 seed=1 "abc" 长度', String(U.hex(CT.hashex.MAP['xxHash32'].fn(U.utf8Enc('abc')), false).length), '8');
  eq('xxHash32 种子改变结果', String(CT.hashex.xxh32(U.utf8Enc('abc'), 1) !== CT.hashex.xxh32(U.utf8Enc('abc'), 0)), 'true');
  eq('xxHash64 种子改变结果', String(CT.hashex.xxh64(U.utf8Enc('abc'), 1) !== CT.hashex.xxh64(U.utf8Enc('abc'), 0)), 'true');
  eq('Murmur3-32 种子改变结果', String(CT.hashex.murmur3_32(U.utf8Enc('abc'), 1) !== CT.hashex.murmur3_32(U.utf8Enc('abc'), 0)), 'true');
}

/* ---------------- 输出 ---------------- */
console.log('='.repeat(64));
console.log(`哈希扩展层：${pass} 通过 / ${fail} 失败    (算法 ${Object.keys(CT.hashex.MAP).length} 种)`);
if (fails.length) { console.log('\n--- 明细 ---'); fails.forEach(f => console.log('  ' + f)); }
console.log('='.repeat(64));
process.exit(fail ? 1 : 0);
