/* 扩展哈希层对拍：CT.hash2 vs OpenSSL(Whirlpool) / hashlib(SHAKE) / Python 参考 */
const fs = require('fs');
const path = require('path');
const { load } = require('./_load.js');
const CT = load();
const U = CT.util;
const H2 = CT.hash2;

let pass = 0, fail = 0;
const fails = [];
function eq(name, got, exp) {
  if (got === exp) pass++;
  else { fail++; if (fails.length < 30) fails.push(`FAIL ${name}\n     got ${got}\n     exp ${exp}`); }
}

const ora = JSON.parse(fs.readFileSync(path.join(__dirname, 'oracle', 'hash2_oracle.json'), 'utf8'));
const INPUTS = ora.inputs.map(h => U.unhex(h));

/* ---------------- 1. 对拍参考实现 ---------------- */
// 键：oracle 中的名字 → 本库算法名
const PAIR = {
  whirlpool: 'Whirlpool',
  shake128: 'SHAKE128',
  shake256: 'SHAKE256',
  fletcher16: 'Fletcher-16',
  fletcher32: 'Fletcher-32',
  elf: 'ELFHash',
  oneatatime: 'OneAtATime',
  fnv1a128: 'FNV-1a-128',
  bsdsum: 'BSDSum',
  sysvsum: 'SYSVSum'
};

for (const oraName of Object.keys(PAIR)) {
  const name = PAIR[oraName];
  const entry = H2.MAP[name];
  if (!entry) { fails.push('缺实现：' + name); fail++; continue; }
  const exp = ora.results[oraName];
  if (!exp) { fails.push('缺对拍数据：' + oraName); fail++; continue; }
  for (let i = 0; i < INPUTS.length; i++) {
    let got;
    try { got = U.hex(entry.fn(INPUTS[i]), false); } catch (e) { got = 'ERR:' + e.message; }
    eq(`${name}[${i}] len=${INPUTS[i].length}`, got, exp[i]);
  }
}

/* ---------------- 2. Whirlpool 公开向量 ---------------- */
// ISO/IEC 10118-3 标准测试向量
eq('Whirlpool("")', U.hex(H2.whirlpool(U.utf8Enc('')), false),
   '19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3');
eq('Whirlpool("abc")', U.hex(H2.whirlpool(U.utf8Enc('abc')), false),
   '4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5');

/* ---------------- 3. SipHash-2-4 公开向量 ---------------- */
// 参考实现标准向量：key = 00 01 ... 0f，空输入 → 0x726fdb47dd0e0e31（小端输出）
{
  const key = U.unhex('000102030405060708090a0b0c0d0e0f');
  eq('SipHash-2-4(空)', U.hex(H2.siphash24(new Uint8Array(0), key), false), '310e0edd47db6f72');
  // 密钥不同结果不同；同钥同输入稳定
  eq('SipHash 稳定', U.hex(H2.siphash24(U.utf8Enc('abc'), key), false),
     U.hex(H2.siphash24(U.utf8Enc('abc'), key), false));
  eq('SipHash 密钥敏感', String(U.hex(H2.siphash24(U.utf8Enc('abc'), key), false) !==
     U.hex(H2.siphash24(U.utf8Enc('abc'), new Uint8Array(16)), false)), 'true');
  eq('SipHash 输出 8 字节', String(H2.siphash24(U.utf8Enc('x'), key).length), '8');
  let threw = false;
  try { H2.siphash24(U.utf8Enc('x'), new Uint8Array(8)); } catch (e) { threw = true; }
  eq('SipHash 密钥长度校验', String(threw), 'true');
  // SipHash-1-3 / 4-8 变体应可用
  eq('SipHash-1-3 长度', String(H2.siphash24(U.utf8Enc('x'), key, 1, 3).length), '8');
  eq('SipHash-4-8 长度', String(H2.siphash24(U.utf8Enc('x'), key, 4, 8).length), '8');
}

/* ---------------- 4. Poly1305 RFC 8439 §2.5.2 向量 ---------------- */
{
  const key = U.unhex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b');
  const msg = U.utf8Enc('Cryptographic Forum Research Group');
  eq('Poly1305(RFC 8439)', U.hex(H2.poly1305(msg, key), false), 'a8061dc1305136c6c22b8baf0c0127a9');
  eq('Poly1305 输出 16 字节', String(H2.poly1305(msg, key).length), '16');
  // 空消息：acc=0 → tag = s（密钥后半段）
  const k2 = U.unhex('00'.repeat(16) + '0102030405060708090a0b0c0d0e0f10');
  eq('Poly1305(空消息)', U.hex(H2.poly1305(new Uint8Array(0), k2), false), '0102030405060708090a0b0c0d0e0f10');
  let threw = false;
  try { H2.poly1305(msg, new Uint8Array(16)); } catch (e) { threw = true; }
  eq('Poly1305 密钥长度校验', String(threw), 'true');
  // 不足 16 字节的尾块（补 0x01 规则）
  eq('Poly1305 短块长度', String(H2.poly1305(U.utf8Enc('abc'), key).length), '16');
}

/* ---------------- 5. SHAKE 可变输出长度 ---------------- */
{
  const m = U.utf8Enc('abc');
  eq('SHAKE128 16B', String(H2.shake128(m, 16).length), '16');
  eq('SHAKE128 200B', String(H2.shake128(m, 200).length), '200');
  eq('SHAKE256 200B', String(H2.shake256(m, 200).length), '200');
  // XOF 前缀一致性：长输出的前 32 字节应等于短输出
  eq('SHAKE128 前缀一致', U.hex(H2.shake128(m, 200).slice(0, 32), false), U.hex(H2.shake128(m, 32), false));
  eq('SHAKE256 前缀一致', U.hex(H2.shake256(m, 200).slice(0, 64), false), U.hex(H2.shake256(m, 64), false));
}

/* ---------------- 6. Fletcher 边界 ---------------- */
eq('Fletcher-16 空', String(H2.fletcher16(new Uint8Array(0))), '0');
eq('Fletcher-32 空', String(H2.fletcher32(new Uint8Array(0))), '0');
eq('Fletcher-16("a")', String(H2.fletcher16(U.utf8Enc('a'))), '0x6161'.length ? String(0x61 * 256 + 0x61) : '');
eq('Fletcher-16 单字节 0xFF', String(H2.fletcher16(new Uint8Array([0xFF]))), '0');
eq('BSDSum 空', String(H2.bsdSum(new Uint8Array(0))), '0');
eq('SYSVSum 空', String(H2.sysvSum(new Uint8Array(0))), '0');
eq('SYSVSum 进位折叠', String(H2.sysvSum(new Uint8Array([0xFF, 0xFF, 0x01]))), String(0x1FF));
eq('ELFHash 空', U.hex(U.packU32BE(H2.elfHash(new Uint8Array(0))), false), '00000000');
eq('OneAtATime 空', U.hex(U.packU32BE(H2.oneAtATime(new Uint8Array(0))), false), '00000000');

/* ---------------- 7. 并入主哈希表 ---------------- */
{
  eq('Whirlpool 已并入 CT.hash.ALGOS', String(!!CT.hash.ALGOS['Whirlpool']), 'true');
  eq('并入后结果一致', U.hex(CT.hash.ALGOS['Whirlpool'].fn(U.utf8Enc('abc')), false),
     U.hex(H2.whirlpool(U.utf8Enc('abc')), false));
}

console.log('='.repeat(64));
console.log(`扩展哈希层：${pass} 通过 / ${fail} 失败    (算法 ${Object.keys(H2.MAP).length} 种)`);
if (fails.length) { console.log('\n--- 明细 ---'); fails.forEach(f => console.log('  ' + f)); }
console.log('='.repeat(64));
process.exit(fail ? 1 : 0);
