/* 哈希层对拍
 * 主对照：Java MessageDigest/Mac 生成的 oracle.txt（JDK 权威实现）
 * 辅对照：node:crypto（SHA-2/SHA-3/RIPEMD/Keccak）、RFC 标准向量（MD4/SM3） */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { load } = require('./_load.js');
const CT = load();
const U = CT.util;

let pass = 0, fail = 0;
function eq(name, got, exp) {
  const A = typeof got === 'string' ? got : U.hex(got);
  const B = typeof exp === 'string' ? exp : U.hex(exp);
  if (A === B) pass++;
  else { fail++; console.log('FAIL ' + name + '\n  got ' + A + '\n  exp ' + B); }
}

// 与 Java 预言机使用完全相同的消息构造
function msgOf(n) {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 37 + 11) & 0xff;
  return b;
}
const LENS = [0,1,15,16,17,31,32,47,48,55,56,57,63,64,65,79,80,100,111,112,113,127,128,129,1000];

/* ---------- 1. Java 预言机 ---------- */
const oraclePath = path.join(__dirname, 'oracle', 'oracle.txt');
if (fs.existsSync(oraclePath)) {
  const lines = fs.readFileSync(oraclePath, 'utf8').trim().split('\n');
  const HASHMAP = {
    'MD2': 'MD2', 'MD5': 'MD5', 'SHA-1': 'SHA-1', 'SHA-224': 'SHA-224',
    'SHA-256': 'SHA-256', 'SHA-384': 'SHA-384', 'SHA-512': 'SHA-512',
    'SHA3-224': 'SHA3-224', 'SHA3-256': 'SHA3-256', 'SHA3-384': 'SHA3-384', 'SHA3-512': 'SHA3-512'
  };
  let used = 0;
  for (const ln of lines) {
    const sp1 = ln.indexOf(' '), sp2 = ln.indexOf(' ', sp1 + 1);
    const name = ln.slice(0, sp1), len = +ln.slice(sp1 + 1, sp2), hex = ln.slice(sp2 + 1).trim();
    if (name.startsWith('SKIP')) continue;
    const m = msgOf(len);
    if (name.startsWith('HMAC-')) {
      const algo = name.slice(5);
      eq('Java HMAC-' + algo + ' len=' + len, CT.hash.hmac(algo, U.utf8Enc('key-龙000'), m), hex);
      used++;
    } else if (HASHMAP[name]) {
      eq('Java ' + name + ' len=' + len, CT.hash.ALGOS[HASHMAP[name]].fn(m), hex);
      used++;
    }
  }
  console.log('Java 预言机：比对 ' + used + ' 条');
} else {
  console.log('未找到 oracle.txt，跳过 Java 对拍');
}

/* ---------- 2. node:crypto 对拍（含逐长度边界） ---------- */
const NODEMAP = [['MD5','md5'],['SHA-1','sha1'],['SHA-224','sha224'],['SHA-256','sha256'],
                 ['SHA-384','sha384'],['SHA-512','sha512'],
                 ['SHA3-224','sha3-224'],['SHA3-256','sha3-256'],['SHA3-384','sha3-384'],['SHA3-512','sha3-512']];
for (const [name, nodeName] of NODEMAP) {
  for (const n of LENS) {
    const m = msgOf(n);
    eq('node ' + name + ' len=' + n, CT.hash.ALGOS[name].fn(m),
       crypto.createHash(nodeName).update(Buffer.from(m)).digest('hex'));
  }
}

/* ---------- 3. RIPEMD-160 / Keccak / SHAKE / SM3 ---------- */
for (const n of LENS) {
  const m = msgOf(n);
  eq('node RIPEMD-160 len=' + n, CT.hash.ripemd160(m),
     crypto.createHash('ripemd160').update(Buffer.from(m)).digest('hex'));
}
eq('Keccak-256("")', CT.hash.keccak256(new Uint8Array(0)),
   'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
eq('Keccak-256("abc")', CT.hash.keccak256(U.utf8Enc('abc')),
   '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
eq('SHAKE128("",32)', CT.hash.shake128(new Uint8Array(0), 32),
   '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26');
eq('SHAKE256("",32)', CT.hash.shake256(new Uint8Array(0), 32),
   '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f');

let sm3Native = false;
try { crypto.createHash('sm3').update('x').digest(); sm3Native = true; } catch (e) { /* noop */ }
if (sm3Native) {
  for (const n of LENS) {
    const m = msgOf(n);
    eq('node SM3 len=' + n, CT.hash.sm3(m), crypto.createHash('sm3').update(Buffer.from(m)).digest('hex'));
    eq('node HMAC-SM3 len=' + n, CT.hash.hmac('SM3', U.utf8Enc('key-龙000'), m),
       crypto.createHmac('sm3', Buffer.from('key-龙000')).update(Buffer.from(m)).digest('hex'));
  }
} else {
  eq('SM3("abc")', CT.hash.sm3(U.utf8Enc('abc')),
     '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0');
  eq('SM3(64×"abcd")', CT.hash.sm3(U.utf8Enc('abcd'.repeat(16))),
     'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732');
  console.log('（本机 OpenSSL 无 sm3，改用 GB/T 32905 标准向量）');
}

/* ---------- 4. MD4（Java 21 已移除，用 RFC 1320 向量） ---------- */
const MD4V = {
  '': '31d6cfe0d16ae931b73c59d7e0c089c0',
  'a': 'bde52cb31de33e46245e05fbdbd6fb24',
  'abc': 'a448017aaf21d8525fc10ae87aa6729d',
  'message digest': 'd9130a8164549fe818874806e1c7014b',
  'abcdefghijklmnopqrstuvwxyz': 'd79e1c308aa5bbcdeea8ed63df412da9',
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789': '043f8582f241db351ce627e153e7f0e4',
  '12345678901234567890123456789012345678901234567890123456789012345678901234567890': 'e33b4ddc9c38f2199c3e7b164fcc0536'
};
for (const [k, v] of Object.entries(MD4V)) eq('MD4("' + k.slice(0, 16) + '")', CT.hash.md4(U.utf8Enc(k)), v);

/* ---------- 5. 校验和 ---------- */
const zlib = require('zlib');
for (const n of LENS) {
  const m = msgOf(n);
  eq('CRC32 len=' + n, CT.hash.crc32Text(m), (CT.util.crc32(m) >>> 0).toString(16));
  if (zlib.crc32) eq('CRC32(zlib) len=' + n, CT.util.crc32(m) >>> 0, zlib.crc32(Buffer.from(m)) >>> 0);
}
eq('CRC32("123456789")', CT.hash.crc32Text(U.utf8Enc('123456789')), 'cbf43926');
eq('CRC32C("123456789")', (CT.util.crc32c(U.utf8Enc('123456789')) >>> 0).toString(16), 'e3069283');
eq('Adler32("Wikipedia")', CT.hash.adler32Text(U.utf8Enc('Wikipedia')), '11e60398');
eq('Adler32("123456789")', CT.hash.adler32Text(U.utf8Enc('123456789')), '91e01de');
if (zlib.adler32) for (const n of LENS) eq('Adler32(zlib) len=' + n, CT.util.adler32(msgOf(n)) >>> 0, zlib.adler32(Buffer.from(msgOf(n))) >>> 0);
const crc16check = u => CT.util.crc16(U.utf8Enc('123456789'), u.poly, u.init, u.refin, u.refout, u.xorout);
eq('CRC-16/ARC', crc16check(CT.util.CRC16_VARIANTS['CRC-16/ARC']).toString(16), 'bb3d');
eq('CRC-16/MODBUS', crc16check(CT.util.CRC16_VARIANTS['CRC-16/MODBUS']).toString(16), '4b37');
eq('CRC-16/XMODEM', crc16check(CT.util.CRC16_VARIANTS['CRC-16/XMODEM']).toString(16), '31c3');
eq('CRC-16/USB', crc16check(CT.util.CRC16_VARIANTS['CRC-16/USB']).toString(16), 'b4c8');
eq('CRC-16/X-25', crc16check(CT.util.CRC16_VARIANTS['CRC-16/X-25']).toString(16), '906e');
eq('CRC-16/DNP', crc16check(CT.util.CRC16_VARIANTS['CRC-16/DNP']).toString(16), 'ea82');
eq('JavaHash("hello")', '' + CT.hash.javaHash(U.utf8Enc('hello')), '99162322');
eq('JavaHash("编码工具箱")', '' + CT.hash.javaHash(U.utf8Enc('编码工具箱')),
   '' + '编码工具箱'.split('').reduce((h, c) => (Math.imul(31, h) + c.charCodeAt(0)) | 0, 0));

/* ---------- 6. PBKDF2 ---------- */
eq('PBKDF2-SHA256', CT.hash.pbkdf2('SHA-256', U.utf8Enc('password'), U.utf8Enc('salt'), 1000, 40),
   crypto.pbkdf2Sync('password', 'salt', 1000, 40, 'sha256').toString('hex'));
eq('PBKDF2-SHA1', CT.hash.pbkdf2('SHA-1', U.utf8Enc('passwordPASSWORDpassword'),
   U.utf8Enc('saltSALTsaltSALTsaltSALTsaltSALTsalt'), 4096, 25),
   crypto.pbkdf2Sync('passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 25, 'sha1').toString('hex'));
eq('PBKDF2-SHA512', CT.hash.pbkdf2('SHA-512', U.utf8Enc('pw'), U.utf8Enc('na'), 100, 64),
   crypto.pbkdf2Sync('pw', 'na', 100, 64, 'sha512').toString('hex'));

console.log('\n哈希层：' + pass + ' 通过 / ' + fail + ' 失败');
process.exit(fail ? 1 : 0);
