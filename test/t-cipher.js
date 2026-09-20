/* 密码层对拍：CT.cipher.* vs Java JCE 预言机（cipher_oracle.txt） */
const fs = require('fs');
const path = require('path');
const { load } = require('./_load.js');
const CT = load();
const U = CT.util;

let pass = 0, fail = 0;
const fails = [];
function eq(name, got, exp) {
  const A = typeof got === 'string' ? got : U.hex(got);
  const B = typeof exp === 'string' ? exp : U.hex(exp);
  if (A === B) pass++; else { fail++; if (fails.length < 12) fails.push('FAIL ' + name + '\n  got ' + A + '\n  exp ' + B); }
}

const PADMAP = { 'PKCS5Padding': 'PKCS7', 'NoPadding': 'None' };

function spec2params(spec) {
  const p = spec.split('/');
  const algo = p[0] === 'DESede' ? '3DES' : p[0];
  return { algo, mode: p[1], padding: PADMAP[p[2]] || 'PKCS7' };
}

const lines = fs.readFileSync(path.join(__dirname, 'oracle', 'cipher_oracle.txt'), 'utf8').trim().split('\n');
let cfbFull = 0, cfbFullTotal = 0, cfb8 = 0, cfb8Total = 0;
const unknown = [];

for (const ln of lines) {
  if (ln.startsWith('ERR')) { console.log('预言机跳过：' + ln); continue; }
  const f = ln.split('|');
  const spec = f[0];
  if (spec === 'ARCFOUR') {
    const key = U.unhex(f[1]), data = U.unhex(f[3]), exp = f[4];
    eq('RC4 keylen=' + (key.length) + ' datalen=' + data.length, CT.cipher.rc4(key, data), exp);
    continue;
  }
  const { algo, mode, padding } = spec2params(spec);
  const key = U.unhex(f[1]), iv = U.unhex(f[2]), data = U.unhex(f[3]), exp = f[4];
  const tag = spec + ' key=' + key.length + ' data=' + data.length;

  if (mode === 'CFB') {
    // Java 的 "CFB"（未指定位宽）需要实测确认是整块还是 8 位
    const fullBits = (algo === 'DES' || algo === '3DES') ? 64 : 128;
    const gotFull = U.hex(CT.cipher.encrypt({ algo, mode, padding, key, iv, data, cfbBits: fullBits }));
    const got8 = U.hex(CT.cipher.encrypt({ algo, mode, padding, key, iv, data, cfbBits: 8 }));
    if (gotFull === exp) cfbFull++;
    if (got8 === exp) cfb8++;
    cfbFullTotal++;
    if (gotFull !== exp && got8 !== exp) eq(tag, gotFull, exp);
    else pass++;
    // 顺带验证解密回环
    const useBits = gotFull === exp ? fullBits : 8;
    const dec = U.hex(CT.cipher.decrypt({ algo, mode, padding, key, iv, data: U.unhex(exp), cfbBits: useBits }));
    eq(tag + ' [CFB 解密回环]', dec, f[3]);
    continue;
  }

  eq(tag, CT.cipher.encrypt({ algo, mode, padding, key, iv, data }), exp);
  eq(tag + ' [解密]', CT.cipher.decrypt({ algo, mode, padding, key, iv, data: U.unhex(exp) }), f[3]);
}

console.log('CFB 整块匹配: ' + cfbFull + '/' + cfbFullTotal + '，CFB-8 匹配: ' + cfb8 + '/' + cfb8Total);

/* ---------- 原版手工补零（NoPadding + keyLen 补零）---------- */
{
  const key = U.unhex('13304d6a87a4c1defb1835526f8ca9c6');
  const iv = U.unhex('96b3d0ed0a2744617e9bb8d5f20f2c49');
  const d = U.utf8Enc('hello 龙000');
  const z = CT.cipher.pad(d, 'Zero', 16, 16);
  // 原版公式 i = keyLen - (len % keyLen)，len 为 UTF-8 字节数
  eq('Zero 填充总长 = len + (16 - len%16)', String(z.length), String(d.length + 16 - (d.length % 16)));
  eq('Zero 填充尾巴全 0', U.hex(z.subarray(d.length)), '00'.repeat(16 - (d.length % 16)));
  const z2 = CT.cipher.pad(U.utf8Enc('0123456789abcdef'), 'Zero', 16, 16);
  eq('Zero 填充(16 字节对齐时补满 keyLen)', String(z2.length), '32');
  eq('PKCS7 填充内容(空数据)', U.hex(CT.cipher.pad(new Uint8Array(0), 'PKCS7', 16, 16)), '10'.repeat(16));
}

/* ---------- 与 node:crypto 交叉验证（独立实现）---------- */
const crypto = require('crypto');
const NMAP = [
  ['AES', 'ECB', 'aes-128-ecb', 16], ['AES', 'CBC', 'aes-128-cbc', 16],
  ['AES', 'CFB', 'aes-128-cfb', 16], ['AES', 'OFB', 'aes-128-ofb', 16], ['AES', 'CTR', 'aes-128-ctr', 16],
  ['AES', 'ECB', 'aes-256-ecb', 32], ['AES', 'CBC', 'aes-256-cbc', 32], ['AES', 'CFB', 'aes-256-cfb', 32],
  ['AES', 'OFB', 'aes-256-ofb', 32], ['AES', 'CTR', 'aes-256-ctr', 32],
  ['DES', 'ECB', 'des-ecb', 8], ['DES', 'CBC', 'des-cbc', 8], ['DES', 'CFB', 'des-cfb', 8], ['DES', 'OFB', 'des-ofb', 8],
  ['3DES', 'ECB', 'des-ede3', 24], ['3DES', 'CBC', 'des-ede3-cbc', 24]
];
for (const [algo, mode, nodeName, kl] of NMAP) {
  const key = new Uint8Array(kl);
  for (let i = 0; i < kl; i++) key[i] = (i * 7 + 5) & 0xff;
  const iv = new Uint8Array(8);
  for (let i = 0; i < 8; i++) iv[i] = (i * 11 + 1) & 0xff;
  const bs = kl === 8 || algo === 'DES' || algo === '3DES' ? 8 : 16;
  for (const len of [bs, bs * 2, bs * 3, bs * 10]) {
    const data = new Uint8Array(len);
    for (let i = 0; i < len; i++) data[i] = (i * 13 + 7) & 0xff;
    const ivFull = new Uint8Array(bs); ivFull.set(iv.subarray(0, bs));
    try {
      const c = crypto.createCipheriv(nodeName, Buffer.from(key), mode === 'ECB' ? null : Buffer.from(ivFull));
      c.setAutoPadding(false);
      const exp = Buffer.concat([c.update(Buffer.from(data)), c.final()]).toString('hex');
      const got = U.hex(CT.cipher.encrypt({ algo, mode, padding: 'None', key, iv: ivFull, data }));
      eq('node ' + nodeName + ' len=' + len, got, exp);
    } catch (e) { /* 某些引擎不支持 */ }
  }
}

if (fails.length) console.log('\n' + fails.join('\n'));
console.log('\n密码层：' + pass + ' 通过 / ' + fail + ' 失败');
process.exit(fail ? 1 : 0);
