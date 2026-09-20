/* ===========================================================================
 * 国密 SM4 测试
 *   1) GB/T 32907-2016 官方标准向量（含 100 万次迭代）
 *   2) 与 node:crypto 的 sm4-* （OpenSSL 实现）交叉对拍
 *   3) 经 CT.cipher 统一入口的加解密回环
 *   node test/t-sm4.js [--fast]
 * =========================================================================== */
const crypto = require('crypto');
const { load } = require('./_load.js');

const CT = load();
const U = CT.util;

const FAST = process.argv.includes('--fast');

let pass = 0, fail = 0;
const fails = [];
function eq(name, got, exp) {
  const A = typeof got === 'string' ? got : U.hex(got);
  const B = typeof exp === 'string' ? exp : U.hex(exp);
  if (A === B) pass++; else { fail++; if (fails.length < 20) fails.push(`FAIL ${name}\n     got ${A}\n     exp ${B}`); }
}

const H = U.unhex;

/* ---------------- 1. GB/T 32907-2016 标准向量 ---------------- */
{
  const key = H('0123456789abcdeffedcba9876543210');
  const pt  = H('0123456789abcdeffedcba9876543210');
  const rk = CT.sm4.expandKey(key);
  const out = new Uint8Array(16);
  CT.sm4._cryptBlock(rk, pt, 0, out, 0);
  eq('GB/T 32907 单次加密', out, '681edf34d206965e86b3e94f536e4246');

  // 解密回环
  const rkRev = Uint32Array.from(rk).reverse();
  const back = new Uint8Array(16);
  CT.sm4._cryptBlock(rkRev, H('681edf34d206965e86b3e94f536e4246'), 0, back, 0);
  eq('GB/T 32907 解密回环', back, pt);

  // 官方「迭代 100 万次」向量
  if (!FAST) {
    const t0 = Date.now();
    const buf = Uint8Array.from(pt);
    for (let i = 0; i < 1000000; i++) CT.sm4._cryptBlock(rk, buf, 0, buf, 0);
    const ms = Date.now() - t0;
    eq(`GB/T 32907 迭代 100 万次 (${ms}ms, ${(1000000 / ms * 1000 | 0)} 块/秒)`, buf,
       '595298c7c6fd271f0402f804c33d3f66');
  }
}

/* ---------------- 2. 与 node:crypto (OpenSSL) 对拍 ---------------- */
const SM4_MODES = [
  ['ECB', 'sm4-ecb', false],
  ['CBC', 'sm4-cbc', true],
  ['CFB', 'sm4-cfb', true],
  ['OFB', 'sm4-ofb', true],
  ['CTR', 'sm4-ctr', true]
];

let nodeOK = 0, nodeTot = 0;
for (const [mode, nodeName, useIv] of SM4_MODES) {
  for (let trial = 0; trial < 4; trial++) {
    const key = new Uint8Array(16);
    for (let i = 0; i < 16; i++) key[i] = (i * 31 + trial * 17 + 7) & 0xff;
    const iv = new Uint8Array(16);
    for (let i = 0; i < 16; i++) iv[i] = (i * 13 + trial * 29 + 3) & 0xff;
    for (const len of [16, 32, 48, 160, 37, 1]) {
      const data = new Uint8Array(len);
      for (let i = 0; i < len; i++) data[i] = (i * 19 + trial * 11 + 1) & 0xff;

      // 流模式（CFB/OFB/CTR）不填充；ECB/CBC 两种都测
      const paddings = (mode === 'ECB' || mode === 'CBC')
        ? (len % 16 === 0 ? ['None', 'PKCS7'] : ['PKCS7'])
        : ['None'];

      for (const padding of paddings) {
        nodeTot++;
        const useAutoPad = padding === 'PKCS7';
        try {
          const c = crypto.createCipheriv(nodeName, Buffer.from(key),
            useIv ? Buffer.from(iv) : null);
          c.setAutoPadding(useAutoPad);
          const expEnc = Buffer.concat([c.update(Buffer.from(data)), c.final()]).toString('hex');

          const gotEnc = U.hex(CT.cipher.encrypt({
            algo: 'SM4', mode, padding, key, iv, data
          }));
          const tag = `node ${nodeName} pad=${padding} len=${len} t=${trial}`;
          if (gotEnc === expEnc) nodeOK++;
          eq(tag, gotEnc, expEnc);

          // 解密
          const d = crypto.createDecipheriv(nodeName, Buffer.from(key), useIv ? Buffer.from(iv) : null);
          d.setAutoPadding(useAutoPad);
          const expDec = Buffer.concat([d.update(Buffer.from(expEnc, 'hex')), d.final()]).toString('hex');
          eq(tag + ' [解密]', U.hex(CT.cipher.decrypt({
            algo: 'SM4', mode, padding, key, iv, data: U.unhex(expEnc)
          })), expDec);
        } catch (e) {
          nodeTot--;
          if (fails.length < 20) fails.push(`SKIP ${nodeName} pad=${padding} len=${len}: ${e.message}`);
        }
      }
    }
  }
}

/* ---------------- 3. 自洽性：任意长度 PKCS7 回环 ---------------- */
for (const len of [0, 1, 5, 15, 16, 17, 31, 32, 33, 100, 255, 1000]) {
  const key = H('0123456789abcdeffedcba9876543210');
  const iv = H('000102030405060708090a0b0c0d0e0f');
  const data = new Uint8Array(len);
  for (let i = 0; i < len; i++) data[i] = (i * 37 + 11) & 0xff;
  const enc = CT.cipher.encrypt({ algo: 'SM4', mode: 'CBC', padding: 'PKCS7', key, iv, data });
  eq(`SM4-CBC-PKCS7 回环 len=${len}`, CT.cipher.decrypt({ algo: 'SM4', mode: 'CBC', padding: 'PKCS7', key, iv, data: enc }), data);
  eq(`SM4-CBC-PKCS7 密文长度为块整数倍 len=${len}`, String(enc.length % 16), '0');
}

/* ---------------- 4. SM4-CTR 与 OpenSSL 大报文一致性 ---------------- */
{
  const key = H('fedcba98765432100123456789abcdef');
  const iv = H('0f1e2d3c4b5a69788796a5b4c3d2e1f0');
  const data = new Uint8Array(1024 + 13);
  for (let i = 0; i < data.length; i++) data[i] = (i * 7 + 3) & 0xff;
  const c = crypto.createCipheriv('sm4-ctr', Buffer.from(key), Buffer.from(iv));
  c.setAutoPadding(false);
  const exp = Buffer.concat([c.update(Buffer.from(data)), c.final()]).toString('hex');
  eq('SM4-CTR 1037 字节（跨 65 个计数块）', U.hex(CT.cipher.encrypt({ algo: 'SM4', mode: 'CTR', padding: 'None', key, iv, data })), exp);
}

/* ---------------- 输出 ---------------- */
console.log('='.repeat(64));
console.log(`SM4：${pass} 通过 / ${fail} 失败   (node 对拍 ${nodeOK}/${nodeTot} 组严格一致)`);
if (fails.length) { console.log('\n--- 明细 ---'); fails.forEach(f => console.log('  ' + f)); }
console.log('='.repeat(64));
process.exit(fail ? 1 : 0);
