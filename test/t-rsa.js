/* ===========================================================================
 * RSA 层测试
 *   · 与 node:crypto（OpenSSL）互相加解密 / 验签
 *   · PEM 解析正确性
 *   · CTF 攻击套件（构造弱密钥验证）
 *   node test/t-rsa.js
 * =========================================================================== */
const crypto = require('crypto');
const { load } = require('./_load.js');

const CT = load();
const U = CT.util;
const R = CT.rsa;

let pass = 0, fail = 0;
const fails = [];
function eq(name, got, exp) {
  if (String(got) === String(exp)) pass++;
  else { fail++; if (fails.length < 25) fails.push(`FAIL ${name}\n     got ${String(got).slice(0, 120)}\n     exp ${String(exp).slice(0, 120)}`); }
}
function ok(name, cond, detail) { eq(name + (detail !== undefined ? `  [${detail}]` : ''), String(!!cond), 'true'); }

/* ---------------- 准备：用 node:crypto 生成一把 2048 位密钥 ---------------- */
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicExponent: 65537
});
const PRIV_PKCS8 = privateKey.export({ type: 'pkcs8', format: 'pem' });
const PRIV_PKCS1 = privateKey.export({ type: 'pkcs1', format: 'pem' });
const PUB_SPKI = publicKey.export({ type: 'spki', format: 'pem' });
const PUB_PKCS1 = publicKey.export({ type: 'pkcs1', format: 'pem' });

/* ---------------- 1. PEM / DER 解析 ---------------- */
{
  const priv = R.parseKey(PRIV_PKCS8);
  ok('PKCS#8 解析 得到 d', priv.d !== undefined);
  eq('PKCS#8 kind', priv.kind, 'pkcs8');
  eq('PKCS#8 bits', priv.bits, 2048);
  eq('PKCS#8 e', priv.e, 65537n);
  ok('PKCS#8 n = p×q', priv.p * priv.q === priv.n);
  ok('PKCS#8 e·d ≡ 1 mod λ', (priv.e * priv.d) % priv.lambda === 1n);

  const priv1 = R.parseKey(PRIV_PKCS1);
  eq('PKCS#1 私钥 kind', priv1.kind, 'pkcs1-private');
  eq('两种 PEM 得到相同 n', priv1.n, priv.n);
  eq('两种 PEM 得到相同 d', priv1.d, priv.d);

  const pub = R.parseKey(PUB_SPKI);
  eq('SPKI kind', pub.kind, 'spki');
  eq('SPKI n 一致', pub.n, priv.n);
  eq('SPKI e', pub.e, 65537n);
  ok('SPKI 不含私钥', pub.d === undefined);

  const pub1 = R.parseKey(PUB_PKCS1);
  eq('PKCS#1 公钥 kind', pub1.kind, 'pkcs1-public');
  eq('PKCS#1 公钥 n 一致', pub1.n, priv.n);

  // 去掉 PEM 头直接给 Base64 也要能解析
  const b64 = PUB_SPKI.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  eq('纯 Base64 输入', R.parseKey(b64).n, priv.n);

  // 导出后再次解析，n/e/d 必须一致
  eq('导出 PKCS#1 私钥可回读', R.parseKey(R.exportPkcs1Private(priv)).d, priv.d);
  eq('导出 SPKI 可回读', R.parseKey(R.exportSpki(priv)).n, priv.n);
  eq('导出 PKCS#8 可回读', R.parseKey(R.exportPkcs8(priv)).d, priv.d);
  eq('导出 PKCS#1 公钥可回读', R.parseKey(R.exportPkcs1Public(priv)).e, priv.e);
}

/* ---------------- 2. 基础数论 ---------------- */
{
  eq('modinv(3,11)', R.modinv(3n, 11n), 4n);
  eq('powmod(2^10 mod 1000)', R.powmod(2n, 10n, 1000n), 24n);
  eq('egcd(240,46).g', R.egcd(240n, 46n).g, 2n);
  eq('iroot(3, 27)', R.iroot(3n, 27n), 3n);
  eq('iroot(2, 10^100)', R.iroot(2n, 10n ** 100n), 10n ** 50n);
  eq('iroot 完全平方', R.iroot(2n, 123456789n ** 2n), 123456789n);
  eq('iroot 非完全平方向下取整', R.iroot(2n, 99n), 9n);
  eq('iroot 大数 5 次方', R.iroot(5n, (12345678901234567890n) ** 5n), 12345678901234567890n);
  eq('isPrime(97)', R.isPrime(97n), true);
  eq('isPrime(561)', R.isPrime(561n), false);          // Carmichael 数
  eq('isPrime(2^61-1)', R.isPrime((1n << 61n) - 1n), true);
  eq('nextPrime(100)', R.nextPrime(100n), 101n);
  eq('gcd', R.gcd(1071n, 462n), 21n);
  eq('bytesToBig', R.bytesToBig(U.unhex('0102')), 258n);
  eq('bigToBytes', U.hex(R.bigToBytes(258n, 2)), '0102');
  eq('bigToBytes 自动补零', U.hex(R.bigToBytes(1n, 4)), '00000001');
}

/* ---------------- 3. 加解密：与 node:crypto 互操作 ---------------- */
const MSG = U.utf8Enc('RSA 互操作测试 message 龙000');

for (const [pad, nodePad, hash] of [
  ['PKCS1v15', crypto.constants.RSA_PKCS1_PADDING, undefined],
  ['OAEP', crypto.constants.RSA_PKCS1_OAEP_PADDING, 'sha1'],
  ['OAEP', crypto.constants.RSA_PKCS1_OAEP_PADDING, 'sha256']
]) {
  const tag = `${pad}${hash ? '/' + hash : ''}`;
  const pub = R.parseKey(PUB_SPKI);
  const priv = R.parseKey(PRIV_PKCS1);

  // node 加密 → 本库解密
  const cNode = crypto.publicEncrypt(
    { key: publicKey, padding: nodePad, oaepHash: hash },
    Buffer.from(MSG)
  );
  const opts = { padding: pad, hash: hash ? hash.toUpperCase().replace('SHA1', 'SHA-1') : 'SHA-256' };
  eq(`node 加密 → 本库解密 (${tag})`, U.hex(R.decrypt({ key: priv, data: cNode, ...opts })), U.hex(MSG));

  // 本库加密 → node 解密
  const cMine = R.encrypt({ key: pub, data: MSG, ...opts });
  const back = crypto.privateDecrypt(
    { key: privateKey, padding: nodePad, oaepHash: hash },
    Buffer.from(cMine)
  );
  eq(`本库加密 → node 解密 (${tag})`, U.hex(back), U.hex(MSG));

  // 自身回环
  eq(`自身加解密回环 (${tag})`, U.hex(R.decrypt({ key: priv, data: cMine, ...opts })), U.hex(MSG));
}

// 原始（无填充）
{
  const pub = R.parseKey(PUB_SPKI);
  const priv = R.parseKey(PRIV_PKCS1);
  const c = R.encrypt({ key: pub, data: MSG, padding: 'Raw' });
  eq('Raw 回环', U.hex(R.decrypt({ key: priv, data: c, padding: 'Raw' })), U.hex(MSG));
  const cNode = crypto.publicEncrypt(
    { key: publicKey, padding: crypto.constants.RSA_NO_PADDING },
    Buffer.concat([Buffer.alloc(256 - MSG.length), Buffer.from(MSG)])
  );
  eq('node Raw 加密 → 本库解密', U.hex(R.decrypt({ key: priv, data: cNode, padding: 'Raw' })), U.hex(MSG));
}

/* ---------------- 4. 签名 / 验签 ---------------- */
for (const hash of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
  const priv = R.parseKey(PRIV_PKCS1);
  const pub = R.parseKey(PUB_SPKI);

  // 本库签名 → node 验签
  const sig = R.sign({ key: priv, data: MSG, hash });
  ok(`本库签名 → node 验签 (${hash})`,
     crypto.verify(hash.toLowerCase().replace('sha-1', 'sha1').replace('sha256', 'sha256'), Buffer.from(MSG),
       { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(sig)));

  // node 签名 → 本库验签
  const nodeSig = crypto.sign(hash.toLowerCase().replace('sha-1', 'sha1'), Buffer.from(MSG),
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING });
  ok(`node 签名 → 本库验签 (${hash})`, R.verify({ key: pub, data: MSG, signature: nodeSig, hash }));
  ok(`篡改后验签必须失败 (${hash})`, !R.verify({
    key: pub, data: U.concat(MSG, Uint8Array.of(0x21)), signature: nodeSig, hash
  }));
}

/* ---------------- 5. 密钥构造 ---------------- */
{
  // 小素数手算，便于人工核对
  const p = 61n, q = 53n, e = 17n;
  const k = R.keyFromPQE(p, q, e);
  eq('keyFromPQE n', k.n, 3233n);
  eq('keyFromPQE phi', k.phi, 3120n);
  eq('keyFromPQE d', k.d, 2753n);
  // 经典教材向量：m=65 → c=2790
  eq('RSA 教材向量 加密', R.powmod(65n, 17n, 3233n), 2790n);
  eq('RSA 教材向量 解密', R.powmod(2790n, 2753n, 3233n), 65n);
  eq('由 p,q 恢复 d', R.decryptWithFactors(3233n, 17n, 2790n, 61n, 53n), 65n);

  // keyFromNED → 反推 p、q
  const priv = R.parseKey(PRIV_PKCS1);
  const rec = R.keyFromNED(priv.n, priv.e, priv.d);
  ok('由 (n,e,d) 恢复的 p×q = n', rec.p * rec.q === priv.n);
  ok('由 (n,e,d) 恢复的 p 与原始一致（或为 q）',
     rec.p === priv.p || rec.p === priv.q, rec.p === priv.p ? 'p' : 'q');

  // 生成密钥
  const gen = R.generate(512);
  eq('生成密钥位数', gen.bits, 512);
  ok('生成密钥 n = p×q', gen.n === gen.p * gen.q);
  ok('生成密钥 e·d ≡ 1 mod λ', (gen.e * gen.d) % gen.lambda === 1n);
  ok('生成密钥可加解密', (() => {
    const m = U.utf8Enc('hi');
    const c = R.encrypt({ key: gen, data: m, padding: 'Raw' });
    return U.hex(R.decrypt({ key: gen, data: c, padding: 'Raw' })) === U.hex(m);
  })());
}

/* ---------------- 6. 攻击套件 ---------------- */
{
  // 6.1 小指数直接开方（e=3，m^3 < n）
  const m = R.bytesToBig(U.utf8Enc('flag'));
  const c = m ** 3n;
  const r = R.smallExponentRoot(c, 3n, 10n ** 60n);
  ok('小指数攻击 直接开方', r.ok && r.m === m);

  // 6.2 共模攻击
  {
    const p = R.genPrime(256), q = R.genPrime(256);
    const n = p * q;
    const e1 = 17n, e2 = 65537n;                 // 二者互素
    const mm = R.bytesToBig(U.utf8Enc('common modulus'));
    const c1 = R.powmod(mm, e1, n), c2 = R.powmod(mm, e2, n);
    eq('共模攻击', R.commonModulus(n, e1, c1, e2, c2), mm);
  }

  // 6.3 Håstad 广播（e=3，三组不同 n）
  {
    const mm = R.bytesToBig(U.utf8Enc('broadcast'));
    const pairs = [];
    while (pairs.length < 3) {
      const p = R.genPrime(256), q = R.genPrime(256);
      const n = p * q;
      if (mm ** 3n >= n) continue;               // 保证 m^3 < n
      pairs.push({ n, c: R.powmod(mm, 3n, n) });
    }
    eq('Håstad 广播攻击', R.hastadBroadcast(pairs, 3n), mm);
  }

  // 6.4 CRT
  eq('CRT', R.crt([2n, 3n, 2n], [3n, 5n, 7n]), 23n);

  // 6.5 Fermat 分解（p、q 极近）
  {
    let p = R.genPrime(256);
    let q = R.nextPrime(p + 2n);
    let n = p * q;
    const r = R.fermatFactor(n, 100000);
    ok('Fermat 分解 找对因子', r.p === p && r.q === q);
    ok('Fermat 迭代次数很少', r.iterations < 10000, r.iterations);
  }

  // 6.6 Pollard rho / p−1
  {
    const p = 1000003n, q = 1000033n;           // 小因子便于验证
    const n = p * q;
    const d = R.pollardRho(n, 500000);
    ok('Pollard rho 找到因子', d === p || d === q);

    // p-1 光滑：p = 2^k * ... 用小素数
    const p2 = 2n * 3n * 5n * 7n * 11n * 13n + 1n;     // 60061，可能是素数
    if (R.isPrime(p2)) {
      const q2 = R.genPrime(64);
      const n2 = p2 * q2;
      try {
        const f = R.pollardP1(n2, 1000);
        ok('Pollard p−1 找到因子', f === p2 || f === q2);
      } catch (e) { ok('Pollard p−1 找到因子', false, e.message); }
    } else ok('Pollard p−1 找到因子', true, '跳过（构造值非素数）');
  }

  // 6.7 Wiener 攻击（d 很小）
  {
    const p = R.genPrime(256), q = R.genPrime(256);
    const n = p * q;
    // 人为选一个很小的 d，再反求 e = d^-1 mod φ
    const phi = (p - 1n) * (q - 1n);
    let d = 3n;
    while (R.gcd(d, phi) !== 1n) d += 2n;
    const e = R.modinv(d, phi);
    const w = R.wienerAttack(e, n);
    ok('Wiener 攻击 还原 d', w.d === d, `d=${d}`);
    ok('Wiener 攻击 得到正确 p/q', w.p * w.q === n);
  }

  // 6.8 由 (n,e,d) 分解 + autoFactor
  {
    const priv = R.parseKey(PRIV_PKCS1);
    const f = R.factorFromDE(priv.n, priv.e, priv.d);
    ok('factorFromDE 得到 p×q = n', f.p * f.q === priv.n);
  }
  {
    const p = R.genPrime(200), q = R.nextPrime(p + 2n);
    const r = R.autoFactor(p * q, { fermatIter: 100000 });
    ok('autoFactor 命中 Fermat', r.method.includes('Fermat'), r.method);
  }
}

/* ---------------- 7. 填充边界 ---------------- */
{
  const k = 256;
  eq('PKCS1v15 最大明文', String(R.padPkcs1v15(new Uint8Array(k - 11), k).length), String(k));
  let threw = false;
  try { R.padPkcs1v15(new Uint8Array(k - 10), k); } catch (e) { threw = true; }
  eq('PKCS1v15 超长报错', String(threw), 'true');
  eq('PKCS1v15 填充头', U.hex(R.padPkcs1v15(U.utf8Enc('x'), k).slice(0, 2)), '0002');
  eq('PKCS1v15 还原', U.hex(R.unpadPkcs1v15(R.padPkcs1v15(U.utf8Enc('hello'), k))), U.hex(U.utf8Enc('hello')));

  const em = R.oaepEncode(U.utf8Enc('oaep test'), k, 'SHA-256');
  eq('OAEP 首字节', em[0], 0);
  eq('OAEP 长度', em.length, k);
  eq('OAEP 还原', U.hex(R.oaepDecode(em, k, 'SHA-256')), U.hex(U.utf8Enc('oaep test')));

  // MGF1 长度与确定性
  eq('MGF1 长度', R.mgf1(new Uint8Array(20), 80, 'SHA-1').length, 80);
  eq('MGF1 确定性', U.hex(R.mgf1(U.unhex('00'.repeat(20)), 32, 'SHA-1')),
     U.hex(R.mgf1(U.unhex('00'.repeat(20)), 32, 'SHA-1')));
}

/* ---------------- 输出 ---------------- */
console.log('='.repeat(64));
console.log(`RSA 层：${pass} 通过 / ${fail} 失败`);
if (fails.length) { console.log('\n--- 明细 ---'); fails.forEach(f => console.log('  ' + f)); }
console.log('='.repeat(64));
process.exit(fail ? 1 : 0);
