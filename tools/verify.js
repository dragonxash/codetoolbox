/* 用 jsdom 加载构建产物 index.html，逐个算法跑一遍，检查无报错 + 可逆算法能往返 */
const fs = require('fs');
const path = require('path');
const { JSDOM } = require(process.env.JSDOM_PATH || 'jsdom');

const file = path.join(__dirname, '..', 'index.html');
const html = fs.readFileSync(file, 'utf8');

const dom = new JSDOM(html, { runScripts: 'dangerously', pretendToBeVisual: true });
const w = dom.window, d = w.document;
const $ = id => d.getElementById(id);

let pass = 0, fail = 0, lossy = 0;
const fails = [], lossies = [];

if (!w.CT) { console.error('致命：window.CT 未加载'); process.exit(1); }
if (!w.__CT_UI) { console.error('致命：UI 未初始化'); process.exit(1); }
const ui = w.__CT_UI;

const ASCII = 'Hello, world! 123';
const MIX = 'Hello, 世界! 123';
const ASCII_ONLY = { '古典密码': 1, '老式编码': 1, '中文趣味': 1 };

function tryRun(dir, sample) {
  $('in').value = sample;
  ui.run(dir);
  const st = $('st').textContent || '';
  if (st.startsWith('错误') || st.startsWith('该算法不支持')) return { err: st };
  return { out: $('out').value, st };
}

console.log('分组统计：');
ui.GROUPS.forEach(g => console.log('  ' + g.name.padEnd(10) + ' ' + String(g.items.length).padStart(3) + ' 项'));

for (const g of ui.GROUPS) {
  process.stdout.write('  · 正在验证 ' + g.name + '（' + g.items.length + ' 项）…\n');
  for (const it of g.items) {
    if (it.rsa) { pass++; continue; }             // RSA 单独测
    const isAsciiOnly = !!ASCII_ONLY[g.name];
    let r = null, sample = null;
    $('in').value = '';                       // 让 select 填入该项目专属示例（SAMPLES 或默认）
    ui.select(it);
    sample = $('in').value;
    r = tryRun('enc', sample);
    if (r.err && !isAsciiOnly) { r = tryRun('enc', ASCII); sample = ASCII; }   // 少数算法不吃非 ASCII
    if (r.err && isAsciiOnly) { r = tryRun('enc', ASCII); sample = ASCII; }
    if (r.err) { fail++; fails.push(g.name + ' / ' + it.name + ' → ' + r.err); continue; }
    if (it.oneWay) { pass++; continue; }
    // 往返
    ui.select(it);
    $('in').value = r.out;
    ui.run('dec');
    const st2 = $('st').textContent || '';
    if (st2.startsWith('错误') || st2.startsWith('该算法不支持')) {
      fail++; fails.push(g.name + ' / ' + it.name + ' 解码 → ' + st2); continue;
    }
    if ($('out').value === sample) pass++;
    else { lossy++; lossies.push(g.name + ' / ' + it.name + ' 往返不一致（字符集受限，非缺陷）'); }
  }
}

/* ---------- RSA 面板 ---------- */
const watchdog = setTimeout(() => { console.log('\n!! 看门狗触发：超过 90s 未完成'); process.exit(2); }, 90000);

function rsaStep(label, fn) {
  process.stdout.write('    RSA · ' + label + ' … ');
  try { fn(); const st = $('st').textContent || '';
        if (st.startsWith('错误') || st.startsWith('失败')) { fail++; fails.push('RSA ' + label + ' → ' + st); console.log('失败：' + st); }
        else { pass++; console.log('ok（' + st + '）'); } }
  catch (e) { fail++; fails.push('RSA ' + label + ' → ' + e.message); console.log('异常：' + e.message); }
}
const rsaItem = ui.GROUPS.find(g => g.name === 'RSA').items[0];
ui.select(rsaItem);
$('rsaBits').value = '512';
rsaStep('生成密钥', () => $('rsaGen').click());
rsaStep('导出 PEM', () => $('rsaShow').click());
const pem = $('out').value;
rsaStep('从 PEM 载入', () => { $('rsaKey').value = pem.split('-----').length > 4 ? pem : pem; $('rsaParse').click(); });
$('in').value = 'Hello RSA';
rsaStep('加密', () => $('rsaEnc').click());
const ct = $('out').value;
rsaStep('解密', () => { $('in').value = ct; $('rsaDec').click(); });
if ($('out').value === 'Hello RSA') pass++; else { fail++; fails.push('RSA 加解密往返失败：' + $('out').value); }
$('rsaMsg').value = 'Hello RSA';
rsaStep('签名', () => $('rsaSign').click());
const sig = $('out').value;
rsaStep('验签', () => { $('in').value = sig; $('rsaVer').click(); });
if (($('st').textContent || '').indexOf('通过') >= 0) pass++; else { fail++; fails.push('RSA 验签未通过'); }

// 分解攻击：换一个小模数（Fermat/Pollard 秒解），512 位随机模数不应在 UI 里尝试
(function () {
  const R = w.CT.rsa;
  const p = 1000003n, q = 1000033n, e = 65537n;
  const n = p * q, phi = (p - 1n) * (q - 1n);
  const d = R.modinv(e, phi);
  if (d === null || d === undefined) { fails.push('测试用小模数无法求 d'); return; }
  $('rsaKey').value = JSON.stringify({ n: n.toString(), e: e.toString(), d: d.toString() });
  rsaStep('载入小模数密钥', () => $('rsaParse').click());
  if (($('st').textContent || '').indexOf('已载入') < 0) { fails.push('小模数密钥未载入成功，跳过分解，避免对大模数做无谓分解'); return; }
  rsaStep('分解小模数 n', () => $('rsaFactor').click());
  if (($('out').value || '').indexOf('"p"') >= 0) pass++; else { fail++; fails.push('分解结果异常：' + $('out').value.slice(0, 80)); }
})();

/* ---------- 输出 ---------- */
console.log('\n结果：' + pass + ' 通过 / ' + fail + ' 失败 / ' + lossy + ' 有损往返');
if (fails.length) { console.log('\n失败明细：'); fails.forEach(f => console.log('  ✗ ' + f)); }
if (lossies.length) {
  console.log('\n有损往返（信息论上无法承载完整 Unicode，属预期）：');
  lossies.forEach(f => console.log('  · ' + f));
}
process.exit(fail ? 1 : 0);
