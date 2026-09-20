/* 一键跑全部测试：node test/run-all.js [--fast] */
const { spawnSync } = require('child_process');
const path = require('path');

const files = ['t-hash.js', 't-cipher.js', 't-base.js', 't-sm4.js', 't-hashex.js', 't-classic.js',
               't-cncode.js', 't-misc.js', 't-rsa.js', 't-legacy.js', 't-hash2.js'];

let bad = 0;
for (const f of files) {
  const p = path.join(__dirname, f);
  if (!require('fs').existsSync(p)) { console.log(`[跳过] ${f}（不存在）\n`); continue; }
  const r = spawnSync(process.execPath, [p, ...process.argv.slice(2)], { encoding: 'utf8' });
  process.stdout.write(r.stdout || '');
  if (r.stderr) process.stderr.write(r.stderr);
  if (r.status !== 0) bad++;
}
console.log(bad ? `\n>>> ${bad} 个测试文件未通过` : '\n>>> 全部测试文件通过');
process.exit(bad ? 1 : 0);
