/* 构建单文件离线网页：把 src/*.js 打进 shell.html，产出根目录 index.html */
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const srcDir = path.join(root, 'src');
const files = fs.readdirSync(srcDir).filter(f => f.endsWith('.js')).sort();

const body = files.map(f => {
  const code = fs.readFileSync(path.join(srcDir, f), 'utf8');
  return `/* ===== ${f} ===== */\n${code}`;
}).join('\n\n');

const bundle = `/* CodeToolBox 内核（零依赖，纯 JS） */\n(function () {\nvar CT = {};\n${body}\nwindow.CT = CT;\n})();`;

const shell = fs.readFileSync(path.join(__dirname, 'shell.html'), 'utf8');
if (!shell.includes('<!--__BUNDLE__-->')) throw new Error('shell.html 缺少 <!--__BUNDLE__--> 占位');

const out = shell.replace('<!--__BUNDLE__-->', () => '<script>\n' + bundle + '\n</script>');

const target = path.join(root, 'index.html');
fs.writeFileSync(target, out, 'utf8');

const kb = n => (n / 1024).toFixed(1) + ' KB';
console.log('模块:', files.length, '个 →', files.join(', '));
console.log('内核:', kb(Buffer.byteLength(bundle, 'utf8')));
console.log('产出:', target, kb(Buffer.byteLength(out, 'utf8')));
