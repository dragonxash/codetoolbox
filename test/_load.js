/* 加载器：把 src/*.js 片段拼成一个 CT 对象（Node 端用） */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function load(dir) {
  dir = dir || path.join(__dirname, '..', 'src');
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.js')).sort();
  const code = files.map(f => fs.readFileSync(path.join(dir, f), 'utf8')).join('\n');
  const sandbox = {
    console, Uint8Array, Uint16Array, Uint32Array, Int32Array,
    Array, Object, Math, JSON, String, Number, Boolean, Error, TypeError, RangeError,
    BigInt, parseInt, parseFloat, isNaN, isFinite, RegExp, Date, Map, Set,
    encodeURIComponent, decodeURIComponent, TextEncoder, TextDecoder
  };
  const ctx = vm.createContext(sandbox);
  vm.runInContext('var CT = {};\n' + code + '\n;this.__CT = CT;', ctx, { filename: 'bundle.js' });
  return ctx.__CT;
}

module.exports = { load };
