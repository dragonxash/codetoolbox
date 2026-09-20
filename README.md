# 编码工具箱 · 离线单文件版

把 Android「编码工具箱」APK（`com.doubihuaji.Tool`）的算法库逆向复刻成**零依赖纯 JS**，
并额外扩充了老式编码与扩展哈希两层，最终交付一个可以直接双击打开、断网可用的
单文件网页 `index.html`（约 285 KB，无任何外部请求）。

---

## 快速开始

```
直接用浏览器打开 index.html
```

左侧选算法 → 中间填参数 → 输入文本 → 「编码 / 计算」或「解码」。
`Ctrl`+`Enter` 可直接编码；「上下互换」把结果送回输入框。

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `index.html` | **交付物**：内核 + UI 打包成的单文件网页 |
| `src/*.js` | 内核源码，按 `01`~`11` 顺序加载，挂到全局 `CT` 命名空间 |
| `src/01-core.js` | 工具函数 + MD/SHA/SHA-3/RIPEMD/SM3/CRC/Adler32 + HMAC/PBKDF2 |
| `src/02-cipher.js` | AES/DES/3DES/RC4/XOR + ECB/CBC/CFB/OFB/CTR/PCBC + 填充 |
| `src/03-sm4.js` | 国密 SM4（与 Node `crypto` 对拍 152/152 组） |
| `src/04-base.js` | Base16/32/36/45/58/62/64/85/91、Crockford、Z85 |
| `src/05-hashex.js` | BLAKE2、FNV、xxHash、Murmur3、CRC-8/64、DJB2、SDBM、PJW、NT-Hash |
| `src/06-classic.js` | 29 种古典密码 |
| `src/07a-buddha.js` / `07b-cncode.js` | 与佛论禅 / 佛曰 / 核心价值观 / Ook / BF / 零宽 / 卦象 / 兽语 |
| `src/08-misc.js` | URL、HTML、Unicode、C 转义、QP、进制互转等 |
| `src/09-rsa.js` | 纯 BigInt RSA：密钥生成/解析、加解密、签名验签、分解攻击 |
| `src/10-legacy.js` | UU/XX/Ascii85/Base92/yEnc/Punycode/EBCDIC/盲文/DNA/BubbleBabble… |
| `src/11-hash2.js` | Whirlpool/SHAKE/SipHash/Poly1305/Fletcher/ELF/Jenkins/FNV-1a-128/sum |
| `tools/shell.html` | 网页 UI 外壳（含 `<!--__BUNDLE__-->` 占位） |
| `tools/build.js` | 把 `src/*.js` 注入外壳，产出 `index.html` |
| `tools/verify.js` | jsdom 加载 `index.html`，逐算法跑编码 + 解码往返 |
| `test/` | 11 个测试文件 + `oracle/`（Python/OpenSSL 生成的对拍数据） |
| `docs/SPEC.md` | 原 APK 的行为规格（复刻依据） |
| `docs/EXTENSIONS.md` | 新增两层的实现说明与踩坑记录 |

## 常用命令

```bash
node test/run-all.js        # 全量单元测试（3655 项断言）
node tools/build.js         # 重新打包 index.html
JSDOM_PATH=<jsdom 路径> node tools/verify.js   # 网页级验证
```

## 精度保证

每个算法都做了**独立 oracle 交叉验证**，而非自说自话：

| 层 | 对拍基准 |
| --- | --- |
| 哈希 / 对称加密 | Node `crypto` |
| SM4 | Node `crypto`（152/152 组严格一致） |
| 老式编码 | Python `binascii` / `base64` / `cp037` / base92 官方实现 |
| Whirlpool | OpenSSL legacy provider（libtomcrypt 表佐证） |
| SHAKE / 校验和 | Python `hashlib` 与重写实现 |
| RSA | Node `crypto` 密钥互认 + 公开标准向量 |

## 已知限制

- EBCDIC、盲文、敲敲码、北约音标、T9 以及字母表受限的古典密码（Playfair、Polybius、
  Bifid、Hill、猪圈、摩斯、A1Z26、培根、ADFGVX）无法无损承载任意 Unicode／标点数字，
  往返会有归一化损失，这是编码本身的能力边界。
- Z85 要求 4 字节一组，网页侧会自动补 `0x00` 并在解码时去掉尾零。
- RSA 分解攻击只对弱密钥有效（p/q 接近、存在小因子、e 或 d 过小）；
  位数过大时页面会先弹窗确认，避免长时间无解卡住。

详细说明见 `docs/EXTENSIONS.md`。
