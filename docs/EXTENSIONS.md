# 编码工具箱 · 扩展层文档

本文记录在原 APP 复刻之外**新增的两层算法**（老式编码、扩展哈希），以及单文件网页的
构建与验证流程。原 APP 行为规格见 `SPEC.md`。

---

## 一、总览

| 分组 | 数量 | 说明 |
| --- | ---: | --- |
| 哈希 | 20 | MD2/4/5 · SHA-1/2/3 · Keccak · RIPEMD-160 · SM3 · CRC32/32C · Adler32 · JavaHash · Whirlpool |
| 快速哈希 | 27 | BLAKE2s/b · FNV-1/1a-32/64 · xxHash32/64 · Murmur3-32/128 · CRC-8/8-MAXIM/64-XZ/64-ECMA · DJB2 · SDBM · PJW · NT-Hash |
| 扩展哈希 | 12 | Whirlpool · SHAKE128/256 · SipHash-2-4 · Poly1305 · Fletcher-16/32 · ELFHash · Jenkins one-at-a-time · FNV-1a-128 · BSD/SYSV sum |
| BASE 编码 | 14 | Base16/32/32-Hex/36/45/58/58Check/62/64/64-URL/85/91 · Crockford · Z85 |
| 对称加密 | 6 | AES / DES / 3DES / SM4 / RC4 / XOR（×ECB/CBC/CFB/OFB/CTR/PCBC，PKCS7/Zero/ISO10126/None） |
| 古典密码 | 29 | ROT·Atbash·凯撒·仿射·维吉尼亚·博福特·自动密钥·Gronsfeld·Porta·栅栏×2·列移位·Playfair·Polybius·Bifid·Hill2/3·猪圈·摩斯·A1Z26·培根×2·简单替换·ADFGVX 等 |
| 中文趣味 | 8 | 与佛论禅 · 佛曰 · 核心价值观 · Ook · Brainfuck · 零宽隐写 · 八卦/六十四卦 · 嗷呜兽语 |
| 实用工具 | 14 | URL/表单/HTML/Unicode/C 转义 · Quoted-Printable · 二/八/十进制 · 进制互转 · 反转 · 大小写反转 |
| 老式编码 | 17 | 见第二节 |
| RSA | 1（专用面板） | 密钥生成/解析 · 加解密 · 签名验签 · 分解攻击 |

单文件网页 `index.html` 共 **148 个入口**，内核 262 KB（未压缩，零依赖）。

---

## 二、老式编码层（`src/10-legacy.js`）

| 工具 | 说明 | 对拍来源 |
| --- | --- | --- |
| UUencode | 经典 Unix 二进制转文本，`` ` `` 表示 0 值组 | Python `binascii.b2a_uu` |
| XXencode | UU 的变体，字母表 `+-0-9A-Za-z` | Python 参考实现（同表） |
| Ascii85 | 4 字节 → 5 字符，`<~ ~>` 定界 | Python `base64.a85encode` |
| Ascii85(Adobe) | Adobe 风格定界 | 同上 |
| Ascii85(折叠空格) | 全零组折叠为 `y` | 同上（`foldspaces`） |
| Base92 | thenoviceoof/base92 官方表 | 官方 Python 实现 `_base92python.py` |
| yEnc | Usenet 二进制编码，含关键字节转义 | Python 参考实现 |
| Punycode | RFC 3492 引导算法（含 bias 自适应） | Python `str.encode('punycode')` |
| IDNA 域名 | 逐标签 `xn--` 转换 | Python `idna`/`str.encode('idna')` |
| EBCDIC | cp037 双射表（512 字符 hex 表） | Python `cp037` 编解码 |
| Hexdump | `偏移 | hex | ascii |` 三栏，可反向还原 | Python 重写对拍 |
| 盲文 | Unicode U+2800 区，按 UEB 标点表 | Python 重写对拍 |
| DNA 编码 | 2-bit 碱基（A/C/G/T）映射 | Python 重写对拍 |
| BubbleBabble | `xVVCV...x` 可读指纹格式 | 公开向量（7 组） |
| 敲敲码 | Tap Code，字母内 `/`、词间 `\|` | 往返一致性 |
| 北约音标 | Alpha/Bravo/Charlie… | 往返一致性 |
| T9 九宫格 | 手机键盘数字映射（单向） | 往返一致性 |

### 实现中踩到并修掉的坑

| 位置 | 错误现象 | 修法 |
| --- | --- | --- |
| Ascii85 | 输入 >128 字节时尾部溢出 NUL | 组内字节数应为 `Math.min(4, len - i)`；累加改用乘法避免 32 位溢出 |
| XXencode | 首组多吐字符 | 3 字节组输出 `len + 1` 个字符 |
| Punycode | 中文/emoji 解码偏移 | `pcT(k,bias)` 的三段判定应为 `k-bias`（不是 `k<=bias`）；`acc` 跨轮保持 |
| DNA | 解码只还原一半 | 步进 `i += 4`（1 字节 = 4 碱基） |
| BubbleBabble | C-C 配对被 `-` 切词拆散 | 改按 VCV[C-C] 位置指针推进 |
| 敲敲码 | 原文空格丢失 | 字母内用 `/`、词间用 `\|` |

> 字符集受限（EBCDIC / 盲文 / 敲敲码 / 北约音标 / T9）无法无损承载任意 Unicode，
> 验证脚本把它们标为「有损往返」，属预期而非缺陷。

---

## 三、扩展哈希层（`src/11-hash2.js`）

| 算法 | 输出 | 类别 | 对拍来源 |
| --- | ---: | --- | --- |
| Whirlpool | 64 B | hash | OpenSSL `dgst -whirlpool -provider legacy`（另存 libtomcrypt `whirltab.c` 佐证） |
| SHAKE128 | 可变（默认 32 B） | XOF | Python `hashlib.shake_128` |
| SHAKE256 | 可变（默认 64 B） | XOF | Python `hashlib.shake_256` |
| SipHash-2-4 | 8 B | 键控 | 公开向量（空输入 `310e0edd47db6f72`） |
| Poly1305 | 16 B | MAC | RFC 8439 测试向量 |
| Fletcher-16 / 32 | 2 / 4 B | 校验和 | Python 重写对拍 |
| ELFHash | 4 B | 散列 | Python 重写对拍 |
| Jenkins one-at-a-time | 4 B | 散列 | Python 重写对拍 |
| FNV-1a-128 | 16 B | 散列 | Python 重写对拍（素数 `(1<<88)+0x13B`） |
| BSD sum / SYSV sum | 2 B | 校验和 | Python 重写对拍 |

### Whirlpool 的两个关键点

1. **表生成**：S-box 在 GF(2⁸)（本原多项式 `0x11d`）上派生 8 张 64 位表，
   `Ck[v] = rotr64(C0[v], 8k)`；与 libtomcrypt `whirltab.c` 逐项核对一致。
2. **尾部填充**：按 `whirlpool_done` 的两段式——先补 `0x80`，若剩余空间不足 32 字节
   先压一块，再补零到 56 字节，最后 8 字节写位长（大端）。

调试时用「非平凡向量数值对拍」定位了 `tpg()` 的字节抽取方向：
`byte = k<=3 ? (ih[idx] >>> (8*(3-k))) & 255 : (il[idx] >>> (8*(7-k))) & 255`。
全零输入的 XOR 结果不可区分，必须用真实数据才能暴露方向错误。

---

## 四、构建与验证

```bash
# 1) 单元测试（Node，3655 项断言）
node test/run-all.js

# 2) 打包单文件网页（src/*.js → index.html）
node tools/build.js

# 3) 网页级验证（jsdom 加载 index.html，逐算法跑编码 + 解码往返）
npm i jsdom                       # 装在任意位置均可
JSDOM_PATH=<jsdom 路径> node tools/verify.js
```

`tools/verify.js` 目前的结果：**145 通过 / 0 失败 / 15 有损往返**（有损项见上文说明）。

---

## 五、网页使用提示

- 全部计算在浏览器本地完成，**断网可用**，无任何外部请求。
- `Ctrl`+`Enter` 直接执行「编码 / 计算」。
- 左侧可搜索；每个算法的参数（密钥、位移、模式、填充…）在标题下方。
- RSA 面板：先「生成密钥对」或粘贴 PEM / `{n,e,d}` JSON 后「载入密钥」，
  再做加解密与签名验签。模数 > 256 位时会弹窗提示（暴力分解可能长时间无解）。
- Z85 要求 4 字节一组，编码时会自动补 `0x00`，解码时去掉尾部补位零。
- 部分算法（BASE58Check、Hexdump）的输出含固定格式，解码时请整段复制。

---

## 六、待办

- [ ] RIPEMD-128/256/320、Tiger（参考源码已下载到 `test/oracle/ref/`，未实现）
- [ ] 进阶古典密码：Enigma、Trifid、四方密码、Nihilist、分数化摩斯
- [ ] Step 2：Android Kotlin 重写
