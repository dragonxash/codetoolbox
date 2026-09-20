# 编码工具箱 · 复刻规格书

来源：`G:\QQ文件\nt_qq\编码工具箱.apk` 的反编译产物（jadx 1.5.6）。
本文件是**实现依据**，所有细节均出自反编译源码，不是推测。

---

## 一、原 APP 技术画像

| 项 | 值 |
| --- | --- |
| 包名 | `com.doubihuaji.Tool` |
| 版本 | 1.031 |
| 体积 | 276 KB（classes.dex 172 KB） |
| 编译目标 | compileSdk 33 / targetSdk 33 / **minSdk 13** |
| 语言 | 纯 Java，**无 androidx、无 Kotlin、无第三方库、无 native so** |
| 签名者 | 「逗比滑稽」 |
| 权限 | READ/WRITE_EXTERNAL_STORAGE、INTERNET |
| 混淆 | **无**（类名、方法名全可读）；仅资源被混淆成 `r/a/*.xml` |
| 加固 | **无**（主 dex 可直接反编译） |

**结论：不需要"反汇编"，代码本身就是可读的。真正要复刻的是行为规格。**

---

## 二、架构：一个基类 + 一堆薄壳

```
MainActivity          → 首页，三个 tab 的列表（「算法」「数据」「文件」）
  └ UtilActivity      → 1888 行，全部逻辑都在这里
      ├ AesActivity / DesActivity / Rc4Activity / RsaActivity / HashActivity
      ├ BaseActivity / CodeActivity
      ├ FzActivity / DxxActivity / ReplaceActivity / TimeActivity / AsciiActivity
      ├ RegexActivity / FloatActivity / HexStrActivity / HexActivity / ArmHexActivity
      └ JfActivity / CrcActivity / FileByteActivity / DexActivity
          / StubActivity / JgActivity / FixActivity / FileSplitActivity / FileMergeActivity
```

子类通常只有 20~60 行：在 `onCreate` 里声明**算法列表**和**按钮文案**，再实现 `MainAlgorithm()`。
`SettingsActivity` 是设置页，`WeiActivity` 是「关于」。

### 基类主流程（所有工具共用的骨架）

```java
public String main() {
    try {
        if (文本为空 && !TextUnrestricted) { Toast("内容为空"); return null; }
        if (算法名为空) { Toast(button1EmptyMessage); return null; }
        setTextBytes(text.getBytes());            // 输入字节 = UTF-8，不 trim、不过滤
        Object r = MainAlgorithm(getAlgorithmType());
        if (r instanceof byte[]) { setTextResultBytes((byte[]) r); return new String((byte[]) r); }
        setTextResultBytes(((String) r).getBytes()); return (String) r;
    } catch (Exception e) {
        return isDebug() ? PublicCode.getBug(e)   // Debug 默认 true → 输出整段堆栈
                         : "失败了";
    }
}
```

**按钮约定**：`setButton(s1,s2,s3,s4)`；`s3` 按钮 → `isDecode()==false`；`s4` 按钮 → `isDecode()==true`。

**贯穿全局的三个转换函数（必须逐字照抄）**

```java
// 字节 → 小写 hex，无前缀、无分隔
public String Byte2Hex(byte[] b) {
    char[] H = "0123456789abcdef".toCharArray();
    char[] o = new char[b.length << 1];
    for (int i = 0, j = 0; i < b.length; i++) {
        o[j++] = H[(b[i] & 0xF0) >>> 4];
        o[j++] = H[b[i] & 0x0F];
    }
    return new String(o);
}

// hex → 字节；奇数长度丢弃末尾字符；非法字符抛异常
public static byte[] Hex2Byte(String s) {
    int n = s.length() / 2;  byte[] o = new byte[n];
    for (int i = 0; i < n; i++) o[i] = (byte) Integer.valueOf(s.substring(i*2, i*2+2), 16).intValue();
    return o;
}

// 通用进制转换
public String transRadix(String s, int from, int to) { return new BigInteger(s, from).toString(to); }
```

---

## 三、Tab 1「算法」（7 项）

### 3.1 BASE — `BaseActivity`

算法列表：`BASE91, BASE85, BASE64, BASE62, BASE58, BASE36, BASE32, BASE16`

#### 字符集常量（**从 dex 字节精确提取**）

```js
const base91 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;'=\\?@[]^_`{-}~\"";
// ↑ 91 个。注意作者改过字母表：标准 basE91 的 < > | 被换成了 ' \ -
const base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";  // 58，标准 Bitcoin
const base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";                            // 32，标准 RFC4648
const base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; // 实际 64 个字符！
```

- **BASE91**：标准 basE91 算法（13/14 位分块），只是字母表不同。
- **BASE85**：ASCII85（`z` 表示 4 字节全零），chunk 除权 `[1,85,7225,614125,52200625]`，字符 `值+33`。解码时 `z` 展开为 `!!!!!`，末尾不足用 `'u'`(117) 补齐。
- **BASE64**：Android `Base64.encodeToString(b, 0)` 后 `.replace("\n","")` —— 就是标准 base64，无换行。
- **BASE62**：6 位一组，**非常规**。字符 `i` 是转义前缀：`i`→`"ia"`、`+`→`"ib"`、`/`→`"ic"`（因为 `i` 本身在表里位于索引 34）。尾部不足 6 位时左移补零。
- **BASE58**：标准 base58（BigInteger 风格的 divmod 循环），前导零字节 → 前导 `1`。
- **BASE36**：`new BigInteger(bytes).toString(36)`，**正数前缀 `z`，负数把 `-` 换成 `f`**。解码时首字符 `z` → 去掉，否则 `f` → 补 `-`。
- **BASE32**：自定义实现（非 RFC4648，**无填充 `=`**），5 位一组。
- **BASE16**：就是 `Byte2Hex` / `Hex2Byte`。

---

### 3.2 Code — `CodeActivity`

算法列表：`BYTE, URL, Unicode, Tianyu`

- **BYTE**
  - 编码 = `Arrays.toString(byte[])` → `[1, 2, 3]`（逗号后带空格）
  - 解码 = 去掉 `\n`、`[`、`]`、`(byte)`、空格，按 `,` split 后逐项 `Integer.valueOf`
  - 有个「正则模式」（SP key `Byte2`）：开启后自动从文本里匹配 `\[.*\]` 的内容逐个解码，方便处理 Log 里打印的字节数组
- **URL**：`URLEncoder.encode` / `URLDecoder.decode`（Java 语义：空格→`+`，不编码 `* - _ .`）
- **Unicode**
  - 编码：`char > 127` 才转 `\uXXXX`，且用 `Integer.toHexString(c)` —— **不补零**（0x0a → `\ua`）
  - 解码：标准 `\uXXXX` 解析；额外支持 `\t \r \n \f`；**遇到非十六进制字符直接返回空串**
- **Tianyu**：`return bArr;` —— **空实现，原样返回。作者没做完。**

---

### 3.3 AES — `AesActivity`

列表（16 种）：`AES/{ECB,CBC,CFB,OFB}/{Pkcs7Padding,Pkcs5Padding,ISO10126Padding,NoPadding}`

```
输入字节 → (若解密) 按输出编码解码 → 取 Key → (若加密) 手工补零 → Cipher → 输出编码
```

- **Key 处理**：`getKEYBytes()` 后按长度补齐/截断到 16 / 24 / 32 字节（>24→32，>16→24，否则 16），不足部分补 `0x00`
- **IV**：`getIVBytes()` 截断或补零到 16 字节；**ECB 模式不传 IV**（UI 上隐藏 IV 输入框）
- **NoPadding 手工补零**：`i = keyLen - (len % keyLen)`，补 `i` 个 `0x00`（用 **key 长度**算，不是块长）
- **输入/输出编码**：`No` / `Base`(Base64) / `Hex`
- Java 允许 `Pkcs7Padding`（Android 特有，等价 PKCS5）

### 3.4 DES — `DesActivity`

同 AES 结构，算法名换成 `DES/...`。Key 长度为 8 字节（DES 的 key 补齐逻辑需按 8 处理）。

### 3.5 RC4 — `Rc4Activity`

单算法 `RC4`。**自实现**（Java 标准库不提供 RC4）：

```java
// KSA
byte[] S = new byte[256]; for (int i=0;i<256;i++) S[i]=(byte)i;
int j=0, k=0;
for (int i=0;i<256;i++) {
    int t = KEY[k]&255;
    byte b = S[i];
    j = (t + (b&255) + j) & 255;
    S[i]=S[j]; S[j]=b;
    k = (k+1) % KEY.length;
}
// PRGA
byte[] out = new byte[data.length];
int i=0; j=0;
for (int n=0;n<data.length;n++) {
    i = (i+1)&255; byte b = S[i];
    j = ((b&255)+j)&255;
    S[i]=S[j]; S[j]=b;
    out[n] = (byte)(S[((S[i]&255)+(b&255))&255] ^ data[n]);
}
```

编码选项 `No` / `Base` / `Hex`。

### 3.6 RSA — `RsaActivity`

算法列表：`RSA/ECB/PKCS1Padding, RSA/ECB/NoPadding`

- **KEY 框 = 公钥**（X.509 `X509EncodedKeySpec`），**IV 框 = 私钥**（PKCS#8 `PKCS8EncodedKeySpec`）
- **密钥格式自动识别**：`^[a-f|0-9|A-F]+$` 全匹配 → 当 Hex 解；`^[A-Z|a-z|0-9|+|/|=]+$` 全匹配 → 当 Base64 解；否则原样当作 DER
  - 注意正则里 `|` 在字符类内是字面量 —— 这是原码的 bug，复刻时保留同样判定即可（实际影响极小）
- **两个模式**（图标切换，SP key `Mode`）：
  - mode 0：**公钥加密 / 私钥解密**（默认）
  - mode 1：**私钥加密 / 公钥解密**
- 按 `cipher.getBlockSize()` 分块 `doFinal`
- **密钥生成**：`KeyPairGenerator("RSA")`，位数可选（默认 1024），输出格式 `No`/`Base`/`Hex`，写成 `PrivateKey.key` / `PublicKey.key`

### 3.7 Hash — `HashActivity`

列表（17 种）：
`MD5, MD4, MD2, SHA, SHA224, SHA256, SHA384, SHA512, HmacMD5, HmacSHA1, HmacSHA224, HmacSHA256, HmacSHA384, HmacSHA512, Hash, CRC32, Adler32`

- **输入编码**（SP key `inputcode`）：`No` / `Base`(Base64 解) / `Hex`
- **输出编码**：`No` / `Base` / `Hex`
- KEY 框仅在算法名以 `Hmac` 开头时显示
- **标准库系**：`MessageDigest.getInstance(算法名)` —— 注意算法名就是列表里那个串（`SHA` = SHA-1，`SHA256` **无短横线**）；HMAC 用 `Mac.getInstance(...)` + `SecretKeySpec(key, 算法名)`
- **`Hash`** = `String.valueOf(new String(bytes).hashCode()).getBytes()` —— Java 的 32 位有符号 `hashCode`，转十进制字符串
- **`CRC32`** = `Long.toHexString(new java.util.zip.CRC32().update(b).getValue())` —— 小写 hex、**无前缀、无补零**
- **`Adler32`** = 同上，用 `java.util.zip.Adler32`
- **`MD2`** = 自写 `MD2Digest`，标准 RFC 1319（S 表 256 字节、X[48]/M[16]/C[16]、18 轮）
- **`MD4`** = 自写 `MD4Digest`，标准 RFC 1320；**注意返回值是 128 字节数组，只有前 16 字节有效**，调用处显式截断；长度字段只写低 32 位

---

## 四、Tab 2「数据」（11 项）

| # | 工具 | 类 | 模式 | 核心 |
| --- | --- | --- | --- | --- |
| 1 | 简繁体转换 | `JfActivity` | 默认字典 / DIY字典 / 默认+DIY | asset 两个 7659 字节字典逐位对应，`replaceAll` 正则替换 |
| 2 | 大小写转换 | `DxxActivity` | default / Alternate | default=`toUpperCase/toLowerCase`；Alternate 用自建 map 逐字符换 |
| 3 | Reverse | `FzActivity` | — | `StringBuffer.reverse()`（按 UTF-16 code unit，会破坏 emoji） |
| 4 | Replace | `ReplaceActivity` | default / Regex | KEY=查找、IV=替换 |
| 5 | TimeToDate | `TimeActivity` | `yyyy_MM_dd HH:mm:ss` / `yyyy_MM_dd` | `SimpleDateFormat`；输入进制可选 十进制/十六进制 |
| 6 | StrToAscii | `AsciiActivity` | default / `&#` | default→`[72,101,...]`；`&#`→`&#72;&#101;` |
| 7 | SmaliToRegex | `RegexActivity` | — | 按行解析 smali，逐指令转正则（`invoke-`/`new-instance`/`iget`/`const`/`if-`/`move-result`/`:try_`） |
| 8 | FloatToHex | `FloatActivity` | Double / Float | `floatToIntBits` / `doubleToLongBits`；输入/输出进制可切；`.replace(".0","")` **全局替换（有 bug：1.05→1.5）** |
| 9 | StrToHex | `HexStrActivity` | default / `0x*` | `new BigInteger(1,bytes).toString(radix)`；滑块 2~36；`0x*` 模式每 2 字符加 `0x` 前缀 |
| 10 | HEX(Radix) | `HexActivity` | — | 双滑块 2~36，`new BigInteger(s,from).toString(to)`；失败显示「无法转换」 |
| 11 | ArmHextoHex | `ArmHexActivity` | — | 去空格换行后**每 2 字符一组倒序**（`11223344`→`44332211`）；**不联网** |

**注意**：`ArmActivity`（不在截图里）才联网 —— 它 POST 到 `https://armconverter.com/api/convert` 做 ARM↔机器码转换。

### 关键坑（复刻必须一致或明确改良）

1. `DxxActivity` 的字母表**拼写错误**：`"ABCDEFGHIJKLNMOPQRSTUVWSYZ"`（N/M 颠倒，**X 缺失、S 重复**）。Alternate 模式下遇到非字母字符（含 `X`/`x`）→ `map.get()` 返回 null → NPE → 输出 Java 堆栈。
2. `JfActivity` 用的是 **`replaceAll`（正则）** 而非 `replace`，字典里若有正则元字符会炸；且简/繁方向与按钮文案**相反**（点"简体"是简→繁）。
3. `JfActivity` 循环上界用简体数组长度、索引用繁体数组 —— **两个字典长度必须相等**，否则越界。
4. `FloatActivity` 的 `.replace(".0","")` 全局替换：`1.05` → `1.5`。
5. `AsciiActivity` default 编码空串会 `substring(0,-1)` 越界（被上游空输入检查挡住）。
6. `ArmHexActivity` 只去掉**半角空格和 `\n`**，`\r`、制表符、全角空格不处理。
7. 所有工具的异常路径：`Debug` 默认 true → 结果框显示**整段 Java 异常堆栈**。

---

## 五、Tab 3「文件」（6 项，安卓专属）

| 工具 | 类 | 说明 |
| --- | --- | --- |
| CRC32 | `CrcActivity` | 篡改文件 CRC（改 zip 内条目的 CRC 字段） |
| FileByte | `FileByteActivity` | 两个文件逐字节对比 |
| DexLoader | `DexActivity` | 动态加载 dex |
| APK Encryption | `StubActivity` | 给 APK 加壳：塞入 `assets/jiagu.dex` 的 `StubApp`，用 `attachBaseContext` + `InMemoryDexClassLoader` 反射加载解密后的 dex |
| APK Decryption | `JgActivity` | **随风加固 / Arm 加固**的静态脱壳 |
| Dex Fix | `FixActivity` | 修复 dex 文件头/校验 |

另有截图外功能：`FileSplitActivity`（文件拆分，4 种方案）、`FileMergeActivity`（合并）。

**这一 tab 网页版做不了，留给安卓版。**

---

## 六、复刻分两步

### 第一步：单文件网页版
覆盖 Tab 1 + Tab 2，共 **18 个工具**。零依赖、双击即用、可发 GitHub Pages。
- 纯 JS 实现，不依赖 Web Crypto（因为需要 CFB/OFB/ISO10126/NoPadding，WebCrypto 不支持）
- 需要自写：AES(+解密)、DES、RC4、MD2、MD4、BASE85/62/58/36/91、BigInt 大数 RSA + DER 解析
- 沿用上个项目（与佛论禅）的手写 AES 思路

### 第二步：安卓 App
Kotlin 重写，三个 tab 全覆盖。策略：**把网页版验证过的算法逻辑一对一翻译成 Kotlin**，再套原生 UI。

### 网页版相对原版的改良点
1. 实时转换（边输边出），不用点按钮
2. 错误提示人话化，不再吐 Java 堆栈
3. 修掉上面的 bug（字母表、`.replace(".0")`、繁简反向），但**保留原版行为选项**，避免互操作时对不上
4. 加「本次转换用到的参数」展示，方便核对
