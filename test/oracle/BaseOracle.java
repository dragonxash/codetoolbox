import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * BASE 系列预言机：方法体由反编译源码 verbatim 移植（去掉 Android 依赖），
 * 用于校验 JS 复刻版是否与原 APP 逐字节一致。
 */
public class BaseOracle {

    static char[] base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    static char[] base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    static char[] base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
    static byte[] base91 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;'=\\?@[]^_`{-}~\"".getBytes();

    /* ============ 原版工具 ============ */
    public static String Byte2Hex(byte[] b) {
        char[] H = "0123456789abcdef".toCharArray();
        char[] o = new char[b.length << 1];
        for (int i = 0, j = 0; i < b.length; i++) {
            o[j++] = H[(b[i] & 0xF0) >>> 4];
            o[j++] = H[b[i] & 0x0F];
        }
        return new String(o);
    }
    public static byte[] Hex2Byte(String s) {
        int n = s.length() / 2;
        byte[] o = new byte[n];
        for (int i = 0; i < n; i++) o[i] = (byte) Integer.valueOf(s.substring(i * 2, i * 2 + 2), 16).intValue();
        return o;
    }

    /* ============ BASE91 ============ */
    static byte[] BASE91Encode(byte[] bArr) {
        byte[] bArr2 = base91;
        int length = bArr2.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream((int) Math.ceil(bArr.length * 1.2297f));
        int i = 0, i2 = 0;
        for (byte b : bArr) {
            i |= (b & 255) << i2;
            i2 += 8;
            if (i2 > 13) {
                int i3 = i & 8191;
                if (i3 > 88) { i2 -= 13; i >>= 13; }
                else { i3 = i & 16383; i2 -= 14; i >>= 14; }
                out.write(bArr2[i3 % length]);
                out.write(bArr2[i3 / length]);
            }
        }
        if (i2 > 0) {
            out.write(bArr2[i % length]);
            if (i2 > 7 || i > 90) out.write(bArr2[i / length]);
        }
        return out.toByteArray();
    }
    static byte[] BASE91Decode(byte[] bArr) {
        byte[] bArr2 = base91;
        int length = bArr2.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.round(bArr.length / 1.2297f));
        byte[] bArr3 = new byte[256];
        for (int i = 0; i < 256; i++) bArr3[i] = (byte) (-1);
        for (int i2 = 0; i2 < length; i2++) bArr3[bArr2[i2]] = (byte) i2;
        byte b = (byte) (-1), b2 = b;
        int i3 = 0, i4 = 0;
        for (byte b3 : bArr) {
            byte b4 = bArr3[b3];
            if (b4 != -1) {
                if (b2 == -1) b2 = b4;
                else {
                    int i5 = b2 + (b4 * length);
                    i3 |= i5 << i4;
                    i4 += (i5 & 8191) > 88 ? 13 : 14;
                    do { out.write((byte) i3); i3 >>= 8; i4 -= 8; } while (i4 > 7);
                    b2 = b;
                }
            }
        }
        if (b2 != -1) out.write((byte) ((b2 << i4) | i3));
        return out.toByteArray();
    }

    /* ============ BASE85 ============ */
    static String BASE85Encode(byte[] bArr) {
        StringBuilder sb = new StringBuilder((bArr.length * 5) / 4);
        byte[] bArr2 = new byte[4];
        int i = 0;
        for (byte b : bArr) {
            int i2 = i + 1;
            bArr2[i] = b;
            if (i2 == 4) {
                int v = byteToInt(bArr2);
                if (v == 0) sb.append('z'); else sb.append(encodeChunk(v));
                Arrays.fill(bArr2, (byte) 0);
                i = 0;
            } else i = i2;
        }
        if (i > 0) {
            Arrays.fill(bArr2, i, 4, (byte) 0);
            char[] c = encodeChunk(byteToInt(bArr2));
            for (int i3 = 0; i3 < c.length - (4 - i); i3++) sb.append(c[i3]);
        }
        return sb.toString();
    }
    static char[] encodeChunk(int i) {
        int[] p = {1, 85, 7225, 614125, 52200625};
        long j = 4294967295L & ((long) i);
        char[] c = new char[5];
        for (int k = 0; k < 5; k++) {
            int d = p[4 - k];
            c[k] = (char) ((j / ((long) d)) + ((long) 33));
            j %= (long) d;
        }
        return c;
    }
    static int byteToInt(byte[] b) { return ByteBuffer.wrap(b).getInt(); }
    static byte[] BASE85Decode(byte[] bArr) {
        int i;
        Pattern p = Pattern.compile("\\s+");
        String str = new String(bArr);
        int length = str.length();
        int i2 = 0;
        for (int i3 = 0; i3 < str.length(); i3++) if (str.charAt(i3) == 'e') i2++;
        ByteBuffer buf = ByteBuffer.allocate(BigDecimal.valueOf(i2).multiply(BigDecimal.valueOf(4L))
                .add(BigDecimal.valueOf(length - i2).multiply(BigDecimal.valueOf(4L)).divide(BigDecimal.valueOf(5L))).intValue());
        byte[] bArr2 = new byte[5];
        byte[] bytes = p.matcher(str).replaceAll("").getBytes();
        int i4 = 0;
        for (byte b : bytes) {
            if (b == 122) {
                int i5 = i4 + 1; byte b2 = (byte) 33; bArr2[i4] = b2;
                int i6 = i5 + 1; bArr2[i5] = b2;
                int i7 = i6 + 1; bArr2[i6] = b2;
                int i8 = i7 + 1; bArr2[i7] = b2;
                i = i8 + 1; bArr2[i8] = b2;
            } else { bArr2[i4] = b; i = i4 + 1; }
            if (i != 5) i4 = i;
            else { buf.put(decodeChunk(bArr2)); Arrays.fill(bArr2, (byte) 0); i4 = 0; }
        }
        if (i4 > 0) {
            Arrays.fill(bArr2, i4, 5, (byte) 117);
            byte[] d = decodeChunk(bArr2);
            for (int i9 = 0; i9 < d.length - (5 - i4); i9++) buf.put(d[i9]);
        }
        buf.flip();
        return Arrays.copyOf(buf.array(), buf.limit());
    }
    static byte[] decodeChunk(byte[] bArr) {
        int[] p = {1, 85, 7225, 614125, 52200625};
        return intToByte(((bArr[0] - 33) * p[4]) + 0 + ((bArr[1] - 33) * p[3]) + ((bArr[2] - 33) * p[2])
                + ((bArr[3] - 33) * p[1]) + ((bArr[4] - 33) * p[0]));
    }
    static byte[] intToByte(int i) { return new byte[]{(byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i}; }

    /* ============ BASE62 ============ */
    static String BASE62Encode(byte[] bArr) {
        String s1, s2, s3;
        char[] cArr = base62;
        StringBuffer sb = new StringBuffer(bArr.length * 2);
        int i = 0, i2 = 0, i3 = 0;
        while (true) {
            s2 = "ic"; s1 = "ia";
            if (i >= bArr.length) break;
            i2 = (i2 << 8) | (bArr[i] & 255);
            i3 += 8;
            while (i3 > 5) {
                i3 -= 6;
                char c = cArr[i2 >> i3];
                if (c == 'i') s3 = "ia";
                else if (c == '+') s3 = "ib";
                else s3 = c == '/' ? "ic" : String.valueOf(c);
                sb.append(s3);
                i2 &= (1 << i3) - 1;
            }
            i++;
        }
        if (i3 > 0) {
            char c2 = cArr[i2 << (6 - i3)];
            if (c2 != 'i') {
                if (c2 == '+') s2 = "ib";
                else if (c2 != '/') s2 = String.valueOf(c2);
                s1 = s2;
            }
            sb.append(s1);
        }
        return sb.toString();
    }
    static byte[] BASE62Decode(byte[] bArr) {
        char[] cArr = base62;
        byte[] bArr2 = new byte[256];
        char[] ca = new String(bArr).toCharArray();
        ByteArrayOutputStream out = new ByteArrayOutputStream(ca.length);
        int i = 0, i2 = 0, i3 = 0;
        while (i < ca.length) {
            char c = ca[i];
            if (c == 'i') {
                i++;
                char c2 = ca[i];
                if (c2 == 'a') c = 'i';
                else if (c2 == 'b') c = '+';
                else if (c2 == 'c') c = '/';
                else { i--; c = ca[i]; }
            }
            for (int k = 0; k < cArr.length; k++) bArr2[cArr[k]] = (byte) k;
            i2 = (i2 << 6) | bArr2[c];
            i3 += 6;
            while (i3 > 7) { i3 -= 8; out.write(i2 >> i3); i2 &= (1 << i3) - 1; }
            i++;
        }
        return out.toByteArray();
    }

    /* ============ BASE58 ============ */
    static byte[] BASE58Encode(byte[] bArr) {
        char[] cArr = base58;
        byte[] a = Arrays.copyOfRange(bArr, 0, bArr.length);
        int i = 0;
        while (i < a.length && a[i] == 0) i++;
        int length = a.length * 2;
        byte[] b = new byte[length];
        int i2 = i, i3 = length;
        while (i2 < a.length) {
            byte d = divmod58(a, i2);
            if (a[i2] == 0) i2++;
            i3--;
            b[i3] = (byte) cArr[d];
        }
        while (i3 < length && b[i3] == cArr[0]) i3++;
        while (true) {
            i--;
            if (i >= 0) { i3--; b[i3] = (byte) cArr[0]; }
            else return Arrays.copyOfRange(b, i3, length);
        }
    }
    static byte divmod58(byte[] a, int i) {
        char[] cArr = base58;
        int r = 0;
        while (i < a.length) {
            int v = (r * 256) + (a[i] & 255);
            a[i] = (byte) (v / cArr.length);
            r = v % cArr.length;
            i++;
        }
        return (byte) r;
    }
    static byte[] BASE58Decode(byte[] bArr) {
        char[] cArr = base58;
        String str = new String(bArr);
        int[] map = new int[128];
        for (int i = 0; i < 128; i++) map[i] = -1;
        for (int i2 = 0; i2 < cArr.length; i2++) map[cArr[i2]] = i2;
        int length = str.length();
        byte[] a = new byte[length];
        for (int i3 = 0; i3 < str.length(); i3++) {
            char ch = str.charAt(i3);
            a[i3] = (byte) ((ch < 0 || ch >= 128) ? -1 : map[ch]);
        }
        int i4 = 0;
        while (i4 < length && a[i4] == 0) i4++;
        byte[] b = new byte[length];
        int i5 = i4, i6 = length;
        while (i5 < length) {
            byte d = divmod256(a, i5);
            if (a[i5] == 0) i5++;
            i6--;
            b[i6] = d;
        }
        while (i6 < length && b[i6] == 0) i6++;
        return Arrays.copyOfRange(b, i6 - i4, length);
    }
    static byte divmod256(byte[] a, int i) {
        char[] cArr = base58;
        int r = 0;
        while (i < a.length) {
            int v = (r * cArr.length) + (a[i] & 255);
            a[i] = (byte) (v / 256);
            r = v % 256;
            i++;
        }
        return (byte) r;
    }

    /* ============ BASE36 ============ */
    static String BASE36Encode(byte[] bArr) {
        String s = new BigInteger(bArr).toString(36);
        if (s.charAt(0) == '-') {
            StringBuffer sb = new StringBuffer(s);
            sb.setCharAt(0, 'f');
            return sb.toString();
        }
        return new StringBuffer().append("z").append(s).toString();
    }
    static byte[] BASE36Decode(String str) {
        String s;
        if (str.charAt(0) == 'z') s = str.substring(1);
        else s = new StringBuffer().append("-").append(str.substring(1)).toString();
        return new BigInteger(s, 36).toByteArray();
    }

    /* ============ BASE32 ============ */
    static String BASE32Encode(byte[] bArr) {
        char[] cArr = base32;
        int length = ((bArr.length * 8) / 5) + (bArr.length % 5 != 0 ? 1 : 0);
        char[] c = new char[length];
        int i = 0, i2 = 0;
        for (int i3 = 0; i3 < length; i3++) {
            if (i > 3) {
                int i4 = bArr[i2] & (255 >> i);
                i = (i + 5) % 8;
                int i5 = i4 << i;
                if (i2 < bArr.length - 1) i5 |= (255 & bArr[i2 + 1]) >> (8 - i);
                c[i3] = cArr[i5];
                i2++;
            } else {
                int i6 = i + 5;
                c[i3] = cArr[(bArr[i2] >> (8 - i6)) & 31];
                i = i6 % 8;
                if (i == 0) i2++;
            }
        }
        return new String(c);
    }
    static byte[] BASE32Decode(String str) {
        char[] cArr = base32;
        byte[] map = new byte[128];
        for (int i = 0; i < 128; i++) map[i] = -1;
        for (int i2 = 0; i2 < cArr.length; i2++) {
            char c = cArr[i2];
            byte b = (byte) i2;
            map[c] = b;
            if (i2 < 24) map[Character.toLowerCase(c)] = b;
        }
        char[] ca = new String(str).toCharArray();
        int length = (ca.length * 5) / 8;
        byte[] out = new byte[length];
        int i3 = 0, i4 = 0;
        for (char c2 : ca) {
            byte b2 = map[c2];
            if (i3 <= 3) {
                i3 = (i3 + 5) % 8;
                if (i3 == 0) { out[i4] = (byte) (b2 | out[i4]); i4++; }
                else out[i4] = (byte) ((b2 << (8 - i3)) | out[i4]);
            } else {
                i3 = (i3 + 5) % 8;
                int i5 = i4 + 1;
                out[i4] = (byte) (out[i4] | (b2 >> i3));
                if (i5 < length) out[i5] = (byte) (out[i5] | (b2 << (8 - i3)));
                i4 = i5;
            }
        }
        return out;
    }

    /* ============ BASE64 ============ */
    static String BASE64Encode(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    static byte[] BASE64Decode(byte[] b) { return Base64.getMimeDecoder().decode(b); }

    /* ============ 主程序 ============ */
    static String hex(byte[] b) { return Byte2Hex(b); }
    static byte[] pat(int n, int seed) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte) ((i * 29 + seed * 17 + 3) & 0xff);
        return b;
    }
    static String q(String s) { return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""; }

    interface Fn { String call(byte[] d) throws Exception; }
    static String tryCall(String tag, int n, byte[] d, Fn f) {
        try { return tag + " " + n + " " + q(f.call(d)) + "\n"; }
        catch (Exception e) { return tag + " " + n + " ERR " + e.getClass().getSimpleName() + "\n"; }
    }

    public static void main(String[] args) throws Exception {
        StringBuilder sb = new StringBuilder();
        int[] lens = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 31, 32, 33, 62, 63, 64, 100};
        for (int n : lens) {
            byte[] d = pat(n, n);
            sb.append("DATA ").append(n).append(' ').append(hex(d)).append('\n');
        }
        sb.append("ALPHABET base91 ").append(q(new String(base91, "ISO-8859-1"))).append('\n');
        sb.append("ALPHABET base62 ").append(q(new String(base62))).append('\n');
        sb.append("ALPHABET base58 ").append(q(new String(base58))).append('\n');
        sb.append("ALPHABET base32 ").append(q(new String(base32))).append('\n');

        for (int n : lens) {
            byte[] d = pat(n, n);
            sb.append(tryCall("BASE16", n, d, x -> Byte2Hex(x)));
            sb.append(tryCall("BASE64", n, d, x -> BASE64Encode(x).replace("\n", "")));
            sb.append(tryCall("BASE32", n, d, x -> BASE32Encode(x)));
            sb.append(tryCall("BASE36", n, d, x -> BASE36Encode(x)));
            sb.append(tryCall("BASE58", n, d, x -> new String(BASE58Encode(x), "ISO-8859-1")));
            sb.append(tryCall("BASE62", n, d, x -> BASE62Encode(x)));
            sb.append(tryCall("BASE85", n, d, x -> BASE85Encode(x)));
            sb.append(tryCall("BASE91", n, d, x -> new String(BASE91Encode(x), "ISO-8859-1")));
        }

        for (int n : lens) {
            byte[] d = pat(n, n);
            sb.append(tryCall("D16", n, d, x -> hex(Hex2Byte(Byte2Hex(x)))));
            sb.append(tryCall("D64", n, d, x -> hex(BASE64Decode(BASE64Encode(x).getBytes()))));
            sb.append(tryCall("D32", n, d, x -> hex(BASE32Decode(BASE32Encode(x)))));
            sb.append(tryCall("D36", n, d, x -> hex(BASE36Decode(BASE36Encode(x)))));
            sb.append(tryCall("D58", n, d, x -> hex(BASE58Decode(BASE58Encode(x)))));
            sb.append(tryCall("D62", n, d, x -> hex(BASE62Decode(BASE62Encode(x).getBytes()))));
            sb.append(tryCall("D85", n, d, x -> hex(BASE85Decode(BASE85Encode(x).getBytes()))));
            sb.append(tryCall("D91", n, d, x -> hex(BASE91Decode(BASE91Encode(x)))));
        }

        String[] samples = {"", "abc", "hello world", "龙000の编码工具箱", "ABCabc0123+/", "1234567890123456789012345678901234567890"};
        for (int i = 0; i < samples.length; i++) {
            byte[] d = samples[i].getBytes("UTF-8");
            sb.append(tryCall("T16", i, d, x -> Byte2Hex(x)));
            sb.append(tryCall("T64", i, d, x -> BASE64Encode(x).replace("\n", "")));
            sb.append(tryCall("T32", i, d, x -> BASE32Encode(x)));
            sb.append(tryCall("T36", i, d, x -> BASE36Encode(x)));
            sb.append(tryCall("T58", i, d, x -> new String(BASE58Encode(x), "ISO-8859-1")));
            sb.append(tryCall("T62", i, d, x -> BASE62Encode(x)));
            sb.append(tryCall("T85", i, d, x -> BASE85Encode(x)));
            sb.append(tryCall("T91", i, d, x -> new String(BASE91Encode(x), "ISO-8859-1")));
        }
        sb.append("SAMPLES ").append(samples.length).append('\n');
        for (int i = 0; i < samples.length; i++) sb.append("S ").append(i).append(' ').append(q(samples[i])).append('\n');
        System.out.print(sb);
    }
}
