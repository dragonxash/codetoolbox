import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.*;

/** 密码层预言机：用 JCE 生成权威向量，供 JS 实现逐字节对拍 */
public class CipherOracle {
    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
    static byte[] pattern(int n, int seed) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte) ((i * 29 + seed * 17 + 3) & 0xff);
        return b;
    }

    public static void main(String[] args) throws Exception {
        StringBuilder out = new StringBuilder();

        String[] aesSpecs = {
            "AES/ECB/PKCS5Padding", "AES/CBC/PKCS5Padding", "AES/CFB/PKCS5Padding", "AES/OFB/PKCS5Padding",
            "AES/CFB/NoPadding", "AES/OFB/NoPadding", "AES/CTR/NoPadding", "AES/ECB/NoPadding", "AES/CBC/NoPadding"
        };
        String[] desSpecs = {
            "DES/ECB/PKCS5Padding", "DES/CBC/PKCS5Padding", "DES/CFB/NoPadding", "DES/OFB/NoPadding",
            "DES/ECB/NoPadding", "DES/CBC/NoPadding"
        };
        String[] des3Specs = { "DESede/ECB/NoPadding", "DESede/CBC/PKCS5Padding", "DESede/ECB/PKCS5Padding" };

        int[] paddedLens = {0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 100};

        for (String spec : aesSpecs) {
            boolean noPad = spec.contains("NoPadding");
            for (int kl : new int[]{16, 24, 32}) {
                byte[] key = pattern(kl, kl);
                for (int dl : (noPad ? new int[]{0, 16, 32, 48} : paddedLens)) {
                    out.append(run(spec, key, dl));
                }
            }
        }
        for (String spec : desSpecs) {
            boolean noPad = spec.contains("NoPadding");
            byte[] key = pattern(8, 8);
            for (int dl : (noPad ? new int[]{0, 8, 16, 24} : paddedLens)) {
                out.append(run(spec, key, dl));
            }
        }
        for (String spec : des3Specs) {
            boolean noPad = spec.contains("NoPadding");
            byte[] key = pattern(24, 24);
            for (int dl : (noPad ? new int[]{0, 8, 16, 24} : paddedLens)) {
                out.append(run(spec, key, dl));
            }
        }

        // RC4（ARCFOUR）
        int[] rc4Lens = {0, 1, 8, 16, 17, 100, 1000};
        for (int kl : new int[]{5, 16}) {
            byte[] key = pattern(kl, kl);
            for (int dl : rc4Lens) {
                Cipher c = Cipher.getInstance("ARCFOUR");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ARCFOUR"));
                byte[] d = pattern(dl, dl);
                out.append("ARCFOUR|").append(hex(key)).append("||").append(hex(d)).append("|")
                   .append(hex(c.doFinal(d))).append("\n");
            }
        }

        System.out.print(out);
    }

    static String run(String spec, byte[] key, int dl) {
        try {
            String[] parts = spec.split("/");
            String algo = parts[0];
            String mode = parts.length > 1 ? parts[1] : "ECB";
            Cipher c = Cipher.getInstance(spec);
            int bs = c.getBlockSize();
            byte[] iv = pattern(Math.max(bs, 1), 99);
            byte[] data = pattern(dl, dl);
            if ("ECB".equals(mode)) {
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algo));
            } else {
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algo), new IvParameterSpec(iv));
            }
            byte[] enc = c.doFinal(data);
            Cipher c2 = Cipher.getInstance(spec);
            if ("ECB".equals(mode)) {
                c2.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algo));
            } else {
                c2.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algo), new IvParameterSpec(iv));
            }
            byte[] dec = c2.doFinal(enc);
            String check = Arrays.equals(dec, data) ? "ok" : "BAD";
            return spec + "|" + hex(key) + "|" + hex(iv) + "|" + hex(data) + "|" + hex(enc) + "|" + bs + "|" + check + "\n";
        } catch (Exception e) {
            return "ERR " + spec + " dl=" + dl + " : " + e + "\n";
        }
    }
}
