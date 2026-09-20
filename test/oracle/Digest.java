import java.security.MessageDigest;
import java.util.*;

public class Digest {
    public static void main(String[] a) throws Exception {
        String[] algos = {"MD2","MD4","MD5","SHA-1","SHA-224","SHA-256","SHA-384","SHA-512","SHA3-224","SHA3-256","SHA3-384","SHA3-512"};
        // 长度边界 + 随机长度
        List<byte[]> msgs = new ArrayList<>();
        int[] lens = {0,1,15,16,17,31,32,47,48,55,56,57,63,64,65,79,80,100,111,112,113,127,128,129,1000};
        for (int n : lens) {
            byte[] b = new byte[n];
            for (int i = 0; i < n; i++) b[i] = (byte)((i * 37 + 11) & 0xff);
            msgs.add(b);
        }
        StringBuilder sb = new StringBuilder();
        for (String algo : algos) {
            MessageDigest md;
            try { md = MessageDigest.getInstance(algo); } catch (Exception e) { sb.append("SKIP ").append(algo).append("\n"); continue; }
            for (byte[] m : msgs) {
                byte[] d = md.digest(m);
                sb.append(algo).append(' ').append(m.length).append(' ');
                for (byte x : d) sb.append(String.format("%02x", x));
                sb.append('\n');
            }
        }
        // HMAC
        String[][] hm = {{"HmacMD5","MD5"},{"HmacSHA1","SHA-1"},{"HmacSHA256","SHA-256"},{"HmacSHA512","SHA-512"}};
        for (String[] p : hm) {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance(p[0]);
            for (byte[] m : msgs) {
                mac.init(new javax.crypto.spec.SecretKeySpec("key-龙000".getBytes("UTF-8"), p[0]));
                byte[] d = mac.doFinal(m);
                sb.append("HMAC-").append(p[1]).append(' ').append(m.length).append(' ');
                for (byte x : d) sb.append(String.format("%02x", x));
                sb.append('\n');
            }
        }
        System.out.print(sb);
    }
}
