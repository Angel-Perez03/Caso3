package crypto;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class CryptoUtils {
    // Carga clave privada RSA desde archivo PKCS#8
    public static PrivateKey loadPrivateKey(String path) throws Exception {
        byte[] b = Files.readAllBytes(Paths.get(path));
        return java.security.KeyFactory
            .getInstance("RSA")
            .generatePrivate(new PKCS8EncodedKeySpec(b));
    }

    // Carga clave pública RSA desde archivo X.509
    public static PublicKey loadPublicKey(String path) throws Exception {
        byte[] b = Files.readAllBytes(Paths.get(path));
        return java.security.KeyFactory
            .getInstance("RSA")
            .generatePublic(new X509EncodedKeySpec(b));
    }

    // Genera IV aleatorio de 16 bytes para AES/CBC
    public static IvParameterSpec generateIV() {
        byte[] iv = new byte[16];
        new java.security.SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    // Cifra con AES/CBC/PKCS5
    public static byte[] encryptAES(byte[] data, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key, iv);
        return c.doFinal(data);
    }

    // Descifra con AES/CBC/PKCS5
    public static byte[] decryptAES(byte[] ct, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, key, iv);
        return c.doFinal(ct);
    }

    // Firma con RSA/SHA256
    public static byte[] sign(byte[] data, PrivateKey priv) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(priv);
        s.update(data);
        return s.sign();
    }

    // Verifica firma RSA/SHA256
    public static boolean verifySignature(byte[] data, byte[] sig, PublicKey pub) throws Exception {
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(pub);
        s.update(data);
        return s.verify(sig);
    }

    // Genera HMAC-SHA256
    public static byte[] generateHMAC(byte[] data, SecretKey key) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(key);
        return m.doFinal(data);
    }

    // Verifica HMAC-SHA256
    public static boolean verifyHMAC(byte[] data, byte[] hmac, SecretKey key) throws Exception {
        byte[] calc = generateHMAC(data, key);
        return MessageDigest.isEqual(calc, hmac);
    }

    // Deriva clave AES-256 de material compartido
    public static SecretKey deriveAESKey(byte[] shared) throws Exception {
        byte[] h = MessageDigest.getInstance("SHA-512").digest(shared);
        return new SecretKeySpec(Arrays.copyOf(h, 32), "AES");
    }

    // Deriva clave HMAC-SHA256 de material compartido
    public static SecretKey deriveHMACKey(byte[] shared) throws Exception {
        byte[] h = MessageDigest.getInstance("SHA-512").digest(shared);
        return new SecretKeySpec(Arrays.copyOfRange(h, 32, 64), "HmacSHA256");
    }
}
