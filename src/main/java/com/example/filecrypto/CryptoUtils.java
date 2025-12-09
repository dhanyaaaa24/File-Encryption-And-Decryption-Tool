package com.example.filecrypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {

    // ---------- AES GCM Encryption Result ----------
    public static class EncryptionResult {
        private final byte[] iv;
        private final byte[] ciphertext;
        private final byte[] tag;

        public EncryptionResult(byte[] iv, byte[] ciphertext, byte[] tag) {
            this.iv = iv;
            this.ciphertext = ciphertext;
            this.tag = tag;
        }

        public byte[] getIv() { return iv; }
        public byte[] getCiphertext() { return ciphertext; }
        public byte[] getTag() { return tag; }
    }

    // ---------- AES GCM Encryption ----------
    public static EncryptionResult encryptAesGcm(byte[] plaintext, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException {
        byte[] iv = randomBytes(12);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        byte[] output = cipher.doFinal(plaintext);

        int tagLen = 16;
        byte[] ciphertext = Arrays.copyOfRange(output, 0, output.length - tagLen);
        byte[] tag = Arrays.copyOfRange(output, output.length - tagLen, output.length);

        return new EncryptionResult(iv, ciphertext, tag);
    }

    // ---------- AES GCM Decryption ----------
    public static byte[] decryptAesGcm(byte[] ciphertext, byte[] key, byte[] iv, byte[] tag) throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

        byte[] combined = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
        System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);

        return cipher.doFinal(combined);
    }

    // ---------- Packaged Output Format ----------
    public static byte[] packageEncrypted(byte[] salt, byte[] iv, byte[] ciphertext, byte[] tag) {
        if (salt.length > 255 || iv.length > 255) {
            throw new IllegalArgumentException("Salt and IV must be <= 255 bytes.");
        }

        int total = 1 + salt.length + 1 + iv.length + ciphertext.length + tag.length;
        byte[] out = new byte[total];
        int pos = 0;

        out[pos++] = (byte) salt.length;
        System.arraycopy(salt, 0, out, pos, salt.length);
        pos += salt.length;

        out[pos++] = (byte) iv.length;
        System.arraycopy(iv, 0, out, pos, iv.length);
        pos += iv.length;

        System.arraycopy(ciphertext, 0, out, pos, ciphertext.length);
        pos += ciphertext.length;

        System.arraycopy(tag, 0, out, pos, tag.length);

        return out;
    }

    // ---------- Packaged Data Holder ----------
    public static class PackagedData {
        private final byte[] salt;
        private final byte[] iv;
        private final byte[] ciphertext;
        private final byte[] tag;

        public PackagedData(byte[] salt, byte[] iv, byte[] ciphertext, byte[] tag) {
            this.salt = salt;
            this.iv = iv;
            this.ciphertext = ciphertext;
            this.tag = tag;
        }

        public byte[] getSalt() { return salt; }
        public byte[] getIv() { return iv; }
        public byte[] getCiphertext() { return ciphertext; }
        public byte[] getTag() { return tag; }
    }

    // ---------- Unpack Method ----------
    public static PackagedData unpackageEncrypted(byte[] packaged) {
        int pos = 0;

        int saltLen = Byte.toUnsignedInt(packaged[pos++]);
        byte[] salt = Arrays.copyOfRange(packaged, pos, pos + saltLen);
        pos += saltLen;

        int ivLen = Byte.toUnsignedInt(packaged[pos++]);
        byte[] iv = Arrays.copyOfRange(packaged, pos, pos + ivLen);
        pos += ivLen;

        int tagLen = 16;
        int remaining = packaged.length - pos;
        if (remaining < tagLen) {
            throw new IllegalArgumentException("Invalid package: too small for tag.");
        }

        byte[] ciphertext = Arrays.copyOfRange(packaged, pos, packaged.length - tagLen);
        byte[] tag = Arrays.copyOfRange(packaged, packaged.length - tagLen, packaged.length);

        return new PackagedData(salt, iv, ciphertext, tag);
    }

    // ---------- Utilities ----------
    public static byte[] randomBytes(int len) {
        byte[] b = new byte[len];
        new SecureRandom().nextBytes(b);
        return b;
    }

    public static byte[] hexToBytes(String hex) {
        String h = hex.replaceAll("\\s+", "");
        if (h.length() % 2 != 0) throw new IllegalArgumentException("Hex length must be even.");

        byte[] out = new byte[h.length() / 2];

        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(h.charAt(2*i), 16);
            int lo = Character.digit(h.charAt(2*i + 1), 16);

            if (hi < 0 || lo < 0)
                throw new IllegalArgumentException("Invalid hex string.");

            out[i] = (byte) ((hi << 4) + lo);
        }

        return out;
    }
}