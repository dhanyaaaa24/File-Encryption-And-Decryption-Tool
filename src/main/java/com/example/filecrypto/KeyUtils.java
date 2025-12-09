package com.example.filecrypto;

import java.security.SecureRandom;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class KeyUtils {

    public static byte[] deriveKeyFromPassword(String password, byte[] salt, int keyBits) throws java.security.NoSuchAlgorithmException, java.security.spec.InvalidKeySpecException {
        int iterations = 200_000; // Strong default; adjust if needed
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyBits);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(spec).getEncoded();
    }

    public static byte[] generateSalt(int len) {
        byte[] s = new byte[len];
        new SecureRandom().nextBytes(s);
        return s;
    }
}
