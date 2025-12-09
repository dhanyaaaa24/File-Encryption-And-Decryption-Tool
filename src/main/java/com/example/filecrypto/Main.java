package com.example.filecrypto;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Main {

    private static void printUsage() {
        System.out.println("""
                File Encryption & Decryption Tool (AES-256-GCM)

                Usage:
                  Encrypt: java -jar file-crypto-cli.jar encrypt <inputFile> <outputFile> --password "<password>"
                  Decrypt: java -jar file-crypto-cli.jar decrypt <inputFile> <outputFile> --password "<password>"

                Optional flags:
                  --salt <hex>   Use a specific salt (hex) instead of generating one (advanced)

                Notes:
                  - Output format: [salt|iv|ciphertext|tag] combined in a single file.
                  - Keep your password secret; losing it means the data cannot be recovered.
                """);
    }

    public static void main(String[] args) {
        if (args.length < 4) {
            printUsage();
            System.exit(1);
        }

        String command = args[0];
        Path input = Paths.get(args[1]);
        Path output = Paths.get(args[2]);

        String password = null;
        byte[] saltOverride = null;

        for (int i = 3; i < args.length; i++) {
            if ("--password".equals(args[i]) && i + 1 < args.length) {
                password = args[++i];
            } else if ("--salt".equals(args[i]) && i + 1 < args.length) {
                saltOverride = CryptoUtils.hexToBytes(args[++i]);
            }
        }

        if (password == null || password.trim().isEmpty()) {
            System.err.println("Error: --password is required.");
            printUsage();
            System.exit(1);
        }

        try {
            if (!Files.exists(input)) {
                System.err.println("Error: Input file does not exist: " + input);
                System.exit(1);
            }

            switch (command.toLowerCase()) {
                case "encrypt" -> {
                    byte[] plaintext = Files.readAllBytes(input);

                    byte[] salt = (saltOverride != null) ? saltOverride : KeyUtils.generateSalt(16);
                    byte[] key = KeyUtils.deriveKeyFromPassword(password, salt, 256);

                    CryptoUtils.EncryptionResult result = CryptoUtils.encryptAesGcm(plaintext, key);

                    byte[] packaged = CryptoUtils.packageEncrypted(
                            salt,
                            result.getIv(),
                            result.getCiphertext(),
                            result.getTag());

                    Files.write(output, packaged);
                    System.out.println("Encrypted: " + input + " → " + output);
                }

                case "decrypt" -> {
                    byte[] packagedData = Files.readAllBytes(input);
                    CryptoUtils.PackagedData pd = CryptoUtils.unpackageEncrypted(packagedData);

                    byte[] key2 = KeyUtils.deriveKeyFromPassword(password, pd.getSalt(), 256);

                    byte[] decrypted = CryptoUtils.decryptAesGcm(
                            pd.getCiphertext(),
                            key2,
                            pd.getIv(),
                            pd.getTag());

                    Files.write(output, decrypted);
                    System.out.println("Decrypted: " + input + " → " + output);
                }

                default -> {
                    System.err.println("Unknown command: " + command);
                    printUsage();
                    System.exit(1);
                }
            }

        } catch (IOException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException
                | InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException
                | NoSuchPaddingException e) {
            System.err.println("Failure: " + e.getMessage());
            System.exit(2);
        }
    }
}
