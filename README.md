# File Encryption & Decryption Tool (AES-256-GCM)

## 1. Introduction
This is a command-line tool built in Java to securely encrypt and decrypt any file using AES-256-GCM.
It derives a strong encryption key from a password using PBKDF2WithHmacSHA256, ensuring strong security and data integrity.
The encrypted output file contains the salt, IV, ciphertext, and authentication tag packaged together.

## 2. Tech Stack
- Java 17
- AES-256-GCM (Java Cryptography Architecture)
- PBKDF2WithHmacSHA256 (password-based key derivation)
- Maven (build tool)

## 3. Project Structure

src/main/java/com/example/filecrypto/
│── Main.java          // CLI for encryption and decryption
│── CryptoUtils.java   // AES-GCM encrypt/decrypt + packaging
└── KeyUtils.java      // PBKDF2 key derivation + salt generation
pom.xml                // Maven configuration


## 4. Important Notes
- If you lose your password, the data cannot be decrypted.  
- AES-GCM includes authentication; any tampering will cause decryption to fail.  
- Encrypted file format:  
  [saltLength][salt][ivLength][iv][ciphertext][tag]  
- Custom hex salt may be used for deterministic encryption (advanced).

## 5. How to Use
- Build the Project: '''mvn clean package'''
- This will generate: target/file-crypto-cli-1.0.0.jar
- Encrypt a file: java -jar target/file-crypto-cli-1.0.0.jar encrypt input.txt encrypted.bin --password "mypassword"
- Decrypt a file: java -jar target/file-crypto-cli-1.0.0.jar decrypt encrypted.bin output.txt --password "mypassword"

## 6. Example Workflow
- Create a test file: echo "Hello World" > test.txt
- Encrypt: java -jar target/file-crypto-cli-1.0.0.jar encrypt test.txt secure.bin --password "1234"
- Decrypt: java -jar target/file-crypto-cli-1.0.0.jar decrypt secure.bin decrypted.txt --password "1234"
- Verify: cat decrypted.txt

## 7. License
- This project is open-source and available for free use.


