# File Encryption & Decryption Tool (AES-256-GCM)

## 1. Introduction
This is a command-line tool built in Java to securely encrypt and decrypt any file using AES-256-GCM.
It derives a strong encryption key from the user’s password using PBKDF2WithHmacSHA256, ensuring confidentiality and integrity.
The tool outputs one packaged encrypted file containing the salt, IV, ciphertext, and authentication tag.

## 2. Tech Stack
- Java 17
- AES-256-GCM (Java Cryptography Architecture)
- PBKDF2WithHmacSHA256 (Password-based key derivation)
- Maven (Build automation)

## 3. Project Structure
src/main/java/com/example/filecrypto/
│── Main.java          // CLI for encryption and decryption
│── CryptoUtils.java   // AES-GCM encrypt/decrypt + packaging logic
└── KeyUtils.java      // PBKDF2 key derivation + salt generation

pom.xml                // Maven configuration

## 4. Important Notes
- If you lose your password, the data cannot be decrypted.
- AES-GCM provides authentication; any modification of encrypted data will make decryption fail.
- Encrypted output file format:
  [saltLength][salt][ivLength][iv][ciphertext][tag]
- Custom hex salt may be provided for advanced/deterministic encryption use cases.

## 5. How to Use

### Build the Project
mvn clean package

Produces:
target/file-crypto-cli-1.0.0.jar

### Encrypt a File
java -jar target/file-crypto-cli-1.0.0.jar encrypt input.txt encrypted.bin --password "mypassword"

### Decrypt a File
java -jar target/file-crypto-cli-1.0.0.jar decrypt encrypted.bin output.txt --password "mypassword"

### Sample Test
Create test file:
echo "Hello World" > test.txt

Encrypt:
java -jar target/file-crypto-cli-1.0.0.jar encrypt test.txt secure.bin --password "1234"

Decrypt:
java -jar target/file-crypto-cli-1.0.0.jar decrypt secure.bin decrypted.txt --password "1234"

Verify:
cat decrypted.txt

## 6. License
This project is open-source and free to use.
