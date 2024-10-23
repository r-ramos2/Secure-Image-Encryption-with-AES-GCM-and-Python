# 🔐 Secure Image Encryption with AES-GCM and Python

## Table of Contents
1. [Introduction](#introduction)
2. [Features and Benefits](#features-and-benefits)
3. [Project Details](#project-details)
   - [Security Considerations](#security-considerations)
4. [How it Works](#how-it-works)
5. [Usage Instructions](#usage-instructions)
6. [Cryptographic Details](#cryptographic-details)
7. [Best Practices for Secure Image Encryption](#best-practices-for-secure-image-encryption)
8. [Conclusion](#conclusion)
9. [Resources](#resources)

---

## Introduction

In today’s world, protecting sensitive data is paramount, and images often contain valuable or confidential information. This project demonstrates how to securely encrypt and decrypt images using the **Advanced Encryption Standard (AES)** in **GCM (Galois/Counter Mode)** with Python. The project showcases modern cryptographic principles, secure coding practices, and emphasizes the importance of both data confidentiality and integrity.

The methods used in this project not only protect image data from unauthorized access but also ensure that any tampering with the data can be detected. The goal is to implement a robust solution that follows cybersecurity best practices, demonstrating a deep understanding of encryption methods suitable for real-world applications.

---

## 🚀 Features and Benefits

- **AES-256 Encryption**: Employs AES-GCM for strong encryption and built-in data integrity checks, ensuring data is safe from unauthorized access or tampering.
- **Password-Based Key Derivation**: Utilizes `PBKDF2HMAC` with salt and multiple iterations to derive cryptographic keys securely from passwords, adding an extra layer of protection.
- **Randomized Salt and IV**: Secure generation of salt and initialization vector (IV) for each encryption session ensures that identical images encrypted with the same password result in different ciphertexts.
- **Image Authenticity Validation**: The use of AES-GCM ensures that the ciphertext includes an authentication tag to detect any tampering during storage or transmission.
- **Scalability and Flexibility**: Suitable for a variety of use cases, from personal privacy applications to secure image transmission in enterprise-level cybersecurity protocols.
- **Cross-Platform Compatibility**: This solution works on any system that supports Python, making it versatile for development, testing, and deployment across different environments.

---

## 🧑‍💻 Project Details

This project securely encrypts and decrypts images using Python’s `cryptography` library. It follows best practices in cryptography by combining symmetric encryption (AES) with secure key derivation techniques and image processing through the Pillow library.

### Key Steps in the Encryption and Decryption Process

1. **Key Derivation**: A strong key is derived from a password using the PBKDF2-HMAC algorithm with SHA-256 as the hashing function. A randomly generated salt and 100,000 iterations ensure the key is resistant to brute-force attacks.
2. **AES-GCM Encryption**: AES-GCM (Galois/Counter Mode) is used to encrypt the image bytes. This mode provides both encryption and authentication, ensuring that any unauthorized modifications to the ciphertext can be detected.
3. **Image Handling**: Images are converted to bytes for encryption and then back to image format after decryption using the Pillow (`PIL`) library.
4. **Metadata Storage**: The encrypted output includes the ciphertext, the IV, salt, and the authentication tag, all of which are required to safely decrypt the image.

---

### Security Considerations

- **Password Security**: It is crucial to use a strong password for the key derivation function to protect the encrypted images. Passwords should be complex and stored securely.
- **Salt and IV Randomization**: Every encryption session generates a new random salt and IV, ensuring that the same image encrypted with the same password results in different ciphertexts, preventing replay attacks.
- **Authenticated Encryption**: AES-GCM ensures that the data is authenticated, meaning that tampering with the ciphertext will cause decryption to fail.
- **Code Hygiene**: Sensitive data such as passwords should not be hardcoded in the script. Use environment variables or a secure storage method to handle sensitive information.

By following these principles, this project demonstrates a practical understanding of secure encryption and secure coding practices, essential for a role in cybersecurity.

---

## 📚 How it Works

The code structure is divided into key functions that handle each aspect of the encryption process:

- **`generate_key()`**: Securely derives a 256-bit AES key from a password using `PBKDF2HMAC` with a random salt and multiple iterations for added security.
- **`encrypt_image()`**: Converts the image into bytes, generates a random IV, encrypts the image using AES-GCM, and returns the ciphertext, authentication tag, IV, and salt.
- **`decrypt_image()`**: Takes the encrypted image data, IV, salt, and authentication tag, regenerates the key, and decrypts the image bytes, ensuring the data’s integrity.
- **`image_to_bytes()`**: Converts an image file into a byte stream, making it ready for encryption.
- **`bytes_to_image()`**: Converts the decrypted byte stream back into an image file, restoring the original data.

---

## 💡 Usage Instructions

1. **Install Dependencies**: Ensure the required Python packages are installed:

   ```bash
   pip install cryptography pillow
   ```

2. **Encrypt an Image**:
   - Convert the image to bytes, encrypt the byte stream, and securely store the output.

3. **Decrypt an Image**:
   - Use the password, salt, IV, and tag to reverse the process and recover the original image.

Example usage in Python:

```python
password = "strong_password_123"
image_path = "example.png"

# Convert image to bytes
image_data = image_to_bytes(image_path)

# Encrypt the image
encrypted_data, tag, iv, salt = encrypt_image(image_data, password)

# Decrypt the image
decrypted_data = decrypt_image(encrypted_data, tag, iv, salt, password)

# Save the decrypted image
bytes_to_image(decrypted_data, "decrypted_image.png")

print("Image encryption and decryption completed successfully!")
```

---

## 🔐 Cryptographic Details

### Key Derivation
- **PBKDF2HMAC**: A key derivation function that applies SHA-256 hashing and 100,000 iterations to derive a secure 256-bit key from the password. This method adds computational complexity to deter brute-force attacks.

### AES-GCM Encryption
- **AES-256 GCM**: A symmetric encryption algorithm used for its efficiency and strong security guarantees. GCM mode not only encrypts the data but also generates an authentication tag, ensuring the integrity of the ciphertext.

### Security Improvements
- **Authenticated Encryption**: By using AES-GCM, this project ensures that unauthorized modifications to the encrypted image (ciphertext) can be detected during decryption, providing integrity in addition to confidentiality.
- **Secure Randomness**: Both the salt and IV are generated using `os.urandom()`, ensuring strong entropy and making the encryption process resistant to attacks that exploit predictable randomness.

---

## 🛡️ Best Practices for Secure Image Encryption

- **Use Secure Passwords**: Always use strong, complex passwords for deriving encryption keys.
- **Avoid Hardcoding Secrets**: Never store sensitive information like passwords directly in the source code.
- **Regularly Update Libraries**: Always use the latest versions of security libraries (e.g., `cryptography`) to ensure the code is free from known vulnerabilities.
- **Encrypt Data at Rest and in Transit**: Ensure that both stored and transmitted data is encrypted to maintain security at all times.
- **Monitor and Audit**: In real-world implementations, monitor for any anomalies or potential breaches and perform regular audits of encryption systems.

---

## 🔚 Conclusion

This project showcases a robust and secure method for encrypting and decrypting image data, adhering to industry-standard cryptographic practices. By employing **AES-GCM encryption**, key derivation through `PBKDF2HMAC`, and secure handling of sensitive data, it provides a practical example of secure coding in the field of cybersecurity.

---

## 🛠️ Resources
- [NIST SP 800-63B Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [OWASP Password Policy](https://owasp.org/www-project-cheat-sheets/cheatsheets/Password_Policy_Cheat_Sheet.html)
- [Python Official Documentation](https://docs.python.org/3/)
- [Cryptography Library Documentation](https://cryptography.io/en/latest/)
- [AES Encryption Explained](https://www.khanacademy.org/computing/computer-science/cryptography/cryptography-basics/a/aes)
