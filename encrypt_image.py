import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from PIL import Image
import io

# Constants for encryption configuration
SALT_LENGTH = 16        # 16 bytes for salt (128 bits)
IV_LENGTH = 12          # 12 bytes for IV (96 bits), recommended for AES-GCM
KEY_LENGTH = 32         # 32 bytes for AES-256 (256 bits)
PBKDF2_ITERATIONS = 100000  # Recommended number of iterations for PBKDF2

# Mac-specific path to Desktop/target folder
DESKTOP_TARGET_FOLDER = os.path.join(os.path.expanduser("~"), "Desktop", "target")

# Supported image extensions for encryption
SUPPORTED_IMAGE_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.bmp', '.tiff', '.gif')

def generate_key(password: str, salt: bytes) -> bytes:
    """Generate a secure key using PBKDF2HMAC with SHA-256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_image(image_data: bytes, password: str):
    """Encrypt image bytes using AES-GCM."""
    salt = os.urandom(SALT_LENGTH)
    key = generate_key(password, salt)
    iv = os.urandom(IV_LENGTH)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(image_data) + encryptor.finalize()
    return ciphertext, encryptor.tag, iv, salt

def decrypt_image(ciphertext: bytes, tag: bytes, iv: bytes, salt: bytes, password: str) -> bytes:
    """Decrypt image bytes using AES-GCM."""
    key = generate_key(password, salt)
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    try:
        return decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        raise ValueError("Decryption failed. The data may have been tampered with.")

def image_to_bytes(image_path: str) -> bytes:
    """Convert an image file to a byte array."""
    with Image.open(image_path) as img:
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format=img.format)
        return img_byte_arr.getvalue()

def bytes_to_image(image_bytes: bytes, output_path: str, original_format: str):
    """Convert a byte array back into an image file."""
    with Image.open(io.BytesIO(image_bytes)) as img:
        img.save(output_path, format=original_format)

def get_secure_password() -> str:
    """Retrieve the encryption password securely from environment variables or prompt."""
    import getpass
    password = os.getenv("IMAGE_ENCRYPTION_PASSWORD")
    if not password:
        password = getpass.getpass(prompt="Enter encryption password: ")
    return password

def encrypt_all_images_in_folder(password: str):
    """Encrypt all supported image files in the target folder."""
    for filename in os.listdir(DESKTOP_TARGET_FOLDER):
        if filename.lower().endswith(SUPPORTED_IMAGE_EXTENSIONS):
            input_image_path = os.path.join(DESKTOP_TARGET_FOLDER, filename)
            encrypted_file_path = os.path.join(DESKTOP_TARGET_FOLDER, f"{filename}.dat")

            try:
                image_data = image_to_bytes(input_image_path)
                encrypted_data, tag, iv, salt = encrypt_image(image_data, password)

                # Save encrypted data to a .dat file
                with open(encrypted_file_path, "wb") as f:
                    f.write(salt + iv + tag + encrypted_data)
                
                print(f"Encrypted {filename} successfully.")
            except Exception as e:
                print(f"Failed to encrypt {filename}: {e}")

def decrypt_all_dat_files_in_folder(password: str):
    """Decrypt all .dat files in the target folder to their original images."""
    for filename in os.listdir(DESKTOP_TARGET_FOLDER):
        if filename.lower().endswith('.dat'):
            encrypted_file_path = os.path.join(DESKTOP_TARGET_FOLDER, filename)
            decrypted_image_path = os.path.join(DESKTOP_TARGET_FOLDER, filename.replace('.dat', ''))

            try:
                with open(encrypted_file_path, "rb") as f:
                    encrypted_file_data = f.read()

                # Extract salt, IV, tag, and ciphertext
                salt_from_file = encrypted_file_data[:SALT_LENGTH]
                iv_from_file = encrypted_file_data[SALT_LENGTH:SALT_LENGTH + IV_LENGTH]
                tag_from_file = encrypted_file_data[SALT_LENGTH + IV_LENGTH:SALT_LENGTH + IV_LENGTH + 16]
                ciphertext_from_file = encrypted_file_data[SALT_LENGTH + IV_LENGTH + 16:]

                # Decrypt the image
                decrypted_data = decrypt_image(ciphertext_from_file, tag_from_file, iv_from_file, salt_from_file, password)

                # Get the original image format from the decrypted data
                with Image.open(io.BytesIO(decrypted_data)) as img:
                    original_format = img.format

                # Save decrypted image
                bytes_to_image(decrypted_data, decrypted_image_path, original_format)
                print(f"Decrypted {filename} successfully.")
            except ValueError as ve:
                print(f"Decryption failed for {filename}: {ve}")
            except Exception as e:
                print(f"Failed to decrypt {filename}: {e}")

# Main workflow
if __name__ == "__main__":
    if not os.path.exists(DESKTOP_TARGET_FOLDER):
        os.makedirs(DESKTOP_TARGET_FOLDER)

    # Ask the user if they want to encrypt or decrypt
    choice = input("Do you want to (e)ncrypt or (d)ecrypt? ").strip().lower()

    password = get_secure_password()

    if choice == 'e':
        print("Starting encryption of all images in the target folder...")
        encrypt_all_images_in_folder(password)
    elif choice == 'd':
        print("Starting decryption of all .dat files in the target folder...")
        decrypt_all_dat_files_in_folder(password)
    else:
        print("Invalid choice. Please choose either 'e' for encryption or 'd' for decryption.")
