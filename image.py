from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

def encrypt_image(input_image_path, output_image_path, password):
    # Read the image file into memory as bytes
    with open(input_image_path, 'rb') as f:
        plaintext = f.read()

    # Generate a key and salt using PBKDF2 with password and salt
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Generate a random IV
    iv = os.urandom(16)

    # Encrypt the image data using AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Write the encrypted image data to a file
    with open(output_image_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

    print(f"Encryption complete. Encrypted image saved as {output_image_path}")

def decrypt_image(encrypted_image_path, output_image_path, password):
    # Read the encrypted image file into memory as bytes
    with open(encrypted_image_path, 'rb') as f:
        encrypted_data = f.read()

    # Extract salt, IV, and ciphertext
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

    # Derive key using PBKDF2 with password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Decrypt the image data using AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Write the decrypted image data to a file
    with open(output_image_path, 'wb') as f:
        f.write(decrypted_data)

    print(f"Decryption complete. Decrypted image saved as {output_image_path}")

# Example usage:
input_image = 'input_image.jpg'
encrypted_image = 'encrypted_image.bin'
decrypted_image = 'decrypted_image.jpg'
password = 'YourStrongPassword'

# Encrypt the image
encrypt_image(input_image, encrypted_image, password)

# Decrypt the image
decrypt_image(encrypted_image, decrypted_image, password)
