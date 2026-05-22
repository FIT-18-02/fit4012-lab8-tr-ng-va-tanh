import struct
import hashlib
import os

from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


# =========================================================
# CONSTANTS
# =========================================================

DES_KEY_SIZE = 8
DES_BLOCK_SIZE = 8
DES_IV_SIZE = 8
SHA256_DIGEST_SIZE = 32


# =========================================================
# PKCS7 PADDING
# =========================================================

def pkcs7_pad(data: bytes) -> bytes:
    pad_len = DES_BLOCK_SIZE - (len(data) % DES_BLOCK_SIZE)
    padding = bytes([pad_len] * pad_len)
    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Empty data")
    
    pad_len = data[-1]
    if pad_len < 1 or pad_len > DES_BLOCK_SIZE or data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS7 padding")
    
    return data[:-pad_len]


# =========================================================
# SHA256
# =========================================================

def sha256_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# =========================================================
# DES-CBC
# =========================================================

def generate_des_key() -> bytes:
    return get_random_bytes(DES_KEY_SIZE)


def generate_iv() -> bytes:
    return get_random_bytes(DES_IV_SIZE)


def des_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt using DES-CBC → return iv + ciphertext"""
    if len(key) != DES_KEY_SIZE:
        raise ValueError("DES key must be 8 bytes")

    iv = generate_iv()
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded = pkcs7_pad(plaintext)
    ciphertext = cipher.encrypt(padded)
    return iv + ciphertext


def des_decrypt(key: bytes, ciphertext_with_iv: bytes) -> bytes:
    """Decrypt DES-CBC, input = iv(8) + ciphertext"""
    if len(key) != DES_KEY_SIZE:
        raise ValueError("DES key must be 8 bytes")
    if len(ciphertext_with_iv) < DES_IV_SIZE:
        raise ValueError("Ciphertext too short")

    iv = ciphertext_with_iv[:DES_IV_SIZE]
    ciphertext = ciphertext_with_iv[DES_IV_SIZE:]

    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    return pkcs7_unpad(padded_plaintext)


# =========================================================
# RSA-OAEP
# =========================================================

def load_public_key(path: str):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def load_private_key(path: str):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def rsa_encrypt(public_key, data: bytes) -> bytes:
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(data)


def rsa_decrypt(private_key, encrypted_data: bytes) -> bytes:
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_data)


# =========================================================
# PACKET BUILD / PARSE (THEO ĐÚNG PROTOCOL LAB 8)
# =========================================================

def pack_u32(value: int) -> bytes:
    return struct.pack("!I", value)


def unpack_u32(data: bytes) -> int:
    return struct.unpack("!I", data)[0]


def build_packet(encrypted_des_key: bytes, ciphertext: bytes, sha256_digest: bytes) -> bytes:
    """Build packet theo đúng format Lab 8"""
    packet = b""
    packet += pack_u32(len(encrypted_des_key))   # len_key
    packet += encrypted_des_key                   # encrypted DES key
    packet += pack_u32(len(ciphertext))           # len_cipher
    packet += ciphertext                          # IV(8) + ciphertext
    packet += sha256_digest                       # SHA-256 (32 bytes)
    return packet


def parse_packet(packet: bytes):
    """Parse packet theo protocol Lab 8"""
    offset = 0

    len_key = unpack_u32(packet[offset:offset + 4])
    offset += 4
    encrypted_key = packet[offset:offset + len_key]
    offset += len_key

    len_cipher = unpack_u32(packet[offset:offset + 4])
    offset += 4
    ciphertext = packet[offset:offset + len_cipher]
    offset += len_cipher

    sha256_digest = packet[offset:offset + SHA256_DIGEST_SIZE]

    return encrypted_key, ciphertext, sha256_digest


# =========================================================
# SOCKET HELPERS
# =========================================================

def recv_exact(sock, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Socket connection closed unexpectedly")
        data += chunk
    return data


def send_packet(sock, packet: bytes):
    """Gửi trực tiếp packet (KHÔNG thêm length prefix) - đúng protocol Lab 8"""
    sock.sendall(packet)


def receive_packet(sock) -> bytes:
    """Nhận packet theo cấu trúc Lab 8 (không có outer length prefix)"""
    # Đọc len_key
    raw_len_key = recv_exact(sock, 4)
    len_key = unpack_u32(raw_len_key)
    enc_key = recv_exact(sock, len_key)

    # Đọc len_cipher
    raw_len_cipher = recv_exact(sock, 4)
    len_cipher = unpack_u32(raw_len_cipher)
    ciphertext = recv_exact(sock, len_cipher)

    # Đọc hash
    sha_hash = recv_exact(sock, SHA256_DIGEST_SIZE)

    return raw_len_key + enc_key + raw_len_cipher + ciphertext + sha_hash


# =========================================================
# ALIASES (Backward Compatibility)
# =========================================================

des_encrypt_cbc = des_encrypt
des_decrypt_cbc = des_decrypt
sha256_digest = sha256_hash
encrypt_des_key_rsa = rsa_encrypt
decrypt_des_key_rsa = rsa_decrypt
build_secure_packet = build_packet
parse_secure_packet = parse_packet
