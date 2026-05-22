import os
import socket
import struct
import hashlib
from typing import Tuple

from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


DES_KEY_SIZE = 8
DES_BLOCK_SIZE = 8
SHA256_DIGEST_SIZE = 32
LENGTH_HEADER_SIZE = 4


# =========================================================
# DES-CBC
# =========================================================

def generate_des_key_iv() -> Tuple[bytes, bytes]:
    """
    Generate random DES key and IV.
    """
    key = get_random_bytes(DES_KEY_SIZE)
    iv = get_random_bytes(DES_BLOCK_SIZE)
    return key, iv


def encrypt_des_cbc(plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext using DES-CBC with PKCS#7 padding.

    Returns:
        key
        iv
        ciphertext
    """
    key, iv = generate_des_key_iv()

    cipher = DES.new(key, DES.MODE_CBC, iv)

    padded = pad(plaintext, DES_BLOCK_SIZE)

    ciphertext = cipher.encrypt(padded)

    return key, iv, ciphertext


def decrypt_des_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt DES-CBC ciphertext and remove padding.
    """
    cipher = DES.new(key, DES.MODE_CBC, iv)

    padded_plaintext = cipher.decrypt(ciphertext)

    plaintext = unpad(padded_plaintext, DES_BLOCK_SIZE)

    return plaintext


# =========================================================
# SHA-256
# =========================================================

def compute_sha256(data: bytes) -> bytes:
    """
    Compute SHA-256 digest.
    """
    return hashlib.sha256(data).digest()


def verify_sha256(data: bytes, expected_hash: bytes) -> bool:
    """
    Verify SHA-256 digest.
    """
    actual_hash = compute_sha256(data)

    return actual_hash == expected_hash


# =========================================================
# RSA-OAEP
# =========================================================

def load_public_key(path: str):
    """
    Load RSA public key from PEM file.
    """
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def load_private_key(path: str):
    """
    Load RSA private key from PEM file.
    """
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def rsa_encrypt_des_key(des_key: bytes, public_key) -> bytes:
    """
    Encrypt DES key using RSA-OAEP.
    """
    cipher_rsa = PKCS1_OAEP.new(public_key)

    encrypted_key = cipher_rsa.encrypt(des_key)

    return encrypted_key


def rsa_decrypt_des_key(encrypted_key: bytes, private_key) -> bytes:
    """
    Decrypt DES key using RSA-OAEP.
    """
    cipher_rsa = PKCS1_OAEP.new(private_key)

    des_key = cipher_rsa.decrypt(encrypted_key)

    return des_key


# =========================================================
# PACKET
# =========================================================

def build_packet(
    encrypted_des_key: bytes,
    ciphertext_with_iv: bytes,
    sha256_hash: bytes
) -> bytes:
    """
    Build Lab 8 packet format.

    Format:
        [len_key: 4 bytes]
        [encrypted_des_key]
        [len_cipher: 4 bytes]
        [ciphertext_with_iv]
        [sha256_hash: 32 bytes]
    """

    len_key = len(encrypted_des_key)
    len_cipher = len(ciphertext_with_iv)

    packet = b""

    packet += struct.pack("!I", len_key)
    packet += encrypted_des_key

    packet += struct.pack("!I", len_cipher)
    packet += ciphertext_with_iv

    packet += sha256_hash

    return packet


def parse_packet(packet: bytes):
    """
    Parse Lab 8 packet.
    """

    offset = 0

    # Read encrypted key length
    len_key = struct.unpack(
        "!I",
        packet[offset:offset + LENGTH_HEADER_SIZE]
    )[0]

    offset += LENGTH_HEADER_SIZE

    # Read encrypted DES key
    encrypted_des_key = packet[offset:offset + len_key]

    offset += len_key

    # Read ciphertext length
    len_cipher = struct.unpack(
        "!I",
        packet[offset:offset + LENGTH_HEADER_SIZE]
    )[0]

    offset += LENGTH_HEADER_SIZE

    # Read ciphertext
    ciphertext_with_iv = packet[offset:offset + len_cipher]

    offset += len_cipher

    # Read SHA256 hash
    sha256_hash = packet[offset:offset + SHA256_DIGEST_SIZE]

    return (
        encrypted_des_key,
        ciphertext_with_iv,
        sha256_hash
    )


# =========================================================
# SOCKET HELPERS
# =========================================================

def recv_exact(sock: socket.socket, size: int) -> bytes:
    """
    Receive exactly 'size' bytes from socket.
    """

    data = b""

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Socket connection closed")

        data += chunk

    return data


def send_packet(sock: socket.socket, packet: bytes):
    """
    Send packet through socket.
    """
    sock.sendall(packet)


def receive_packet(sock: socket.socket) -> bytes:
    """
    Receive Lab 8 packet from socket.
    """

    # Read key length
    raw_len_key = recv_exact(sock, LENGTH_HEADER_SIZE)

    len_key = struct.unpack("!I", raw_len_key)[0]

    encrypted_des_key = recv_exact(sock, len_key)

    # Read ciphertext length
    raw_len_cipher = recv_exact(sock, LENGTH_HEADER_SIZE)

    len_cipher = struct.unpack("!I", raw_len_cipher)[0]

    ciphertext_with_iv = recv_exact(sock, len_cipher)

    # Read SHA256 hash
    sha256_hash = recv_exact(sock, SHA256_DIGEST_SIZE)

    packet = (
        raw_len_key
        + encrypted_des_key
        + raw_len_cipher
        + ciphertext_with_iv
        + sha256_hash
    )

    return packet
