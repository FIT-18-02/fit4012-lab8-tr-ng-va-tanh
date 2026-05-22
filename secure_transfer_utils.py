import hashlib
import os
import struct
from pathlib import Path
from typing import Tuple

from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad


# =========================================================
# CONSTANTS
# =========================================================

DES_KEY_SIZE = 8
DES_BLOCK_SIZE = 8
DES_IV_SIZE = 8

SHA256_DIGEST_SIZE = 32

RSA_KEY_SIZE = 2048


# =========================================================
# HASH HELPERS
# =========================================================

def sha256_digest(data: bytes) -> bytes:
    """
    Compute SHA-256 digest
    """
    return hashlib.sha256(data).digest()


# =========================================================
# DES HELPERS
# =========================================================

def generate_des_key() -> bytes:
    """
    Generate random 8-byte DES key
    """
    return os.urandom(DES_KEY_SIZE)


def generate_iv() -> bytes:
    """
    Generate random 8-byte IV
    """
    return os.urandom(DES_IV_SIZE)


def generate_des_key_iv() -> Tuple[bytes, bytes]:
    """
    Generate DES key + IV
    """
    return generate_des_key(), generate_iv()


def pkcs7_pad(data: bytes) -> bytes:
    """
    Apply PKCS#7 padding
    """
    return pad(data, DES_BLOCK_SIZE)


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding
    """
    return unpad(data, DES_BLOCK_SIZE)


def des_encrypt_cbc(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using DES-CBC

    Returns:
        iv + ciphertext
    """

    iv = generate_iv()

    cipher = DES.new(key, DES.MODE_CBC, iv)

    padded = pkcs7_pad(plaintext)

    ciphertext = cipher.encrypt(padded)

    return iv + ciphertext


def des_decrypt_cbc(key: bytes, ciphertext_with_iv: bytes) -> bytes:
    """
    Decrypt DES-CBC ciphertext

    Input:
        iv + ciphertext
    """

    iv = ciphertext_with_iv[:DES_IV_SIZE]
    ciphertext = ciphertext_with_iv[DES_IV_SIZE:]

    cipher = DES.new(key, DES.MODE_CBC, iv)

    padded_plaintext = cipher.decrypt(ciphertext)

    plaintext = pkcs7_unpad(padded_plaintext)

    return plaintext


def encrypt_des_cbc(plaintext: bytes):
    """
    High-level DES encrypt helper

    Returns:
        key, iv, iv+ciphertext
    """

    key, iv = generate_des_key_iv()

    cipher = DES.new(key, DES.MODE_CBC, iv)

    padded = pkcs7_pad(plaintext)

    ciphertext = cipher.encrypt(padded)

    return key, iv, iv + ciphertext


def decrypt_des_cbc(key: bytes, data: bytes) -> bytes:
    """
    High-level DES decrypt helper
    """

    return des_decrypt_cbc(key, data)


# =========================================================
# RSA HELPERS
# =========================================================

def load_public_key(path: str | Path):
    """
    Load RSA public key from PEM file
    """

    return RSA.import_key(Path(path).read_bytes())


def load_private_key(path: str | Path):
    """
    Load RSA private key from PEM file
    """

    return RSA.import_key(Path(path).read_bytes())


def rsa_encrypt_key(des_key: bytes, public_key) -> bytes:
    """
    Encrypt DES key using RSA-OAEP
    """

    if len(des_key) != DES_KEY_SIZE:
        raise ValueError("DES key must be 8 bytes")

    cipher_rsa = PKCS1_OAEP.new(public_key)

    encrypted_key = cipher_rsa.encrypt(des_key)

    return encrypted_key


def rsa_decrypt_key(encrypted_key: bytes, private_key) -> bytes:
    """
    Decrypt DES key using RSA-OAEP
    """

    cipher_rsa = PKCS1_OAEP.new(private_key)

    des_key = cipher_rsa.decrypt(encrypted_key)

    if len(des_key) != DES_KEY_SIZE:
        raise ValueError("Invalid DES key length")

    return des_key


# Backward-compatible aliases
encrypt_des_key_rsa = rsa_encrypt_key
decrypt_des_key_rsa = rsa_decrypt_key


# =========================================================
# PACKET HELPERS
# =========================================================

def pack_u32(value: int) -> bytes:
    """
    Pack unsigned int (4 bytes, network byte order)
    """

    return struct.pack("!I", value)


def unpack_u32(data: bytes) -> int:
    """
    Unpack unsigned int
    """

    return struct.unpack("!I", data)[0]


def build_packet(
    encrypted_des_key: bytes,
    ciphertext: bytes,
    sha256_hash: bytes
) -> bytes:
    """
    Build packet format:

    [len_key: 4 bytes]
    [encrypted_des_key]
    [len_cipher: 4 bytes]
    [ciphertext]
    [sha256_hash: 32 bytes]
    """

    packet = b""

    packet += pack_u32(len(encrypted_des_key))
    packet += encrypted_des_key

    packet += pack_u32(len(ciphertext))
    packet += ciphertext

    packet += sha256_hash

    return packet


def parse_packet(packet: bytes):
    """
    Parse secure packet
    """

    cursor = 0

    # key length
    key_len = unpack_u32(packet[cursor:cursor + 4])
    cursor += 4

    # encrypted key
    encrypted_key = packet[cursor:cursor + key_len]
    cursor += key_len

    # ciphertext length
    cipher_len = unpack_u32(packet[cursor:cursor + 4])
    cursor += 4

    # ciphertext
    ciphertext = packet[cursor:cursor + cipher_len]
    cursor += cipher_len

    # hash
    hash_value = packet[cursor:cursor + SHA256_DIGEST_SIZE]

    return encrypted_key, ciphertext, hash_value


# Backward-compatible aliases
build_secure_packet = build_packet
parse_secure_packet = parse_packet


# =========================================================
# HIGH LEVEL HELPERS
# =========================================================

def build_sender_payload(plaintext: bytes, public_key):
    """
    Build sender payload
    """

    hash_value = sha256_digest(plaintext)

    key, iv, ciphertext = encrypt_des_cbc(plaintext)

    encrypted_key = rsa_encrypt_key(key, public_key)

    packet = build_packet(
        encrypted_key,
        ciphertext,
        hash_value
    )

    return packet, key, ciphertext, hash_value


def open_receiver_payload(packet: bytes, private_key):
    """
    Open and verify received payload
    """

    encrypted_key, ciphertext, hash_value = parse_packet(packet)

    key = rsa_decrypt_key(encrypted_key, private_key)

    plaintext = des_decrypt_cbc(key, ciphertext)

    valid = sha256_digest(plaintext) == hash_value

    return plaintext, valid


# =========================================================
# SOCKET HELPERS
# =========================================================

def recv_exact(sock, num_bytes: int) -> bytes:
    """
    Receive exactly num_bytes from socket
    """

    data = b""

    while len(data) < num_bytes:

        chunk = sock.recv(num_bytes - len(data))

        if not chunk:
            raise ConnectionError("Socket connection closed")

        data += chunk

    return data


def send_packet(sock, packet: bytes):
    """
    Send packet with length prefix

    Format:
        [packet_length: 4 bytes]
        [packet]
    """

    packet_length = pack_u32(len(packet))

    sock.sendall(packet_length + packet)


def receive_packet(sock) -> bytes:
    """
    Receive packet with length prefix
    """

    raw_length = recv_exact(sock, 4)

    packet_length = unpack_u32(raw_length)

    packet = recv_exact(sock, packet_length)

    return packet


def recv_secure_packet(sock):
    """
    Receive packet and parse immediately
    """

    packet = receive_packet(sock)

    return parse_packet(packet)
