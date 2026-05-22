import hashlib
import os
import struct
from pathlib import Path
from typing import Tuple

from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

# =========================
# CONSTANTS
# =========================
DES_BLOCK_SIZE = 8
DES_KEY_SIZE = 8
DES_IV_SIZE = 8

RSA_KEY_SIZE = 2048

SHA256_DIGEST_SIZE = 32


# =========================
# HASH
# =========================
def sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# =========================
# DES
# =========================
def generate_des_key_iv() -> Tuple[bytes, bytes]:
    return os.urandom(8), os.urandom(8)


def encrypt_des_cbc(plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    key, iv = generate_des_key_iv()

    cipher = DES.new(key, DES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, 8))

    return key, iv, iv + ct


def decrypt_des_cbc(key: bytes, data: bytes) -> bytes:
    iv = data[:8]
    ct = data[8:]

    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), 8)


# =========================
# RSA
# =========================
def load_public_key(path: str | Path):
    return RSA.import_key(Path(path).read_bytes())


def load_private_key(path: str | Path):
    return RSA.import_key(Path(path).read_bytes())


def encrypt_des_key_rsa(key: bytes, public_key) -> bytes:
    if len(key) != 8:
        raise ValueError("DES key phải 8 bytes")
    return PKCS1_OAEP.new(public_key).encrypt(key)


def decrypt_des_key_rsa(enc: bytes, private_key) -> bytes:
    key = PKCS1_OAEP.new(private_key).decrypt(enc)
    if len(key) != 8:
        raise ValueError("DES key sai")
    return key


# =========================
# PACKET
# =========================
def pack_u32(data: bytes) -> bytes:
    return struct.pack("!I", len(data))


def unpack_u32(data: bytes) -> int:
    return struct.unpack("!I", data)[0]


def build_secure_packet(enc_key: bytes, ciphertext: bytes, hash_val: bytes) -> bytes:
    return (
        pack_u32(enc_key) +
        enc_key +
        pack_u32(ciphertext) +
        ciphertext +
        hash_val
    )


def parse_secure_packet(packet: bytes):
    c = 0

    klen = unpack_u32(packet[c:c+4]); c += 4
    enc_key = packet[c:c+klen]; c += klen

    clen = unpack_u32(packet[c:c+4]); c += 4
    ciphertext = packet[c:c+clen]; c += clen

    hash_val = packet[c:c+32]

    return enc_key, ciphertext, hash_val


# =========================
# HIGH LEVEL
# =========================
def build_sender_payload(plaintext: bytes, public_key):
    hash_val = sha256_digest(plaintext)

    key, iv, ciphertext = encrypt_des_cbc(plaintext)
    enc_key = encrypt_des_key_rsa(key, public_key)

    packet = build_secure_packet(enc_key, ciphertext, hash_val)

    return packet, key, ciphertext, hash_val


def open_receiver_payload(packet: bytes, private_key):
    enc_key, ciphertext, hash_val = parse_secure_packet(packet)

    key = decrypt_des_key_rsa(enc_key, private_key)
    plaintext = decrypt_des_cbc(key, ciphertext)

    return plaintext, sha256_digest(plaintext) == hash_val


# =========================
# SOCKET
# =========================
def recv_exact(conn, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return data


def recv_secure_packet(conn):
    klen = unpack_u32(recv_exact(conn, 4))
    enc_key = recv_exact(conn, klen)

    clen = unpack_u32(recv_exact(conn, 4))
    ciphertext = recv_exact(conn, clen)

    hash_val = recv_exact(conn, 32)

    return enc_key, ciphertext, hash_val
