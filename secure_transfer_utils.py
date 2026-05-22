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

LENGTH_HEADER_SIZE = 4
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
    return os.urandom(DES_KEY_SIZE), os.urandom(DES_IV_SIZE)


def validate_des_key_iv(des_key: bytes, iv: bytes) -> None:
    if len(des_key) != DES_KEY_SIZE:
        raise ValueError("DES key phải đúng 8 bytes.")
    if len(iv) != DES_IV_SIZE:
        raise ValueError("IV phải đúng 8 bytes.")


def encrypt_des_cbc(plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    des_key, iv = generate_des_key_iv()
    validate_des_key_iv(des_key, iv)

    cipher = DES.new(des_key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, DES_BLOCK_SIZE))

    # IV được gắn vào đầu ciphertext theo spec lab
    return des_key, iv, iv + ciphertext


def decrypt_des_cbc(des_key: bytes, ciphertext_with_iv: bytes) -> bytes:
    if len(des_key) != DES_KEY_SIZE:
        raise ValueError("DES key sai độ dài.")

    if len(ciphertext_with_iv) <= DES_IV_SIZE:
        raise ValueError("Ciphertext không hợp lệ.")

    iv = ciphertext_with_iv[:DES_IV_SIZE]
    ciphertext = ciphertext_with_iv[DES_IV_SIZE:]

    cipher = DES.new(des_key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES_BLOCK_SIZE)


# =========================
# RSA
# =========================
def generate_rsa_keypair(private_path: str | Path, public_path: str | Path) -> None:
    private_path = Path(private_path)
    public_path = Path(public_path)

    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)

    key = RSA.generate(RSA_KEY_SIZE)

    private_path.write_bytes(key.export_key())
    public_path.write_bytes(key.publickey().export_key())


def load_public_key(path: str | Path):
    return RSA.import_key(Path(path).read_bytes())


def load_private_key(path: str | Path):
    return RSA.import_key(Path(path).read_bytes())


def encrypt_des_key_rsa(des_key: bytes, public_key) -> bytes:
    if len(des_key) != DES_KEY_SIZE:
        raise ValueError("DES key phải đúng 8 bytes.")

    return PKCS1_OAEP.new(public_key).encrypt(des_key)


def decrypt_des_key_rsa(encrypted_key: bytes, private_key) -> bytes:
    key = PKCS1_OAEP.new(private_key).decrypt(encrypted_key)

    if len(key) != DES_KEY_SIZE:
        raise ValueError("Giải mã RSA sai DES key.")

    return key


# =========================
# PACKET HELPERS
# =========================
def pack_u32(data: bytes) -> bytes:
    return struct.pack("!I", len(data))


def unpack_u32(data: bytes) -> int:
    return struct.unpack("!I", data)[0]


def build_secure_packet(
    encrypted_des_key: bytes,
    ciphertext_with_iv: bytes,
    sha256_hash: bytes
) -> bytes:
    if len(sha256_hash) != SHA256_DIGEST_SIZE:
        raise ValueError("SHA-256 sai độ dài.")

    return (
        pack_u32(encrypted_des_key) +
        encrypted_des_key +
        pack_u32(ciphertext_with_iv) +
        ciphertext_with_iv +
        sha256_hash
    )


def parse_secure_packet(packet: bytes) -> Tuple[bytes, bytes, bytes]:
    cursor = 0

    # DES key
    key_len = unpack_u32(packet[cursor:cursor + 4])
    cursor += 4

    enc_key = packet[cursor:cursor + key_len]
    cursor += key_len

    # ciphertext
    cipher_len = unpack_u32(packet[cursor:cursor + 4])
    cursor += 4

    ciphertext = packet[cursor:cursor + cipher_len]
    cursor += cipher_len

    # hash
    sha_hash = packet[cursor:cursor + SHA256_DIGEST_SIZE]
    cursor += SHA256_DIGEST_SIZE

    if cursor != len(packet):
        raise ValueError("Packet bị dư hoặc thiếu dữ liệu.")

    return enc_key, ciphertext, sha_hash


# =========================
# HIGH LEVEL API
# =========================
def build_sender_payload(plaintext: bytes, public_key) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Returns:
    packet, des_key, ciphertext_with_iv, sha256_hash
    """
    sha_hash = sha256_digest(plaintext)

    des_key, _, ciphertext = encrypt_des_cbc(plaintext)
    enc_key = encrypt_des_key_rsa(des_key, public_key)

    packet = build_secure_packet(enc_key, ciphertext, sha_hash)

    return packet, des_key, ciphertext, sha_hash


def open_receiver_payload(packet: bytes, private_key) -> Tuple[bytes, bool]:
    enc_key, ciphertext, sha_hash = parse_secure_packet(packet)

    des_key = decrypt_des_key_rsa(enc_key, private_key)
    plaintext = decrypt_des_cbc(des_key, ciphertext)

    return plaintext, sha256_digest(plaintext) == sha_hash


# =========================
# SOCKET HELPERS
# =========================
def recv_exact(conn, n: int) -> bytes:
    if n <= 0:
        raise ValueError("n phải > 0")

    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket đóng giữa chừng")
        data += chunk

    return data


def recv_secure_packet(conn) -> bytes:
    key_len = unpack_u32(recv_exact(conn, 4))
    enc_key = recv_exact(conn, key_len)

    cipher_len = unpack_u32(recv_exact(conn, 4))
    ciphertext = recv_exact(conn, cipher_len)

    sha_hash = recv_exact(conn, SHA256_DIGEST_SIZE)

    return enc_key, ciphertext, sha_hash
