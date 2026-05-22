import struct
import hashlib

from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# DES block size = 8 bytes
BLOCK_SIZE = 8


# =========================
# PKCS7 PADDING
# =========================

def pkcs7_pad(data: bytes) -> bytes:
    """
    Add PKCS7 padding so data length becomes multiple of 8.
    """

    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)

    padding = bytes([pad_len] * pad_len)

    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS7 padding.
    """

    if len(data) == 0:
        raise ValueError("Empty data")

    pad_len = data[-1]

    # padding length must be between 1 and BLOCK_SIZE
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")

    # verify padding bytes
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes")

    return data[:-pad_len]


# =========================
# DES CBC ENCRYPT / DECRYPT
# =========================

def generate_des_key() -> bytes:
    """
    Generate random 8-byte DES key.
    """

    return get_random_bytes(8)


def des_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using DES-CBC.

    Return:
        IV + ciphertext
    """

    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")

    iv = get_random_bytes(8)

    cipher = DES.new(key, DES.MODE_CBC, iv)

    padded = pkcs7_pad(plaintext)

    ciphertext = cipher.encrypt(padded)

    return iv + ciphertext


def des_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt DES-CBC ciphertext.

    Input format:
        IV + encrypted_data
    """

    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")

    if len(ciphertext) < 8:
        raise ValueError("Ciphertext too short")

    iv = ciphertext[:8]

    encrypted_data = ciphertext[8:]

    cipher = DES.new(key, DES.MODE_CBC, iv)

    padded_plaintext = cipher.decrypt(encrypted_data)

    plaintext = pkcs7_unpad(padded_plaintext)

    return plaintext


# =========================
# SHA256
# =========================

def sha256_hash(data: bytes) -> bytes:
    """
    Return SHA-256 digest (32 bytes).
    """

    return hashlib.sha256(data).digest()


# =========================
# RSA KEY LOADING
# =========================

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


# =========================
# RSA OAEP
# =========================

def rsa_encrypt(public_key, data: bytes) -> bytes:
    """
    Encrypt data using RSA-OAEP.
    """

    cipher = PKCS1_OAEP.new(public_key)

    return cipher.encrypt(data)


def rsa_decrypt(private_key, encrypted_data: bytes) -> bytes:
    """
    Decrypt RSA-OAEP encrypted data.
    """

    cipher = PKCS1_OAEP.new(private_key)

    return cipher.decrypt(encrypted_data)


# =========================
# PACKET HELPERS
# =========================

def build_packet(
    encrypted_des_key: bytes,
    ciphertext: bytes,
    sha256_digest: bytes
) -> bytes:
    """
    Build Lab 8 packet format:

    [len_key: 4 bytes]
    [encrypted_des_key]
    [len_cipher: 4 bytes]
    [ciphertext]
    [sha256_hash: 32 bytes]
    """

    packet = b""

    # encrypted DES key length
    packet += struct.pack("!I", len(encrypted_des_key))

    # encrypted DES key
    packet += encrypted_des_key

    # ciphertext length
    packet += struct.pack("!I", len(ciphertext))

    # ciphertext
    packet += ciphertext

    # SHA256 hash
    packet += sha256_digest

    return packet


def parse_packet(packet: bytes):
    """
    Parse packet and return:

    (
        encrypted_des_key,
        ciphertext,
        sha256_digest
    )
    """

    offset = 0

    # read encrypted key length
    len_key = struct.unpack(
        "!I",
        packet[offset:offset + 4]
    )[0]

    offset += 4

    # read encrypted DES key
    encrypted_key = packet[offset:offset + len_key]

    offset += len_key

    # read ciphertext length
    len_cipher = struct.unpack(
        "!I",
        packet[offset:offset + 4]
    )[0]

    offset += 4

    # read ciphertext
    ciphertext = packet[offset:offset + len_cipher]

    offset += len_cipher

    # read hash
    sha256_digest = packet[offset:offset + 32]

    return (
        encrypted_key,
        ciphertext,
        sha256_digest
    )


# =========================
# SOCKET HELPERS
# =========================

def recv_exact(sock, size: int) -> bytes:
    """
    Receive exactly `size` bytes from socket.
    """

    data = b""

    while len(data) < size:

        chunk = sock.recv(size - len(data))

        if not chunk:
            raise ConnectionError(
                "Socket connection closed"
            )

        data += chunk

    return data
