import struct
import hashlib

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
    """
    Apply PKCS7 padding for DES block size.
    """

    pad_len = DES_BLOCK_SIZE - (len(data) % DES_BLOCK_SIZE)

    padding = bytes([pad_len] * pad_len)

    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS7 padding.
    """

    if not data:
        raise ValueError("Empty data")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > DES_BLOCK_SIZE:
        raise ValueError("Invalid padding")

    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes")

    return data[:-pad_len]


# =========================================================
# SHA256
# =========================================================

def sha256_hash(data: bytes) -> bytes:
    """
    Compute SHA-256 digest.
    """

    return hashlib.sha256(data).digest()


# =========================================================
# DES HELPERS
# =========================================================

def generate_des_key() -> bytes:
    """
    Generate random 8-byte DES key.
    """

    return get_random_bytes(DES_KEY_SIZE)


def generate_iv() -> bytes:
    """
    Generate random 8-byte IV.
    """

    return get_random_bytes(DES_IV_SIZE)


def des_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using DES-CBC.

    Returns:
        iv + ciphertext
    """

    if len(key) != DES_KEY_SIZE:
        raise ValueError("DES key must be 8 bytes")

    iv = generate_iv()

    cipher = DES.new(key, DES.MODE_CBC, iv)

    padded = pkcs7_pad(plaintext)

    ciphertext = cipher.encrypt(padded)

    return iv + ciphertext


def des_decrypt(key: bytes, ciphertext_with_iv: bytes) -> bytes:
    """
    Decrypt DES-CBC ciphertext.

    Input format:
        iv + ciphertext
    """

    if len(key) != DES_KEY_SIZE:
        raise ValueError("DES key must be 8 bytes")

    if len(ciphertext_with_iv) < DES_IV_SIZE:
        raise ValueError("Ciphertext too short")

    iv = ciphertext_with_iv[:DES_IV_SIZE]

    ciphertext = ciphertext_with_iv[DES_IV_SIZE:]

    cipher = DES.new(key, DES.MODE_CBC, iv)

    padded_plaintext = cipher.decrypt(ciphertext)

    plaintext = pkcs7_unpad(padded_plaintext)

    return plaintext


# =========================================================
# RSA HELPERS
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


def rsa_encrypt(public_key, data: bytes) -> bytes:
    """
    Encrypt data using RSA-OAEP.
    """

    cipher_rsa = PKCS1_OAEP.new(public_key)

    return cipher_rsa.encrypt(data)


def rsa_decrypt(private_key, encrypted_data: bytes) -> bytes:
    """
    Decrypt RSA-OAEP encrypted data.
    """

    cipher_rsa = PKCS1_OAEP.new(private_key)

    return cipher_rsa.decrypt(encrypted_data)


# =========================================================
# PACKET HELPERS
# =========================================================

def pack_u32(value: int) -> bytes:
    """
    Pack unsigned int to 4 bytes network byte order.
    """

    return struct.pack("!I", value)


def unpack_u32(data: bytes) -> int:
    """
    Unpack 4-byte unsigned int.
    """

    return struct.unpack("!I", data)[0]


def build_packet(
    encrypted_des_key: bytes,
    ciphertext: bytes,
    sha256_digest: bytes
) -> bytes:
    """
    Build Lab 8 packet format.

    Format:
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

    packet += sha256_digest

    return packet


def parse_packet(packet: bytes):
    """
    Parse packet.

    Returns:
        encrypted_des_key,
        ciphertext,
        sha256_digest
    """

    offset = 0

    # encrypted key length
    len_key = unpack_u32(packet[offset:offset + 4])

    offset += 4

    # encrypted key
    encrypted_key = packet[offset:offset + len_key]

    offset += len_key

    # ciphertext length
    len_cipher = unpack_u32(packet[offset:offset + 4])

    offset += 4

    # ciphertext
    ciphertext = packet[offset:offset + len_cipher]

    offset += len_cipher

    # SHA256 hash
    sha256_digest = packet[offset:offset + SHA256_DIGEST_SIZE]

    return (
        encrypted_key,
        ciphertext,
        sha256_digest
    )


# =========================================================
# SOCKET HELPERS
# =========================================================

def recv_exact(sock, size: int) -> bytes:
    """
    Receive exactly size bytes from socket.
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


def send_packet(sock, packet: bytes):
    """
    Send packet with length prefix.

    Format:
        [packet_length: 4 bytes]
        [packet]
    """

    packet_length = pack_u32(len(packet))

    sock.sendall(packet_length + packet)


def receive_packet(sock) -> bytes:
    """
    Receive packet with length prefix.
    """

    raw_length = recv_exact(sock, 4)

    packet_length = unpack_u32(raw_length)

    packet = recv_exact(sock, packet_length)

    return packet
