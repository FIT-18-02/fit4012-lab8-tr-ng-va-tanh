import hashlib
import os
import struct
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad


DES_KEY_SIZE = 8
DES_BLOCK_SIZE = 8
SHA256_SIZE = 32


# =========================================================
# DES helpers
# =========================================================

def generate_des_key():
    """
    Generate random 8-byte DES key
    """
    return os.urandom(DES_KEY_SIZE)


def generate_iv():
    """
    Generate random 8-byte IV for DES-CBC
    """
    return os.urandom(DES_BLOCK_SIZE)


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

    Input format:
        iv + ciphertext
    """
    iv = ciphertext_with_iv[:DES_BLOCK_SIZE]
    ciphertext = ciphertext_with_iv[DES_BLOCK_SIZE:]

    cipher = DES.new(key, DES.MODE_CBC, iv)

    padded_plaintext = cipher.decrypt(ciphertext)

    plaintext = pkcs7_unpad(padded_plaintext)

    return plaintext


# =========================================================
# SHA-256 helpers
# =========================================================

def sha256_hash(data: bytes) -> bytes:
    """
    Compute SHA-256 hash
    """
    return hashlib.sha256(data).digest()


# =========================================================
# RSA helpers
# =========================================================

def load_public_key(public_key_path: str):
    """
    Load RSA public key from PEM file
    """
    with open(public_key_path, "rb") as f:
        return RSA.import_key(f.read())


def load_private_key(private_key_path: str):
    """
    Load RSA private key from PEM file
    """
    with open(private_key_path, "rb") as f:
        return RSA.import_key(f.read())


def rsa_encrypt_key(des_key: bytes, public_key) -> bytes:
    """
    Encrypt DES key using RSA-OAEP
    """
    cipher_rsa = PKCS1_OAEP.new(public_key)

    encrypted_key = cipher_rsa.encrypt(des_key)

    return encrypted_key


def rsa_decrypt_key(encrypted_key: bytes, private_key) -> bytes:
    """
    Decrypt DES key using RSA-OAEP
    """
    cipher_rsa = PKCS1_OAEP.new(private_key)

    des_key = cipher_rsa.decrypt(encrypted_key)

    return des_key


# =========================================================
# Packet helpers
# =========================================================

def build_packet(
    encrypted_des_key: bytes,
    ciphertext: bytes,
    sha256_digest: bytes
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

    packet += struct.pack("!I", len(encrypted_des_key))
    packet += encrypted_des_key

    packet += struct.pack("!I", len(ciphertext))
    packet += ciphertext

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

    # Read encrypted key length
    len_key = struct.unpack("!I", packet[offset:offset + 4])[0]
    offset += 4

    # Read encrypted key
    encrypted_des_key = packet[offset:offset + len_key]
    offset += len_key

    # Read ciphertext length
    len_cipher = struct.unpack("!I", packet[offset:offset + 4])[0]
    offset += 4

    # Read ciphertext
    ciphertext = packet[offset:offset + len_cipher]
    offset += len_cipher

    # Read SHA256 hash
    sha256_digest = packet[offset:offset + SHA256_SIZE]

    return (
        encrypted_des_key,
        ciphertext,
        sha256_digest
    )


# =========================================================
# Socket helpers
# =========================================================

def recv_exact(sock, num_bytes):
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

    packet_length = struct.pack("!I", len(packet))

    sock.sendall(packet_length + packet)


def receive_packet(sock) -> bytes:
    """
    Receive packet with length prefix
    """

    raw_length = recv_exact(sock, 4)

    packet_length = struct.unpack("!I", raw_length)[0]

    packet = recv_exact(sock, packet_length)

    return packet
