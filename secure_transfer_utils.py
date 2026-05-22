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
    pad_len = DES_BLOCK_SIZE - (len(data) % DES_BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)


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
    """Return: IV (8 bytes) + ciphertext"""
    if len(key) != DES_KEY_SIZE:
        raise ValueError("DES key must be 8 bytes")
    
    iv = generate_iv()
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded = pkcs7_pad(plaintext)
    ciphertext = cipher.encrypt(padded)
    return iv + ciphertext


def des_decrypt(key: bytes, ciphertext_with_iv: bytes) -> bytes:
    """Input: IV (8 bytes) + ciphertext"""
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
    return PKCS1_OAEP.new(public_key).encrypt(data)


def rsa_decrypt(private_key, encrypted_data: bytes) -> bytes:
    return PKCS1_OAEP.new(private_key).decrypt(encrypted_data)


# =========================================================
# PACKET BUILD / PARSE
# =========================================================
def pack_u32(value: int) -> bytes:
    return struct.pack("!I", value)


def unpack_u32(data: bytes) -> int:
    return struct.unpack("!I", data)[0]


def build_packet(encrypted_des_key: bytes, ciphertext: bytes, sha256_digest: bytes) -> bytes:
    """Build packet theo đúng protocol Lab 8"""
    packet = b""
    packet += pack_u32(len(encrypted_des_key))
    packet += encrypted_des_key
    packet += pack_u32(len(ciphertext))
    packet += ciphertext
    packet += sha256_digest
    return packet


def parse_packet(packet: bytes):
    """Parse packet theo protocol Lab 8"""
    offset = 0
    len_key = unpack_u32(packet[offset:offset + 4])
    offset += 4
    enc_key = packet[offset:offset + len_key]
    offset += len_key

    len_cipher = unpack_u32(packet[offset:offset + 4])
    offset += 4
    ciphertext = packet[offset:offset + len_cipher]
    offset += len_cipher

    sha_hash = packet[offset:offset + SHA256_DIGEST_SIZE]
    return enc_key, ciphertext, sha_hash


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
    """LAB 8: Gửi trực tiếp packet (không thêm length prefix)"""
    sock.sendall(packet)


def receive_packet(sock) -> bytes:
    """Nhận và reconstruct full packet theo format Lab 8"""
    len_key = unpack_u32(recv_exact(sock, 4))
    enc_key = recv_exact(sock, len_key)
    
    len_cipher = unpack_u32(recv_exact(sock, 4))
    cipher = recv_exact(sock, len_cipher)
    
    sha_hash = recv_exact(sock, SHA256_DIGEST_SIZE)
    
    return pack_u32(len_key) + enc_key + pack_u32(len_cipher) + cipher + sha_hash


def recv_secure_packet(sock):
    packet = receive_packet(sock)
    return parse_packet(packet)


# =========================================================
# ALIASES
# =========================================================
des_encrypt_cbc = des_encrypt
des_decrypt_cbc = des_decrypt
sha256_digest = sha256_hash
encrypt_des_key_rsa = rsa_encrypt
decrypt_des_key_rsa = rsa_decrypt
build_secure_packet = build_packet
parse_secure_packet = parse_packet
