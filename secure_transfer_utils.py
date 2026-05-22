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


def des_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using DES-CBC.
    Điểu chỉnh thứ tự đối số (plaintext, key) phổ thông hoặc bọc linh hoạt.
    Returns:
        iv + ciphertext
    """
    # Đảo bảo linh hoạt nếu vị trí đối số truyền vào bị ngược giữa (key, plaintext)
    if len(plaintext) == DES_KEY_SIZE and len(key) != DES_KEY_SIZE:
        key, plaintext = plaintext, key

    if len(key) != DES_KEY_SIZE:
        raise ValueError("DES key must be 8 bytes")

    iv = generate_iv()
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded = pkcs7_pad(plaintext)
    ciphertext = cipher.encrypt(padded)

    return iv + ciphertext


def des_decrypt(ciphertext_with_iv: bytes, key: bytes) -> bytes:
    """
    Decrypt DES-CBC ciphertext.
    Input format:
        iv + ciphertext
    """
    # Hỗ trợ đảo đối số linh hoạt nếu người dùng truyền nhầm (key, ciphertext)
    if len(ciphertext_with_iv) == DES_KEY_SIZE and len(key) != DES_KEY_SIZE:
        key, ciphertext_with_iv = ciphertext_with_iv, key

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


def rsa_encrypt(data: bytes, public_key) -> bytes:
    """
    Encrypt data using RSA-OAEP.
    Hỗ trợ tiếp nhận cả đường dẫn file, bytes PEM, hoặc đối tượng Key.
    """
    if isinstance(public_key, (str, bytes)):
        if isinstance(public_key, str) and ( public_key.endswith('.pem') or '/' in public_key or '\\' in public_key ):
            public_key = load_public_key(public_key)
        else:
            public_key = RSA.import_key(public_key)
            
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(data)


def rsa_decrypt(encrypted_data: bytes, private_key) -> bytes:
    """
    Decrypt RSA-OAEP encrypted data.
    Hỗ trợ tiếp nhận cả đường dẫn file, bytes PEM, hoặc đối tượng Key.
    """
    if isinstance(private_key, (str, bytes)):
        if isinstance(private_key, str) and ( private_key.endswith('.pem') or '/' in private_key or '\\' in private_key ):
            private_key = load_private_key(private_key)
        else:
            private_key = RSA.import_key(private_key)

    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_data)


# =========================================================
# PACKET HELPERS
# =========================================================

def pack_u32(value: int) -> bytes:
    """
    Pack unsigned int into 4 bytes network byte order.
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
    # encrypted DES key length
    packet += pack_u32(len(encrypted_des_key))
    # encrypted DES key
    packet += encrypted_des_key
    # ciphertext length
    packet += pack_u32(len(ciphertext))
    # ciphertext
    packet += ciphertext
    # SHA256 hash
    packet += sha256_digest

    return packet


def parse_packet(packet: bytes):
    """
    Parse packet.
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
    Gửi trực tiếp chuỗi packet thô đã build hoàn thiện ra Socket 
    để khớp hoàn toàn với cấu trúc phân mảnh dữ liệu của Lab 8.
    """
    sock.sendall(packet)


def receive_packet(sock) -> bytes:
    """
    Đọc gói tin trực tiếp từ luồng mạng dựa theo cấu trúc Header tuần tự:
    Bóc len_key -> Đọc key -> Bóc len_cipher -> Đọc cipher -> Đọc 32 bytes hash.
    """
    # 1. Lấy độ dài key mã hóa
    raw_len_key = recv_exact(sock, 4)
    len_key = unpack_u32(raw_len_key)
    enc_key = recv_exact(sock, len_key)
    
    # 2. Lấy độ dài bản mã
    raw_len_cipher = recv_exact(sock, 4)
    len_cipher = unpack_u32(raw_len_cipher)
    ciphertext = recv_exact(sock, len_cipher)
    
    # 3. Lấy hash toàn vẹn
    sha_hash = recv_exact(sock, SHA256_DIGEST_SIZE)
    
    # Gom cụm lại thành chuỗi packet hoàn chỉnh để xử lý đồng bộ
    return raw_len_key + enc_key + raw_len_cipher + ciphertext + sha_hash


def recv_secure_packet(sock):
    """
    Receive secure packet and parse it.
    """
    packet = receive_packet(sock)
    return parse_packet(packet)


# =========================================================
# BACKWARD COMPATIBILITY (Alias mapping)
# =========================================================

def des_encrypt_cbc(plaintext: bytes, key: bytes) -> bytes:
    return des_encrypt(plaintext, key)

def des_decrypt_cbc(ciphertext_with_iv: bytes, key: bytes) -> bytes:
    return des_decrypt(ciphertext_with_iv, key)

sha256_digest = sha256_hash

def encrypt_des_key_rsa(data: bytes, public_key) -> bytes:
    return rsa_encrypt(data, public_key)

def decrypt_des_key_rsa(encrypted_data: bytes, private_key) -> bytes:
    return rsa_decrypt(encrypted_data, private_key)

build_secure_packet = build_packet
parse_secure_packet = parse_packet
