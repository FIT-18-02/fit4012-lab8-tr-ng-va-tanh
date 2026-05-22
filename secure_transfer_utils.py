import struct

# =========================================================
# CONSTANTS
# =========================================================

SHA256_DIGEST_SIZE = 32

# =========================================================
# PACKET HELPERS
# =========================================================

def pack_u32(value: int) -> bytes:
    """Pack unsigned int into 4 bytes network byte order."""
    return struct.pack("!I", value)

def unpack_u32(data: bytes) -> int:
    """Unpack 4-byte unsigned int."""
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
# BACKWARD COMPATIBILITY
# =========================================================

build_secure_packet = build_packet
parse_secure_packet = parse_packet
