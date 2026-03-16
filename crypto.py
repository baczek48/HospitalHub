import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

# Argon2id parameters - tuned for ~1s derivation on typical hardware
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
SALT_SIZE = 16
NONCE_SIZE = 12
FILE_VERSION = 1

# Binary file format (v2):
#   HHUB  (4 bytes magic)
#   \x02  (1 byte version)
#   salt  (16 bytes)
#   nonce (12 bytes)
#   ciphertext (rest of file — AES-256-GCM encrypted JSON)
#
# Legacy format (v1): JSON envelope with base64 fields — still readable.

_MAGIC = b"HHUB"
_BIN_VERSION = 2
_HEADER_SIZE = len(_MAGIC) + 1 + SALT_SIZE + NONCE_SIZE  # 4+1+16+12 = 33


def _zero(ba: bytearray) -> None:
    """Best-effort zeroing of a bytearray in memory."""
    for i in range(len(ba)):
        ba[i] = 0


def _derive_key(password: str, salt: bytes) -> bytearray:
    """Derive AES-256 key from master password using Argon2id."""
    raw = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )
    return bytearray(raw)


def encrypt(data: dict, password: str) -> bytes:
    """Encrypt vault data with AES-256-GCM. Returns binary file content."""
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(password, salt)

    plaintext = bytearray(json.dumps(data, ensure_ascii=False).encode("utf-8"))
    aesgcm = AESGCM(bytes(key))
    ciphertext = aesgcm.encrypt(nonce, bytes(plaintext), None)

    _zero(key)
    _zero(plaintext)

    # Binary format: MAGIC + VERSION + SALT + NONCE + CIPHERTEXT
    return _MAGIC + bytes([_BIN_VERSION]) + salt + nonce + ciphertext


def decrypt(content: bytes, password: str) -> dict:
    """Decrypt vault file content. Raises ValueError on wrong password or corruption.

    Supports both binary format (v2, magic HHUB) and legacy JSON format (v1).
    """
    if content[:4] == _MAGIC:
        return _decrypt_binary(content, password)
    return _decrypt_legacy(content, password)


def _decrypt_binary(content: bytes, password: str) -> dict:
    """Decrypt binary vault format (v2)."""
    if len(content) < _HEADER_SIZE + 16:  # at least GCM tag
        raise ValueError(
            "Plik vault jest uszkodzony (za krótki).\n"
            "Czy plik nie został przypadkiem edytowany?")

    version = content[4]
    if version != _BIN_VERSION:
        raise ValueError(
            f"Nieobsługiwana wersja pliku vault (v{version}).")

    offset = len(_MAGIC) + 1
    salt = content[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = content[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = content[offset:]

    key = _derive_key(password, salt)
    try:
        aesgcm = AESGCM(bytes(key))
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        _zero(key)
        raise ValueError("Nieprawidłowe hasło.")
    _zero(key)

    try:
        return json.loads(plaintext.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError(
            "Plik vault jest uszkodzony — odszyfrowane dane nie są prawidłowe.\n"
            "Czy plik nie został przypadkiem edytowany?")


def _decrypt_legacy(content: bytes, password: str) -> dict:
    """Decrypt legacy JSON envelope format (v1)."""
    try:
        envelope = json.loads(content.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError(
            "Plik vault jest uszkodzony — nie można odczytać struktury.\n"
            "Czy plik nie został przypadkiem edytowany lub otwarty w edytorze tekstu?")

    if envelope.get("v") != FILE_VERSION:
        raise ValueError(f"Nieobsługiwana wersja pliku vault (v{envelope.get('v')})")

    try:
        salt = base64.b64decode(envelope["salt"])
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["data"])
    except (KeyError, Exception) as e:
        raise ValueError(f"Uszkodzony plik vault: {e}")

    key = _derive_key(password, salt)
    try:
        aesgcm = AESGCM(bytes(key))
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        result = json.loads(plaintext.decode("utf-8"))
        _zero(key)
        return result
    except Exception:
        _zero(key)
        raise ValueError("Nieprawidłowe hasło.")


def reencrypt(content: bytes, old_password: str, new_password: str) -> bytes:
    """Decrypt with old password and re-encrypt with new password."""
    data = decrypt(content, old_password)
    return encrypt(data, new_password)


def hash_admin_password(password: str) -> tuple[str, str]:
    """Hash admin password with Argon2id. Returns (hash_b64, salt_b64)."""
    salt = os.urandom(SALT_SIZE)
    raw = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )
    return base64.b64encode(raw).decode(), base64.b64encode(salt).decode()


def verify_admin_password(password: str, hash_b64: str, salt_b64: str) -> bool:
    """Verify admin password against stored hash."""
    salt = base64.b64decode(salt_b64)
    raw = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )
    import hmac
    return hmac.compare_digest(raw, base64.b64decode(hash_b64))
