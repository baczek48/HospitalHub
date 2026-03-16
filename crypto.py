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
    """Encrypt vault data with AES-256-GCM. Returns file content bytes."""
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(password, salt)

    plaintext = bytearray(json.dumps(data, ensure_ascii=False).encode("utf-8"))
    aesgcm = AESGCM(bytes(key))
    ciphertext = aesgcm.encrypt(nonce, bytes(plaintext), None)

    _zero(key)
    _zero(plaintext)

    envelope = {
        "v": FILE_VERSION,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "data": base64.b64encode(ciphertext).decode(),
    }
    return json.dumps(envelope).encode("utf-8")


def decrypt(content: bytes, password: str) -> dict:
    """Decrypt vault file content. Raises ValueError on wrong password or corruption."""
    try:
        envelope = json.loads(content.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("Uszkodzony plik vault - nie mozna odczytac struktury")

    if envelope.get("v") != FILE_VERSION:
        raise ValueError(f"Nieobslugiwana wersja pliku vault (v{envelope.get('v')})")

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
        raise ValueError("Nieprawidlowe haslo lub uszkodzony plik vault")


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
