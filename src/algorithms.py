"""
algorithms.py - Unified interface for password hashing algorithms:
MD5, SHA-256, PBKDF2-HMAC-SHA256, bcrypt, scrypt, and Argon2id.

Provides:
- hash(password, salt=None, **params) -> str
- verify(password, stored_hash) -> bool
"""

import os
import hmac
import base64
import hashlib
from typing import Optional, Dict, Any

import bcrypt
import argon2
from argon2 import PasswordHasher, Type


# ---------------------------------------------------------------------------
# Default and OWASP Reference Configurations
# ---------------------------------------------------------------------------

OWASP_CONFIGS = {
    "MD5": {},  # Not recommended by OWASP, not tunable
    "SHA-256": {},  # Fast general hash, not recommended for password storage
    "PBKDF2": {"iterations": 600000, "hash_name": "sha256"},
    "bcrypt": {"rounds": 10},
    "scrypt": {"n": 131072, "r": 8, "p": 1, "maxmem": 1024 * 1024 * 1024},  # N=2^17
    "Argon2id": {"time_cost": 2, "memory_cost": 19456, "parallelism": 1, "hash_len": 32},  # 19 MiB
}


# ---------------------------------------------------------------------------
# Helpers for Base64 encoding/decoding salts and digests
# ---------------------------------------------------------------------------

def _b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64_decode(data_str: str) -> bytes:
    return base64.b64decode(data_str.encode("ascii"))


# ---------------------------------------------------------------------------
# Algorithm Implementations
# ---------------------------------------------------------------------------

class MD5Algorithm:
    name = "MD5"
    is_tunable = False
    is_salted_by_default = False

    @staticmethod
    def hash(password: str, salt: Optional[bytes] = None, **kwargs) -> str:
        pwd_bytes = password.encode("utf-8")
        if salt is None:
            # Unsalted MD5 (standard 32 hex chars)
            return hashlib.md5(pwd_bytes).hexdigest()
        salt_hex = salt.hex()
        digest_hex = hashlib.md5(salt + pwd_bytes).hexdigest()
        return f"$md5${salt_hex}${digest_hex}"

    @staticmethod
    def verify(password: str, stored_hash: str) -> bool:
        pwd_bytes = password.encode("utf-8")
        if stored_hash.startswith("$md5$"):
            parts = stored_hash.split("$")
            if len(parts) == 4:
                salt = bytes.fromhex(parts[2])
                expected = parts[3]
                actual = hashlib.md5(salt + pwd_bytes).hexdigest()
                return hmac.compare_digest(actual, expected)
        # Unsalted comparison
        actual = hashlib.md5(pwd_bytes).hexdigest()
        return hmac.compare_digest(actual.lower(), stored_hash.lower())


class SHA256Algorithm:
    name = "SHA-256"
    is_tunable = False
    is_salted_by_default = False

    @staticmethod
    def hash(password: str, salt: Optional[bytes] = None, **kwargs) -> str:
        pwd_bytes = password.encode("utf-8")
        if salt is None:
            return hashlib.sha256(pwd_bytes).hexdigest()
        salt_hex = salt.hex()
        digest_hex = hashlib.sha256(salt + pwd_bytes).hexdigest()
        return f"$sha256${salt_hex}${digest_hex}"

    @staticmethod
    def verify(password: str, stored_hash: str) -> bool:
        pwd_bytes = password.encode("utf-8")
        if stored_hash.startswith("$sha256$"):
            parts = stored_hash.split("$")
            if len(parts) == 4:
                salt = bytes.fromhex(parts[2])
                expected = parts[3]
                actual = hashlib.sha256(salt + pwd_bytes).hexdigest()
                return hmac.compare_digest(actual, expected)
        # Unsalted comparison
        actual = hashlib.sha256(pwd_bytes).hexdigest()
        return hmac.compare_digest(actual.lower(), stored_hash.lower())


class PBKDF2Algorithm:
    name = "PBKDF2"
    is_tunable = True
    is_salted_by_default = True

    @staticmethod
    def hash(password: str, salt: Optional[bytes] = None, iterations: int = 600000, hash_name: str = "sha256", **kwargs) -> str:
        if salt is None:
            salt = os.urandom(16)
        pwd_bytes = password.encode("utf-8")
        derived = hashlib.pbkdf2_hmac(hash_name, pwd_bytes, salt, iterations)
        return f"$pbkdf2-{hash_name}${iterations}${_b64_encode(salt)}${_b64_encode(derived)}"

    @staticmethod
    def verify(password: str, stored_hash: str) -> bool:
        try:
            parts = stored_hash.split("$")
            # Format: ['', 'pbkdf2-sha256', 'iterations', 'salt_b64', 'hash_b64']
            if len(parts) != 5:
                return False
            _, scheme, iter_str, salt_b64, hash_b64 = parts
            hash_name = scheme.replace("pbkdf2-", "")
            iterations = int(iter_str)
            salt = _b64_decode(salt_b64)
            expected = _b64_decode(hash_b64)
            actual = hashlib.pbkdf2_hmac(hash_name, password.encode("utf-8"), salt, iterations, dklen=len(expected))
            return hmac.compare_digest(actual, expected)
        except Exception:
            return False


class BcryptAlgorithm:
    name = "bcrypt"
    is_tunable = True
    is_salted_by_default = True

    @staticmethod
    def hash(password: str, salt: Optional[bytes] = None, rounds: int = 10, **kwargs) -> str:
        # Note: bcrypt has a 72-byte limit. We truncate here or preserve error if testing limit
        truncate = kwargs.get("truncate_72", True)
        pwd_bytes = password.encode("utf-8")
        if truncate and len(pwd_bytes) > 72:
            pwd_bytes = pwd_bytes[:72]
        
        if salt is None:
            salt = bcrypt.gensalt(rounds=rounds)
        elif not isinstance(salt, (bytes, bytearray)) or not (salt.startswith(b"$2a$") or salt.startswith(b"$2b$") or salt.startswith(b"$2y$")):
            # If a raw random salt is passed in, convert to standard bcrypt salt with configured rounds
            salt = bcrypt.gensalt(rounds=rounds)
        return bcrypt.hashpw(pwd_bytes, salt).decode("ascii")

    @staticmethod
    def verify(password: str, stored_hash: str) -> bool:
        try:
            pwd_bytes = password.encode("utf-8")
            if len(pwd_bytes) > 72:
                pwd_bytes = pwd_bytes[:72]
            return bcrypt.checkpw(pwd_bytes, stored_hash.encode("ascii"))
        except Exception:
            return False


class ScryptAlgorithm:
    name = "scrypt"
    is_tunable = True
    is_salted_by_default = True

    @staticmethod
    def hash(password: str, salt: Optional[bytes] = None, n: int = 32768, r: int = 8, p: int = 1, maxmem: int = 1024 * 1024 * 1024, **kwargs) -> str:
        if salt is None:
            salt = os.urandom(16)
        pwd_bytes = password.encode("utf-8")
        derived = hashlib.scrypt(pwd_bytes, salt=salt, n=n, r=r, p=p, maxmem=maxmem)
        return f"$scrypt$ln={n},r={r},p={p}${_b64_encode(salt)}${_b64_encode(derived)}"

    @staticmethod
    def verify(password: str, stored_hash: str) -> bool:
        try:
            parts = stored_hash.split("$")
            # Format: ['', 'scrypt', 'ln=32768,r=8,p=1', 'salt_b64', 'hash_b64']
            if len(parts) != 5:
                return False
            params_str = parts[2]
            param_dict = dict(item.split("=") for item in params_str.split(","))
            n = int(param_dict.get("ln", param_dict.get("n", 32768)))
            r = int(param_dict.get("r", 8))
            p = int(param_dict.get("p", 1))
            salt = _b64_decode(parts[3])
            expected = _b64_decode(parts[4])
            actual = hashlib.scrypt(
                password.encode("utf-8"),
                salt=salt,
                n=n,
                r=r,
                p=p,
                maxmem=1024 * 1024 * 1024,
                dklen=len(expected)
            )
            return hmac.compare_digest(actual, expected)
        except Exception:
            return False


class Argon2idAlgorithm:
    name = "Argon2id"
    is_tunable = True
    is_salted_by_default = True

    @staticmethod
    def hash(password: str, salt: Optional[bytes] = None, time_cost: int = 2, memory_cost: int = 19456, parallelism: int = 1, hash_len: int = 32, **kwargs) -> str:
        # Argon2 generates its own salt internally or can accept salt_len
        ph = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            type=Type.ID
        )
        return ph.hash(password)

    @staticmethod
    def verify(password: str, stored_hash: str) -> bool:
        try:
            ph = PasswordHasher()
            return ph.verify(stored_hash, password)
        except Exception:
            return False


# Registry of all supported algorithms
ALGORITHMS: Dict[str, Any] = {
    "MD5": MD5Algorithm,
    "SHA-256": SHA256Algorithm,
    "PBKDF2": PBKDF2Algorithm,
    "bcrypt": BcryptAlgorithm,
    "scrypt": ScryptAlgorithm,
    "Argon2id": Argon2idAlgorithm,
}


def get_algorithm(name: str):
    if name not in ALGORITHMS:
        raise ValueError(f"Unknown algorithm: {name}. Available: {list(ALGORITHMS.keys())}")
    return ALGORITHMS[name]


def hash_password(algorithm_name: str, password: str, salt: Optional[bytes] = None, **kwargs) -> str:
    algo = get_algorithm(algorithm_name)
    return algo.hash(password, salt=salt, **kwargs)


def verify_password(algorithm_name: str, password: str, stored_hash: str) -> bool:
    algo = get_algorithm(algorithm_name)
    return algo.verify(password, stored_hash)
