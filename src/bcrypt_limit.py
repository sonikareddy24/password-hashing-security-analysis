"""
bcrypt_limit.py - Phase 5: The bcrypt 72-Byte Truncation Edge Case.

Demonstrates the classic bcrypt 72-byte maximum password length limitation.
In the original OpenBSD C specification:
- Passwords are truncated at 72 bytes; characters beyond byte 72 are silently ignored.
- Two passwords differing ONLY after byte 72 produce identical hashes and verify as equal.

In modern Python bcrypt (v4.0.0+):
- Passing >72 bytes raises ValueError to protect developers from unintended silent truncation.
- If manually truncated (e.g. password[:72]), collisions occur.

OWASP Mitigation:
- Pre-hash long passwords using SHA-256 before bcrypt, or migrate to Argon2id.
"""

import sys
import bcrypt
from typing import Dict, Any


def demonstrate_bcrypt_limit() -> Dict[str, Any]:
    print("\n" + "=" * 60)
    print("BCRYPT 72-BYTE LIMITATION EXPERIMENT")
    print("=" * 60)

    # 1. Base 72 bytes + distinct suffixes
    prefix = "A" * 72
    suffix_1 = "SuperSecretSuffix1"
    suffix_2 = "EntirelyDifferentSuffix2"

    pwd1 = prefix + suffix_1  # 90 bytes
    pwd2 = prefix + suffix_2  # 96 bytes

    print(f"Password 1 length : {len(pwd1)} bytes (72 bytes 'A' + '{suffix_1}')")
    print(f"Password 2 length : {len(pwd2)} bytes (72 bytes 'A' + '{suffix_2}')")

    # 2. Modern library exception handling
    library_exception_caught = False
    exception_message = ""
    try:
        bcrypt.hashpw(pwd1.encode("utf-8"), bcrypt.gensalt(4))
    except ValueError as e:
        library_exception_caught = True
        exception_message = str(e)
        print(f"\n[Library Guard] Modern bcrypt raised ValueError on >72 bytes:\n  --> \"{e}\"")

    # 3. Classic silent truncation simulation (or manual truncation)
    pwd1_truncated = pwd1.encode("utf-8")[:72]
    pwd2_truncated = pwd2.encode("utf-8")[:72]

    salt = bcrypt.gensalt(4)
    hash_1 = bcrypt.hashpw(pwd1_truncated, salt)
    hash_2 = bcrypt.hashpw(pwd2_truncated, salt)

    hashes_identical = (hash_1 == hash_2)
    verify_cross = bcrypt.checkpw(pwd2_truncated, hash_1)

    print(f"\n[Truncation Demonstration]")
    print(f"Truncated pwd1 bytes : {len(pwd1_truncated)} bytes")
    print(f"Truncated pwd2 bytes : {len(pwd2_truncated)} bytes")
    print(f"Hash 1               : {hash_1.decode('ascii')}")
    print(f"Hash 2               : {hash_2.decode('ascii')}")
    print(f"Hashes identical?    : {hashes_identical}")
    print(f"Does pwd2 verify against hash_1? : {verify_cross}")

    # 4. Mitigation demonstration: Pre-hashing with SHA-256
    import hashlib
    prehash_1 = hashlib.sha256(pwd1.encode("utf-8")).digest()
    prehash_2 = hashlib.sha256(pwd2.encode("utf-8")).digest()

    salt_mitigated = bcrypt.gensalt(4)
    hash_mitigated_1 = bcrypt.hashpw(prehash_1, salt_mitigated)
    hash_mitigated_2 = bcrypt.hashpw(prehash_2, salt_mitigated)

    mitigated_equal = (hash_mitigated_1 == hash_mitigated_2)
    mitigated_verify_cross = bcrypt.checkpw(prehash_2, hash_mitigated_1)

    print(f"\n[OWASP Pre-hash Mitigation (SHA-256 + bcrypt)]")
    print(f"Pre-hashed length    : {len(prehash_1)} bytes (fixed 32 bytes)")
    print(f"Hashes identical?    : {mitigated_equal} (Desired: False)")
    print(f"Cross-verification   : {mitigated_verify_cross} (Desired: False - correctly distinguished!)")

    return {
        "limitation_bytes": 72,
        "library_exception_raised": library_exception_caught,
        "exception_message": exception_message,
        "password_1_len": len(pwd1),
        "password_2_len": len(pwd2),
        "hashes_identical_under_truncation": hashes_identical,
        "cross_verification_succeeded": verify_cross,
        "prehash_mitigation_works": not mitigated_verify_cross,
        "summary": (
            "bcrypt natively considers only the first 72 bytes of input. Passwords differing only after byte 72 "
            "collide under standard bcrypt truncation. Modern Python bcrypt libraries throw a ValueError to alert "
            "callers. Pre-hashing with SHA-256 fixes the issue by mapping arbitrary-length inputs into 32 bytes."
        )
    }


if __name__ == "__main__":
    demonstrate_bcrypt_limit()
