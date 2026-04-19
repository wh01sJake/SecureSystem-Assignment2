"""
Differential tests for key expansion. Our C expand_key should produce
the same 176 bytes as boppreh's internal _key_matrices (flattened).
"""

import ctypes
import random

from conftest import AES_BLOCK_128, matrix_to_bytes, to_c_buffer

RNG = random.Random(2025)


def _random_key():
    return bytes(RNG.randint(0, 255) for _ in range(16))


def _reference_expanded_key(aes_ref, master_key):
    """Flatten boppreh's per-round matrices into a single 176-byte blob."""
    cipher = aes_ref.AES(master_key)
    return b"".join(matrix_to_bytes(m) for m in cipher._key_matrices)


def test_expand_key_matches_reference(rijndael, aes_ref):
    for _ in range(3):
        master_key = _random_key()

        c_key = to_c_buffer(master_key)
        c_ptr = rijndael.expand_key(c_key, AES_BLOCK_128)
        c_expanded = bytes(ctypes.string_at(c_ptr, 176))

        py_expanded = _reference_expanded_key(aes_ref, master_key)

        assert c_expanded == py_expanded, (
            f"expand_key mismatch for master_key={master_key.hex()}\n"
            f"  first mismatched byte at index "
            f"{next(i for i, (a, b) in enumerate(zip(c_expanded, py_expanded)) if a != b)}"
        )


def test_expand_key_first_round_is_cipher_key(rijndael):
    # Easy sanity check: the first 16 bytes of the expanded key are
    # supposed to be the cipher key itself.
    for _ in range(3):
        master_key = _random_key()
        c_key = to_c_buffer(master_key)
        c_ptr = rijndael.expand_key(c_key, AES_BLOCK_128)
        c_expanded = bytes(ctypes.string_at(c_ptr, 176))

        assert c_expanded[:16] == master_key
