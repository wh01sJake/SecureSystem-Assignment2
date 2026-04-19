"""
End-to-end tests for aes_encrypt_block and aes_decrypt_block.

For each random (plaintext, key) pair we check two things:
  1. Our C ciphertext matches boppreh's ciphertext byte-for-byte.
  2. Feeding that ciphertext back through our C decrypt restores
     the original plaintext.

This is the headline test that demonstrates the whole pipeline works.
"""

import ctypes
import random

from conftest import AES_BLOCK_128, to_c_buffer

RNG = random.Random(31415)


def _random_block():
    return bytes(RNG.randint(0, 255) for _ in range(16))


def test_encrypt_matches_reference(rijndael, aes_ref):
    for _ in range(3):
        plaintext = _random_block()
        key = _random_block()

        # C side.
        c_plain = to_c_buffer(plaintext)
        c_key = to_c_buffer(key)
        c_cipher_ptr = rijndael.aes_encrypt_block(c_plain, c_key, AES_BLOCK_128)
        c_cipher = bytes(ctypes.string_at(c_cipher_ptr, 16))

        # Python reference side.
        py_cipher = aes_ref.AES(key).encrypt_block(plaintext)

        assert c_cipher == py_cipher, (
            f"ciphertext mismatch:\n"
            f"  plaintext={plaintext.hex()}\n"
            f"  key={key.hex()}\n"
            f"  C  got: {c_cipher.hex()}\n"
            f"  py got: {py_cipher.hex()}"
        )


def test_encrypt_then_decrypt_recovers_plaintext(rijndael):
    # The classic roundtrip test: if encryption and decryption are
    # correct inverses, this holds for any input.
    for _ in range(3):
        plaintext = _random_block()
        key = _random_block()

        c_plain = to_c_buffer(plaintext)
        c_key = to_c_buffer(key)

        cipher_ptr = rijndael.aes_encrypt_block(c_plain, c_key, AES_BLOCK_128)
        # Re-wrap the ciphertext into a ctypes buffer so decrypt gets a
        # proper pointer to 16 owned bytes. (ctypes returns a POINTER,
        # which we can pass straight back, but wrapping keeps this test
        # symmetric with encrypt.)
        cipher_bytes = bytes(ctypes.string_at(cipher_ptr, 16))
        c_cipher_buf = to_c_buffer(cipher_bytes)

        recovered_ptr = rijndael.aes_decrypt_block(c_cipher_buf, c_key, AES_BLOCK_128)
        recovered = bytes(ctypes.string_at(recovered_ptr, 16))

        assert recovered == plaintext, (
            f"roundtrip failed:\n"
            f"  plaintext = {plaintext.hex()}\n"
            f"  recovered = {recovered.hex()}"
        )


def test_decrypt_reference_ciphertext(rijndael, aes_ref):
    # Reverse direction: feed a ciphertext produced by the Python
    # reference into our C decrypt and check we recover the plaintext.
    for _ in range(3):
        plaintext = _random_block()
        key = _random_block()

        py_cipher = aes_ref.AES(key).encrypt_block(plaintext)

        c_cipher = to_c_buffer(py_cipher)
        c_key = to_c_buffer(key)
        recovered_ptr = rijndael.aes_decrypt_block(c_cipher, c_key, AES_BLOCK_128)
        recovered = bytes(ctypes.string_at(recovered_ptr, 16))

        assert recovered == plaintext
