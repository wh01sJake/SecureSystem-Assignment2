"""
Differential tests: our C sub_bytes / invert_sub_bytes must produce the
same output as boppreh/aes for identical inputs. Uses 3 random blocks
per operation. Seed is fixed so any failure reproduces.
"""

import random

from conftest import (
    AES_BLOCK_128,
    bytes_to_matrix,
    matrix_to_bytes,
    to_c_buffer,
)

RNG = random.Random(42)


def _random_block():
    return bytes(RNG.randint(0, 255) for _ in range(16))


def test_sub_bytes_matches_reference(rijndael, aes_ref):
    # Ran into a confusion here first time: boppreh's sub_bytes mutates
    # the matrix in place and returns None, so I have to keep a reference
    # to py_state rather than reassigning from the return value.
    for _ in range(3):
        original = _random_block()

        c_block = to_c_buffer(original)
        rijndael.sub_bytes(c_block, AES_BLOCK_128)
        c_result = bytes(c_block)

        py_state = bytes_to_matrix(original)
        aes_ref.sub_bytes(py_state)
        py_result = matrix_to_bytes(py_state)

        assert c_result == py_result, f"mismatch on input {original.hex()}"


def test_invert_sub_bytes_matches_reference(rijndael, aes_ref):
    for _ in range(3):
        original = _random_block()

        c_block = to_c_buffer(original)
        rijndael.invert_sub_bytes(c_block, AES_BLOCK_128)
        c_result = bytes(c_block)

        py_state = bytes_to_matrix(original)
        aes_ref.inv_sub_bytes(py_state)
        py_result = matrix_to_bytes(py_state)

        assert c_result == py_result, f"mismatch on input {original.hex()}"


def test_sub_bytes_then_invert_is_identity(rijndael):
    # Sanity check that doesn't need the reference: sub_bytes followed by
    # its inverse should give back the original block. If this fails the
    # tables are wrong.
    for _ in range(3):
        original = _random_block()
        block = to_c_buffer(original)

        rijndael.sub_bytes(block, AES_BLOCK_128)
        rijndael.invert_sub_bytes(block, AES_BLOCK_128)

        assert bytes(block) == original
