"""
Differential tests for mix_columns and invert_mix_columns.
"""

import random

from conftest import (
    AES_BLOCK_128,
    bytes_to_matrix,
    matrix_to_bytes,
    to_c_buffer,
)

RNG = random.Random(99)


def _random_block():
    return bytes(RNG.randint(0, 255) for _ in range(16))


def test_mix_columns_matches_reference(rijndael, aes_ref):
    for _ in range(3):
        original = _random_block()

        c_block = to_c_buffer(original)
        rijndael.mix_columns(c_block, AES_BLOCK_128)

        py_state = bytes_to_matrix(original)
        aes_ref.mix_columns(py_state)
        py_result = matrix_to_bytes(py_state)

        assert bytes(c_block) == py_result, (
            f"mix_columns mismatch on {original.hex()}:\n"
            f"  C  got: {bytes(c_block).hex()}\n"
            f"  py got: {py_result.hex()}"
        )


def test_invert_mix_columns_matches_reference(rijndael, aes_ref):
    for _ in range(3):
        original = _random_block()

        c_block = to_c_buffer(original)
        rijndael.invert_mix_columns(c_block, AES_BLOCK_128)

        py_state = bytes_to_matrix(original)
        aes_ref.inv_mix_columns(py_state)
        py_result = matrix_to_bytes(py_state)

        assert bytes(c_block) == py_result


def test_mix_then_invert_is_identity(rijndael):
    for _ in range(3):
        original = _random_block()
        block = to_c_buffer(original)

        rijndael.mix_columns(block, AES_BLOCK_128)
        rijndael.invert_mix_columns(block, AES_BLOCK_128)

        assert bytes(block) == original
