"""
Differential tests for shift_rows and invert_shift_rows against boppreh.
"""

import random

from conftest import (
    AES_BLOCK_128,
    bytes_to_matrix,
    matrix_to_bytes,
    to_c_buffer,
)

RNG = random.Random(7)  # different seed than sub_bytes so we exercise
                        # a different set of random blocks


def _random_block():
    return bytes(RNG.randint(0, 255) for _ in range(16))


def test_shift_rows_matches_reference(rijndael, aes_ref):
    for _ in range(3):
        original = _random_block()

        c_block = to_c_buffer(original)
        rijndael.shift_rows(c_block, AES_BLOCK_128)

        py_state = bytes_to_matrix(original)
        aes_ref.shift_rows(py_state)
        py_result = matrix_to_bytes(py_state)

        assert bytes(c_block) == py_result, (
            f"shift_rows mismatch on {original.hex()}:\n"
            f"  C  got: {bytes(c_block).hex()}\n"
            f"  py got: {py_result.hex()}"
        )


def test_invert_shift_rows_matches_reference(rijndael, aes_ref):
    for _ in range(3):
        original = _random_block()

        c_block = to_c_buffer(original)
        rijndael.invert_shift_rows(c_block, AES_BLOCK_128)

        py_state = bytes_to_matrix(original)
        aes_ref.inv_shift_rows(py_state)
        py_result = matrix_to_bytes(py_state)

        assert bytes(c_block) == py_result


def test_shift_then_invert_is_identity(rijndael):
    # If the pair is self-consistent this passes regardless of whether
    # we match the reference. Useful for catching the case where both
    # funcs are wrong but wrong in matching ways.
    for _ in range(3):
        original = _random_block()
        block = to_c_buffer(original)

        rijndael.shift_rows(block, AES_BLOCK_128)
        rijndael.invert_shift_rows(block, AES_BLOCK_128)

        assert bytes(block) == original
