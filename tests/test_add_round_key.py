"""
Differential tests for add_round_key. This is just a byte-wise XOR,
so the test is basically checking that ctypes wiring for the
two-pointer signature works and that the loop bound is right.
"""

import random

from conftest import (
    AES_BLOCK_128,
    bytes_to_matrix,
    matrix_to_bytes,
    to_c_buffer,
)

RNG = random.Random(1337)


def _random_block():
    return bytes(RNG.randint(0, 255) for _ in range(16))


def test_add_round_key_matches_reference(rijndael, aes_ref):
    for _ in range(3):
        block_bytes = _random_block()
        key_bytes = _random_block()

        c_block = to_c_buffer(block_bytes)
        c_key = to_c_buffer(key_bytes)
        rijndael.add_round_key(c_block, c_key, AES_BLOCK_128)

        py_state = bytes_to_matrix(block_bytes)
        py_key = bytes_to_matrix(key_bytes)
        aes_ref.add_round_key(py_state, py_key)
        py_result = matrix_to_bytes(py_state)

        assert bytes(c_block) == py_result


def test_add_round_key_twice_is_identity(rijndael):
    # XORing with the same key twice should give back the original.
    for _ in range(3):
        original = _random_block()
        key = _random_block()

        block = to_c_buffer(original)
        key_buf = to_c_buffer(key)

        rijndael.add_round_key(block, key_buf, AES_BLOCK_128)
        rijndael.add_round_key(block, key_buf, AES_BLOCK_128)

        assert bytes(block) == original
