"""
Shared pytest helpers:
  - Load the compiled rijndael.so once per session
  - Expose the boppreh/aes reference module as aes_ref
  - Provide byte <-> 4x4 matrix conversion so we can bridge our
    flat C buffers with boppreh's nested-list state
"""

import ctypes
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SO_PATH = PROJECT_ROOT / "rijndael.so"
REFERENCE_DIR = PROJECT_ROOT / "aes-python"

# Put the Python reference on sys.path so `import aes` finds boppreh's
# module. This is the simplest way to consume a submodule without turning
# it into a proper Python package.
sys.path.insert(0, str(REFERENCE_DIR))
import aes as ref_aes  # noqa: E402

# The aes_block_size_t enum in rijndael.h: AES_BLOCK_128 is declared first
# so the compiler gives it value 0. Hardcoding it here is a bit fragile
# but scanning the header at runtime is overkill for one constant.
AES_BLOCK_128 = 0


@pytest.fixture(scope="session")
def rijndael():
    """Load rijndael.so and declare the C function signatures we'll call."""
    if not SO_PATH.exists():
        pytest.fail(f"{SO_PATH} not found — run `make` first")
    lib = ctypes.CDLL(str(SO_PATH))

    # ctypes doesn't read the header, so we have to tell it what each
    # function expects. Getting argtypes wrong is a common way to
    # cause segfaults, so keep this in sync with rijndael.h.
    lib.sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    lib.sub_bytes.restype = None
    lib.invert_sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    lib.invert_sub_bytes.restype = None

    lib.shift_rows.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    lib.shift_rows.restype = None
    lib.invert_shift_rows.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    lib.invert_shift_rows.restype = None

    lib.mix_columns.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    lib.mix_columns.restype = None
    lib.invert_mix_columns.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    lib.invert_mix_columns.restype = None

    lib.add_round_key.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_int,
    ]
    lib.add_round_key.restype = None

    lib.expand_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    lib.expand_key.restype = ctypes.POINTER(ctypes.c_ubyte)

    lib.aes_encrypt_block.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_int,
    ]
    lib.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

    lib.aes_decrypt_block.argtypes = [
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_int,
    ]
    lib.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

    return lib


@pytest.fixture(scope="session")
def aes_ref():
    return ref_aes


# ---- byte <-> matrix helpers -----------------------------------------------
# boppreh's 4x4 matrix is filled row-by-row from the input bytes:
#   bytes {b0..b15} -> [[b0,b1,b2,b3], [b4,b5,b6,b7], ...]
# That matches how we lay out the block in C, so no transposition needed.

def bytes_to_matrix(data):
    return [list(data[i:i + 4]) for i in range(0, 16, 4)]


def matrix_to_bytes(matrix):
    # Works whether each row is a list or a bytes object — iterating over
    # either gives integers. boppreh's key expansion returns a mix, which
    # broke the old sum-based flatten.
    return bytes(b for row in matrix for b in row)


def to_c_buffer(data):
    """Wrap 16 bytes in a ctypes array so it can be passed to C by pointer."""
    return (ctypes.c_ubyte * 16)(*data)
