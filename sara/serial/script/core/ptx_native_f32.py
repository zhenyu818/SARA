"""Chosen CPU-simulator binary32 FMA, including its raw quiet-NaN payload.

C99 fmaf rounds once to binary32. Neither Python a*b+c nor binary64 math.fma
followed by a float32 conversion implements that contract in general. This
backend is deliberately tied to the pinned little-endian glibc CPU image; it
makes no physical-GPU NaN-payload claim. Only instruction-local evaluation is
performed, never program-origin replay.
"""
import ctypes
from functools import lru_cache
import struct
import sys


@lru_cache(maxsize=1)
def binding():
    if sys.byteorder != 'little':
        raise RuntimeError('the recorded CPU binary32 backend requires little endian')
    library = ctypes.CDLL('libm.so.6')
    function = library.fmaf
    function.argtypes = [ctypes.c_float, ctypes.c_float, ctypes.c_float]
    function.restype = ctypes.c_float
    rounding = library.fegetround
    rounding.argtypes = []
    rounding.restype = ctypes.c_int
    setting = library.fesetround
    setting.argtypes = [ctypes.c_int]
    setting.restype = ctypes.c_int
    return library, function, rounding, setting


def fma_rn_f32(a, b, c):
    library, function, rounding, setting = binding()
    if rounding() != 0:  # FE_TONEAREST in the pinned glibc execution image.
        raise RuntimeError('the CPU binary32 backend requires nearest-even rounding')
    # Passing c_float objects preserves raw input payloads in the ABI; reading
    # their .value first would insert an unnecessary binary64 conversion.
    operands = [ctypes.c_float.from_buffer_copy(struct.pack('<I', int(x) & 0xffffffff))
                for x in (a,b,c)]
    result = function(*operands)
    return struct.unpack('<I', struct.pack('<f', result))[0]


def fma_rm_f32(a, b, c):
    """One downward-rounded fmaf in the pinned glibc ABI; restore caller fenv."""
    library, function, rounding, setting = binding()
    previous = rounding()
    if previous != 0:
        raise RuntimeError('the CPU binary32 caller must enter in nearest-even mode')
    operands = [ctypes.c_float.from_buffer_copy(struct.pack('<I', int(x) & 0xffffffff))
                for x in (a,b,c)]
    if setting(0x400) != 0 or rounding() != 0x400:
        raise RuntimeError('cannot select pinned glibc FE_DOWNWARD')
    try:
        result = function(*operands)
    finally:
        if setting(previous) != 0 or rounding() != previous:
            raise RuntimeError('cannot restore binary32 caller rounding mode')
    return struct.unpack('<I', struct.pack('<f', result))[0]
