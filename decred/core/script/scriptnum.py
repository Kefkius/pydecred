from __future__ import absolute_import
import sys

from bitcoin.core import _bignum

from .errors import *

_bord = ord
if sys.version > '3':
    _bord = lambda x: x

max_int_32 = (1 << 31) - 1
min_int_32 = -1 << 31

# Max number of bytes data being interpreted as an int may be
# for the majority of opcodes.
math_op_code_max_script_num_len = 4
# Max number of bytes for the type of alternative signature suite.
alt_sig_suites_max_script_num_len = 1

def check_minimal_data_encoding(val):
    """Returns whether or not the passed bytearray adheres to the
    minimal encoding requirements."""
    if len(val) == 0:
        return

    # If the most-significant byte (excluding the sign bit) is zero,
    # it's not minimal.
    if _bord(val[-1]) & 0x7f == 0:
        # One exception in which there's more than one byte and the most
        # significant bit of the second-most significant byte is set it would
        # conflict with the sign bit.
        if len(val) == 1 or _bord(val[len(val)-2]) & 0x80 == 0:
            raise StackMinimalDataError()

def int_32(val):
    """Returns the script number clamped to valid int32 values."""
    val = min(val, max_int_32)
    val = max(val, min_int_32)
    return val

def num2bytearray(n):
    """Convert an integer to encoded bytes."""
    return _bignum.bn2vch(n)

def script_num(v, require_minimal=False, script_num_len=math_op_code_max_script_num_len):
    """Convert encoded bytes to an integer."""
    if len(v) > script_num_len:
        raise StackNumberTooBigError()

    if require_minimal:
        check_minimal_data_encoding(v)

    result = _bignum.vch2bn(v)
    return result

