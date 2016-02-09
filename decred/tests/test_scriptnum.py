import unittest

from decred.core.script import scriptnum

hexToBytes = lambda s: s.decode('hex')

class ScriptnumTest(unittest.TestCase):
    def test_number_to_bytearray(self):
        number_tests = (
            (1, hexToBytes("01")),
            (-1, hexToBytes("81")),
            (127, hexToBytes("7f")),
            (-127, hexToBytes("ff")),
            (128, hexToBytes("8000")),
            (-128, hexToBytes("8080")),
            (129, hexToBytes("8100")),
            (-129, hexToBytes("8180")),
            (256, hexToBytes("0001")),
            (-256, hexToBytes("0081")),
            (32767, hexToBytes("ff7f")),
            (-32767, hexToBytes("ffff")),
            (32768, hexToBytes("008000")),
            (-32768, hexToBytes("008080")),
            (65535, hexToBytes("ffff00")),
            (-65535, hexToBytes("ffff80")),
            (524288, hexToBytes("000008")),
            (-524288, hexToBytes("000088")),
            (7340032, hexToBytes("000070")),
            (-7340032, hexToBytes("0000f0")),

            # Values that are out of range for data that is interpreted as
            # numbers, but are allowed as the result of numeric operations.
            (2147483648, hexToBytes("0000008000")),
            (-2147483648, hexToBytes("0000008080")),
            (2415919104, hexToBytes("0000009000")),
            (-2415919104, hexToBytes("0000009080")),
            (4294967295, hexToBytes("ffffffff00")),
            (-4294967295, hexToBytes("ffffffff80")),
            (4294967296, hexToBytes("0000000001")),
            (-4294967296, hexToBytes("0000000081")),
            (281474976710655, hexToBytes("ffffffffffff00")),
            (-281474976710655, hexToBytes("ffffffffffff80")),
            (72057594037927935, hexToBytes("ffffffffffffff00")),
            (-72057594037927935, hexToBytes("ffffffffffffff80")),
            (9223372036854775807, hexToBytes("ffffffffffffff7f")),
            (-9223372036854775807, hexToBytes("ffffffffffffffff")),
        )

        for num, serialized in number_tests:
            result = scriptnum.num2bytearray(num)
            self.assertEqual(serialized, result)

    def test_create_script_num(self):
        number_tests = (
            # Minimal encoding must reject negative 0.
            (hexToBytes("80"), 0, True, scriptnum.StackMinimalDataError),

            # Minimally encoded valid values with minimal encoding flag.
            # Should not error and return expected integral number.
            (b'', 0, True, False),
            (hexToBytes("01"), 1, True, False),
            (hexToBytes("81"), -1, True, False),
            (hexToBytes("7f"), 127, True, False),
            (hexToBytes("ff"), -127, True, False),
            (hexToBytes("8000"), 128, True, False),
            (hexToBytes("8080"), -128, True, False),
            (hexToBytes("8100"), 129, True, False),
            (hexToBytes("8180"), -129, True, False),
            (hexToBytes("0001"), 256, True, False),
            (hexToBytes("0081"), -256, True, False),
            (hexToBytes("ff7f"), 32767, True, False),
            (hexToBytes("ffff"), -32767, True, False),
            (hexToBytes("008000"), 32768, True, False),
            (hexToBytes("008080"), -32768, True, False),
            (hexToBytes("ffff00"), 65535, True, False),
            (hexToBytes("ffff80"), -65535, True, False),
            (hexToBytes("000008"), 524288, True, False),
            (hexToBytes("000088"), -524288, True, False),
            (hexToBytes("000070"), 7340032, True, False),
            (hexToBytes("0000f0"), -7340032, True, False),
            (hexToBytes("00008000"), 8388608, True, False),
            (hexToBytes("00008080"), -8388608, True, False),
            (hexToBytes("ffffff7f"), 2147483647, True, False),
            (hexToBytes("ffffffff"), -2147483647, True, False),


            # Minimally encoded values that are out of range for data that
            # is interpreted as script numbers with the minimal encoding
            # flag set.  Should error and return 0.
            (hexToBytes("0000008000"), 0, True, scriptnum.StackNumberTooBigError),
            (hexToBytes("0000008080"), 0, True, scriptnum.StackNumberTooBigError),
            (hexToBytes("0000009000"), 0, True, scriptnum.StackNumberTooBigError),
            (hexToBytes("0000009080"), 0, True, scriptnum.StackNumberTooBigError),
            (hexToBytes("ffffffff00"), 0, True, scriptnum.StackNumberTooBigError),
            (hexToBytes("ffffffff80"), 0, True, scriptnum.StackNumberTooBigError),
            (hexToBytes("0000000001"), 0, True, scriptnum.StackNumberTooBigError),
            (hexToBytes("0000000081"), 0, True, scriptnum.StackNumberTooBigError),
            (hexToBytes("ffffffffffff00"), 0, True, scriptnum.StackNumberTooBigError),
            (hexToBytes("ffffffffffff80"), 0, True, scriptnum.StackNumberTooBigError),
            (hexToBytes("ffffffffffffff00"), 0, True, scriptnum.StackNumberTooBigError),
            (hexToBytes("ffffffffffffff80"), 0, True, scriptnum.StackNumberTooBigError),
            (hexToBytes("ffffffffffffff7f"), 0, True, scriptnum.StackNumberTooBigError),
            (hexToBytes("ffffffffffffffff"), 0, True, scriptnum.StackNumberTooBigError),


            # Non-minimally encoded, but otherwise valid values with
            # minimal encoding flag.  Should error and return 0.
            (hexToBytes("00"), 0, True, scriptnum.StackMinimalDataError),       # 0
            (hexToBytes("0100"), 0, True, scriptnum.StackMinimalDataError),     # 1
            (hexToBytes("7f00"), 0, True, scriptnum.StackMinimalDataError),     # 127
            (hexToBytes("800000"), 0, True, scriptnum.StackMinimalDataError),   # 128
            (hexToBytes("810000"), 0, True, scriptnum.StackMinimalDataError),   # 129
            (hexToBytes("000100"), 0, True, scriptnum.StackMinimalDataError),   # 256
            (hexToBytes("ff7f00"), 0, True, scriptnum.StackMinimalDataError),   # 32767
            (hexToBytes("00800000"), 0, True, scriptnum.StackMinimalDataError), # 32768
            (hexToBytes("ffff0000"), 0, True, scriptnum.StackMinimalDataError), # 65535
            (hexToBytes("00000800"), 0, True, scriptnum.StackMinimalDataError), # 524288
            (hexToBytes("00007000"), 0, True, scriptnum.StackMinimalDataError), # 7340032

            # Non-minimally encoded, but otherwise valid values without
            # minimal encoding flag.  Should not error and return expected
            # integral number.
            (hexToBytes("00"), 0, False, False),
            (hexToBytes("0100"), 1, False, False),
            (hexToBytes("7f00"), 127, False, False),
            (hexToBytes("800000"), 128, False, False),
            (hexToBytes("810000"), 129, False, False),
            (hexToBytes("000100"), 256, False, False),
            (hexToBytes("ff7f00"), 32767, False, False),
            (hexToBytes("00800000"), 32768, False, False),
            (hexToBytes("ffff0000"), 65535, False, False),
            (hexToBytes("00000800"), 524288, False, False),
            (hexToBytes("00007000"), 7340032, False, False),
        )

        for serialized, num, minimal_encoding, exception_type in number_tests:
            if exception_type:
                self.assertRaises(exception_type, scriptnum.script_num, serialized,
                                  minimal_encoding, scriptnum.math_op_code_max_script_num_len)
            else:
                scr_num = scriptnum.script_num(serialized, minimal_encoding, 
                                scriptnum.math_op_code_max_script_num_len)
                self.assertEqual(num, scr_num)


    def test_int_32(self):
        number_tests = (
            # Values inside the valid int32 range are just the values
            # themselves cast to an int32.
            (0, 0),
            (1, 1),
            (-1, -1),
            (127, 127),
            (-127, -127),
            (128, 128),
            (-128, -128),
            (129, 129),
            (-129, -129),
            (256, 256),
            (-256, -256),
            (32767, 32767),
            (-32767, -32767),
            (32768, 32768),
            (-32768, -32768),
            (65535, 65535),
            (-65535, -65535),
            (524288, 524288),
            (-524288, -524288),
            (7340032, 7340032),
            (-7340032, -7340032),
            (8388608, 8388608),
            (-8388608, -8388608),
            (2147483647, 2147483647),
            (-2147483647, -2147483647),
            (-2147483648, -2147483648),

            # Values outside of the valid int32 range are limited to int32.
            (2147483648, 2147483647),
            (-2147483649, -2147483648),
            (1152921504606846975, 2147483647),
            (-1152921504606846975, -2147483648),
            (2305843009213693951, 2147483647),
            (-2305843009213693951, -2147483648),
            (4611686018427387903, 2147483647),
            (-4611686018427387903, -2147483648),
            (9223372036854775807, 2147483647),
            (-9223372036854775808, -2147483648),
        )

        for num, expected in number_tests:
            result = scriptnum.int_32(num)
            self.assertEqual(expected, result)
