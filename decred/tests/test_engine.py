import unittest
import sys

from bitcoin.core import x, b2x

from decred.core.script.engine import *
from decred.core.script.opcode import *
from decred.core.script.errors import *
from decred.core.script.scriptbuilder import ScriptBuilder
from decred.core.script.standard import StandardVerifyFlags
from decred.core.transaction import *

_bchr = chr
if sys.version > '3':
    _bchr = lambda x: bytes([x])

decodeHex = x

class DecredEngineTest(unittest.TestCase):
    """Unit tests from Decred."""
    def test_bad_pc(self):
        """Sets the pc to a deliberately bad result then confirms that step() and disasm fail."""
        pc_tests = (
            (2, 0),
            (0, 2),
        )
        # tx with almost empty scripts
        prevout = OutPoint(hash=x('c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704'), index=0)
        txin = TxIn(prev_out=prevout, sig_script=_bchr(OP_NOP), sequence=4294967295)
        txout = TxOut(value=1000000000)
        tx = Transaction(txins=(txin,), txouts=(txout,), locktime=0)

        pk_script = _bchr(OP_NOP)
        for t_script, t_off in pc_tests:
            vm = Engine(pk_script, tx, 0, 0, 0)
            vm.script_idx = t_script
            vm.script_off = t_off

            self.assertRaises(Exception, vm.step)
            self.assertRaises(Exception, vm.disasm_pc)

    def test_check_error_condition(self):
        """Tests the execute early test in check_error_condition()."""
        # tx with almost empty scripts
        prevout = OutPoint(hash=x('c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704'), index=0)
        txin = TxIn(prev_out=prevout, sequence=4294967295)
        txout = TxOut(value=1000000000)
        tx = Transaction(version=1, txins=(txin,), txouts=(txout,), locktime=0)

        pk_script = ''.join(map(_bchr, [OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_NOP, OP_TRUE]))
        vm = Engine(pk_script, tx, 0, 0, 0)

        for i in range(len(pk_script)-1):
            done = vm.step()
            self.assertFalse(done)
            self.assertRaises(StackScriptUnfinishedError, vm.check_error_condition, False)

        done = vm.step()
        self.assertTrue(done)
        vm.check_error_condition(False)

    def test_invalid_flag_combinations(self):
        tests = [ScriptVerifyCleanStack]

        prevout = OutPoint(hash=x('c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704'), index=0)
        txin = TxIn(prev_out=prevout, sig_script=_bchr(OP_NOP), sequence=4294967295)
        txout = TxOut(value=1000000000)
        tx = Transaction(version=1, txins=(txin,), txouts=(txout,), locktime=0)

        pk_script = _bchr(OP_NOP)
        for t in tests:
            self.assertRaises(InvalidFlagsError, Engine, pk_script, tx, 0, t, 0)

    def test_check_pub_key_encoding(self):
        tests = (
            (
                    "uncompressed ok",
                    x("0411db93e1dcdb8a016b49840f8c53bc1eb68" +
                            "a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf" +
                            "9744464f82e160bfa9b8b64f9d4c03f999b8643f656b" +
                            "412a3"),
                    True,
            ),
            (
                    "compressed ok",
                    x("02ce0b14fb842b1ba549fdd675c98075f12e9" +
                            "c510f8ef52bd021a9a1f4809d3b4d"),
                    True,
            ),
            (
                    "compressed ok",
                    x("032689c7c2dab13309fb143e0e8fe39634252" +
                            "1887e976690b6b47f5b2a4b7d448e"),
                    True,
            ),
            (
                    "hybrid",
                    x("0679be667ef9dcbbac55a06295ce870b07029" +
                            "bfcdb2dce28d959f2815b16f81798483ada7726a3c46" +
                            "55da4fbfc0e1108a8fd17b448a68554199c47d08ffb1" +
                            "0d4b8"),
                    False,
            ),
            (
                    "empty",
                    b'',
                    False,
            ),
        )

        flags = ScriptVerifyStrictEncoding
        for name, key, is_valid in tests:
            vm = Engine(_bchr(OP_NOP), Transaction(txins=(TxIn(),)), 0, flags, 0)
            if not is_valid:
                self.assertRaises(Exception, vm.check_pubkey_encoding, key)
            else:
                vm.check_pubkey_encoding(key)

    def test_check_signature_encoding(self):
        tests = (

                (
                        "valid signature",
                        decodeHex("304402204e45e16932b8af514961a1d3a1a25" +
                                "fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
                                "2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
                                "82221a8768d1d09"),
                        True,
                ),
                (
                           "empty.",
                            b'',
                        False,
                ),
                (
                        "bad magic",
                        decodeHex("314402204e45e16932b8af514961a1d3a1a25" +
                                "fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
                                "2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
                                "82221a8768d1d09"),
                        False,
                ),
                (
                        "bad 1st int marker magic",
                        decodeHex("304403204e45e16932b8af514961a1d3a1a25" +
                                "fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
                                "2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
                                "82221a8768d1d09"),
                        False,
                ),
                (
                        "bad 2nd int marker",
                        decodeHex("304402204e45e16932b8af514961a1d3a1a25" +
                                "fdf3f4f7732e9d624c6c61548ab5fb8cd41032018152" +
                                "2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
                                "82221a8768d1d09"),
                        False,
                ),

                (
                        "short len",
                        decodeHex("304302204e45e16932b8af514961a1d3a1a25" +
                                "fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
                                "2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
                                "82221a8768d1d09"),
                        False,
                ),
                (
                        "long len",
                        decodeHex("304502204e45e16932b8af514961a1d3a1a25" +
                                "fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
                                "2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
                                "82221a8768d1d09"),
                        False,
                ),
                (
                        "long X",
                        decodeHex("304402424e45e16932b8af514961a1d3a1a25" +
                                "fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
                                "2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
                                "82221a8768d1d09"),
                        False,
                ),

                (
                        "long Y",
                        decodeHex("304402204e45e16932b8af514961a1d3a1a25" +
                                "fdf3f4f7732e9d624c6c61548ab5fb8cd41022118152" +
                                "2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
                                "82221a8768d1d09"),
                        False,
                ),
                (
                        "short Y",
                        decodeHex("304402204e45e16932b8af514961a1d3a1a25" +
                                "fdf3f4f7732e9d624c6c61548ab5fb8cd41021918152" +
                                "2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
                                "82221a8768d1d09"),
                        False,
                ),
                (
                        "trailing crap",
                        decodeHex("304402204e45e16932b8af514961a1d3a1a25" +
                                "fdf3f4f7732e9d624c6c61548ab5fb8cd41022018152" +
                                "2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
                                "82221a8768d1d0901"),
                        False,
                ),

                (
                        "X == N ",
                        decodeHex("30440220fffffffffffffffffffffffffffff" +
                                "ffebaaedce6af48a03bbfd25e8cd0364141022018152" +
                                "2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
                                "82221a8768d1d09"),
                        False,
                ),
                (
                        "X == N ",
                        decodeHex("30440220fffffffffffffffffffffffffffff" +
                                "ffebaaedce6af48a03bbfd25e8cd0364142022018152" +
                                "2ec8eca07de4860a4acdd12909d831cc56cbbac46220" +
                                "82221a8768d1d09"),
                        False,
                ),
                (
                        "Y == N",
                        decodeHex("304402204e45e16932b8af514961a1d3a1a25" +
                                "fdf3f4f7732e9d624c6c61548ab5fb8cd410220fffff" +
                                "ffffffffffffffffffffffffffebaaedce6af48a03bb" +
                                "fd25e8cd0364141"),
                        False,
                ),

                (
                        "Y > N",
                        decodeHex("304402204e45e16932b8af514961a1d3a1a25" +
                                "fdf3f4f7732e9d624c6c61548ab5fb8cd410220fffff" +
                                "ffffffffffffffffffffffffffebaaedce6af48a03bb" +
                                "fd25e8cd0364142"),
                        False,
                ),
                (
                        "0 len X",
                        decodeHex("302402000220181522ec8eca07de4860a4acd" +
                                "d12909d831cc56cbbac4622082221a8768d1d09"),
                        False,
                ),
                (
                        "0 len Y",
                        decodeHex("302402204e45e16932b8af514961a1d3a1a25" +
                                "fdf3f4f7732e9d624c6c61548ab5fb8cd410200"),
                        False,
                ),
                (
                        "extra R padding",
                        decodeHex("30450221004e45e16932b8af514961a1d3a1a" +
                                "25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181" +
                                "522ec8eca07de4860a4acdd12909d831cc56cbbac462" +
                                "2082221a8768d1d09"),
                        False,
                ),

                (
                        "extra S padding",
                        decodeHex("304502204e45e16932b8af514961a1d3a1a25" +
                                "fdf3f4f7732e9d624c6c61548ab5fb8cd41022100181" +
                                "522ec8eca07de4860a4acdd12909d831cc56cbbac462" +
                                "2082221a8768d1d09"),
                        False,
                ),


        )

        flags = ScriptVerifyStrictEncoding
        for name, sig, is_valid in tests:
            vm = Engine(_bchr(OP_NOP), Transaction(txins=(TxIn(),)), 0, flags, 0)
            if not is_valid:
                self.assertRaises(Exception, vm.check_signature_encoding, sig)
            else:
                vm.check_signature_encoding(sig)

class EngineTest(unittest.TestCase):
    def test_step(self):
        tx = Transaction(txins=(TxIn(),))

        pk_script = b'\x53\x52\x76\x93\x54\x87'
        vm = Engine(pk_script, tx, 0, StandardVerifyFlags, 0)
        # Non-verbose disasm.
        self.assertEqual('OP_3 OP_2 OP_DUP OP_ADD OP_4 OP_EQUAL', vm.disasm_script(1, verbose=False).replace('\n',' ').strip())

        steps = [
            (b'\x03', '01:0000: OP_3'),
            (b'\x03\x02', '01:0001: OP_2'),
            (b'\x03\x02\x02', '01:0002: OP_DUP'),
            (b'\x03\x04', '01:0003: OP_ADD'),
            (b'\x03\x04\x04', '01:0004: OP_4'),
            (b'\x03\x01', '01:0005: OP_EQUAL')
        ]
        for step_stack, disasm in steps:
            self.assertEqual(disasm, vm.disasm_pc())
            vm.step()
            self.assertEqual(step_stack, vm.get_stack())

    def test_conditionals(self):
        tx = Transaction(txins=(TxIn(),))
        pk_script = b''.join([
            b'\x51', # OP_1
            b'\x63', # OP_IF
            b'\x01\x62', # 0x62
            b'\x67', # OP_ELSE
            b'\x01\x63', # 0x63
            b'\x68'  # OP_ENDIF
        ])
        vm = Engine(pk_script, tx, 0, StandardVerifyFlags, 0)
        self.assertEqual('OP_1 OP_IF OP_DATA_1 0x62 OP_ELSE OP_DATA_1 0x63 OP_ENDIF', vm.disasm_script(1, verbose=False).replace('\n', ' ').strip())

        steps = [
            (b'\x01', '01:0000: OP_1'),
            (b'', '01:0001: OP_IF'),
            (b'\x62', '01:0002: OP_DATA_1 0x62'),
            (b'\x62', '01:0003: OP_ELSE'),
            (b'\x62', '01:0004: OP_DATA_1 0x63'),
            (b'\x62', '01:0005: OP_ENDIF')
        ]
        for step_stack, disasm in steps:
            self.assertEqual(disasm, vm.disasm_pc())
            vm.step()
            self.assertEqual(step_stack, vm.get_stack())

    def test_arithmetic(self):
        tx = Transaction(txins=(TxIn(),))
        builder = ScriptBuilder()

        tests = [
            ('multiplication',
            lambda b: b.AddInt64(64).AddOp(OP_2).AddOp(OP_MUL).get_script(),
            128,
            ),
            ('division',
            lambda b: b.AddInt64(100).AddInt64(50).AddOp(OP_DIV).get_script(),
            2,
            ),
            ('addition',
            lambda b: b.AddInt64(100).AddOp(OP_1).AddOp(OP_ADD).get_script(),
            101,
            ),
            ('addition 2',
            lambda b: b.AddData(b'').AddOp(OP_2).AddOp(OP_ADD).get_script(),
            2,
            ),
            ('subtraction',
            lambda b: b.AddInt64(100).AddOp(OP_1).AddOp(OP_SUB).get_script(),
            99,
            )
        ]

        for name, func, expected in tests:
            builder.Reset()
            s = func(builder)
            vm = Engine(s, tx, 0, StandardVerifyFlags, 0)
            vm.execute()
            self.assertEqual(expected, vm.dstack.peek_int(0), '%s: expected %d, got %d' % (name, expected, vm.dstack.peek_int(0)))

    def test_bitwise_operations(self):
        tx = Transaction(txins=(TxIn(),))
        builder = ScriptBuilder()

        tests = [
            ('left shift',
            lambda b: b.AddOp(OP_1).AddOp(OP_8).AddOp(OP_LSHIFT).get_script(),
            256,
            ),
            ('right shift',
            lambda b: b.AddInt64(256).AddOp(OP_8).AddOp(OP_RSHIFT).get_script(),
            1,
            ),
            ('invert',
            lambda b: b.AddOp(OP_12).AddOp(OP_INVERT).get_script(),
            -13,
            ),
            ('and',
            lambda b: b.AddOp(OP_12).AddOp(OP_10).AddOp(OP_AND).get_script(),
            8,
            ),
            ('or',
            lambda b: b.AddOp(OP_12).AddOp(OP_10).AddOp(OP_OR).get_script(),
            14,
            ),
            ('xor',
            lambda b: b.AddOp(OP_12).AddOp(OP_10).AddOp(OP_XOR).get_script(),
            6,
            )
        ]

        for name, func, expected in tests:
            builder.Reset()
            s = func(builder)
            vm = Engine(s, tx, 0, StandardVerifyFlags, 0)
            vm.execute()
            self.assertEqual(expected, vm.dstack.peek_int(0), '%s: expected %d, got %d' % (name, expected, vm.dstack.peek_int(0)))

