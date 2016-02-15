import unittest
import sys

from decred.core.script import opcode, scriptbuilder
from decred.core.script.constants import maxScriptSize
from decred.core.script.errors import *
from decred.core.script.scriptnum import num2bytearray

_bchr = chr
if sys.version > '3':
    _bchr = lambda x: bytes([x])

# ByteArray
BA = lambda items: b''.join(map(_bchr, items))

class ScriptBuilderTest(unittest.TestCase):
    def test_add_op(self):
        tests = (
            ('push OP_0', [opcode.OP_0], b'\x00'),
            ('push OP_1 OP_2', [opcode.OP_1, opcode.OP_2], b'QR'),
            ('push OP_HASH160 OP_EQUAL', [opcode.OP_HASH160, opcode.OP_EQUAL], b'\xa9\x87'),
        )

        builder = scriptbuilder.ScriptBuilder()
        for name, opcodes, expected in tests:
            builder.Reset()
            for op in opcodes:
                builder.AddOp(op)
            result, err = builder.Script()
            self.assertIs(None, err)
            self.assertEqual(expected, result)

    def test_add_int_64(self):
        tests = (
            ("push -1", -1, BA([opcode.OP_1NEGATE])),
            ("push small int 0", 0, BA([opcode.OP_0])),
            ("push small int 1", 1, BA([opcode.OP_1])),
            ("push small int 2", 2, BA([opcode.OP_2])),
            ("push small int 3", 3, BA([opcode.OP_3])),
            ("push small int 4", 4, BA([opcode.OP_4])),
            ("push small int 5", 5, BA([opcode.OP_5])),
            ("push small int 6", 6, BA([opcode.OP_6])),
            ("push small int 7", 7, BA([opcode.OP_7])),
            ("push small int 8", 8, BA([opcode.OP_8])),
            ("push small int 9", 9, BA([opcode.OP_9])),
            ("push small int 10", 10, BA([opcode.OP_10])),
            ("push small int 11", 11, BA([opcode.OP_11])),
            ("push small int 12", 12, BA([opcode.OP_12])),
            ("push small int 13", 13, BA([opcode.OP_13])),
            ("push small int 14", 14, BA([opcode.OP_14])),
            ("push small int 15", 15, BA([opcode.OP_15])),
            ("push small int 16", 16, BA([opcode.OP_16])),
            ("push 17", 17, BA([opcode.OP_DATA_1, 0x11])),
            ("push 65", 65, BA([opcode.OP_DATA_1, 0x41])),
            ("push 127", 127, BA([opcode.OP_DATA_1, 0x7f])),
            ("push 128", 128, BA([opcode.OP_DATA_2, 0x80, 0])),
            ("push 255", 255, BA([opcode.OP_DATA_2, 0xff, 0])),
            ("push 256", 256, BA([opcode.OP_DATA_2, 0, 0x01])),
            ("push 32767", 32767, BA([opcode.OP_DATA_2, 0xff, 0x7f])),
            ("push 32768", 32768, BA([opcode.OP_DATA_3, 0, 0x80, 0])),
            ("push -2", -2, BA([opcode.OP_DATA_1, 0x82])),
            ("push -3", -3, BA([opcode.OP_DATA_1, 0x83])),
            ("push -4", -4, BA([opcode.OP_DATA_1, 0x84])),
            ("push -5", -5, BA([opcode.OP_DATA_1, 0x85])),
            ("push -17", -17, BA([opcode.OP_DATA_1, 0x91])),
            ("push -65", -65, BA([opcode.OP_DATA_1, 0xc1])),
            ("push -127", -127, BA([opcode.OP_DATA_1, 0xff])),
            ("push -128", -128, BA([opcode.OP_DATA_2, 0x80, 0x80])),
            ("push -255", -255, BA([opcode.OP_DATA_2, 0xff, 0x80])),
            ("push -256", -256, BA([opcode.OP_DATA_2, 0x00, 0x81])),
            ("push -32767", -32767, BA([opcode.OP_DATA_2, 0xff, 0xff])),
            ("push -32768", -32768, BA([opcode.OP_DATA_3, 0x00, 0x80, 0x80])),
        )

        builder = scriptbuilder.ScriptBuilder()
        for name, val, expected in tests:
            builder.Reset().AddInt64(val)
            result, err = builder.Script()
            self.assertIs(None, err)
            self.assertEqual(expected, result)

    def test_add_data(self):
        tests = (

            # BIP0062: Pushing an empty byte sequence must use OP_0.
            ("push empty byte sequence", b'', BA([opcode.OP_0]), False),
            ("push 1 byte 0x00", BA([0x00]), BA([opcode.OP_0]), False),

            # BIP0062: Pushing a 1-byte sequence of byte 0x01 through 0x10 must use OP_n.
            ("push 1 byte 0x01", BA([0x01]), BA([opcode.OP_1]), False),
            ("push 1 byte 0x02", BA([0x02]), BA([opcode.OP_2]), False),
            ("push 1 byte 0x03", BA([0x03]), BA([opcode.OP_3]), False),
            ("push 1 byte 0x04", BA([0x04]), BA([opcode.OP_4]), False),
            ("push 1 byte 0x05", BA([0x05]), BA([opcode.OP_5]), False),
            ("push 1 byte 0x06", BA([0x06]), BA([opcode.OP_6]), False),
            ("push 1 byte 0x07", BA([0x07]), BA([opcode.OP_7]), False),
            ("push 1 byte 0x08", BA([0x08]), BA([opcode.OP_8]), False),
            ("push 1 byte 0x09", BA([0x09]), BA([opcode.OP_9]), False),
            ("push 1 byte 0x0a", BA([0x0a]), BA([opcode.OP_10]), False),
            ("push 1 byte 0x0b", BA([0x0b]), BA([opcode.OP_11]), False),
            ("push 1 byte 0x0c", BA([0x0c]), BA([opcode.OP_12]), False),
            ("push 1 byte 0x0d", BA([0x0d]), BA([opcode.OP_13]), False),
            ("push 1 byte 0x0e", BA([0x0e]), BA([opcode.OP_14]), False),
            ("push 1 byte 0x0f", BA([0x0f]), BA([opcode.OP_15]), False),
            ("push 1 byte 0x10", BA([0x10]), BA([opcode.OP_16]), False),

            # BIP0062: Pushing the byte 0x81 must use OP_1NEGATE.
            ("push 1 byte 0x81", BA([0x81]), BA([opcode.OP_1NEGATE]), False),

            # BIP0062: Pushing any other byte sequence up to 75 bytes must
            # use the normal data push (opcode byte n, with n the number of
            # bytes, followed n bytes of data being pushed).
            ("push 1 byte 0x11", BA([0x11]), BA([opcode.OP_DATA_1, 0x11]), False),
            ("push 1 byte 0x80", BA([0x80]), BA([opcode.OP_DATA_1, 0x80]), False),
            ("push 1 byte 0x82", BA([0x82]), BA([opcode.OP_DATA_1, 0x82]), False),
            ("push 1 byte 0xff", BA([0xff]), BA([opcode.OP_DATA_1, 0xff]), False),
            (
                    "push data len 17",
                    BA([0x49] * 17),
                    BA([opcode.OP_DATA_17]) + BA([0x49] * 17),
                    False
            ),
            (
                    "push data len 75",
                    BA([0x49] * 75),
                    BA([opcode.OP_DATA_75]) + BA([0x49] * 75),
                    False
            ),
            # BIP0062: Pushing 76 to 255 bytes must use OP_PUSHDATA1.
            (
                    "push data len 76",
                    BA([0x49] * 76),
                    BA([opcode.OP_PUSHDATA1, 76]) + BA([0x49] * 76),
                    False
            ),
            (
                    "push data len 255",
                    BA([0x49] * 255),
                    BA([opcode.OP_PUSHDATA1, 255]) + BA([0x49] * 255),
                    False
            ),

            # BIP0062: Pushing 256 to 520 bytes must use OP_PUSHDATA2.
            (
                    "push data len 256",
                    BA([0x49] * 256),
                    BA([opcode.OP_PUSHDATA2, 0, 1]) + BA([0x49] * 256),
                    False
            ),
            (
                    "push data len 520",
                    BA([0x49] * 520),
                    BA([opcode.OP_PUSHDATA2, 0x08, 0x02]) + BA([0x49] * 520),
                    False
            ),

            # BIP0062: OP_PUSHDATA4 can never be used, as pushes over 520
            # bytes are not allowed, and those below can be done using
            # other operators.
            (
                    "push data len 521",
                    BA([0x49] * 4097),
                    b'',
                    False
            ),
            (
                    "push data len 32767 (canonical)",
                    BA([0x49] * 32767),
                    b'',
                    False
            ),
            (
                    "push data len 65536 (canonical)",
                    BA([0x49] * 65536),
                    b'',
                    False
            ),
            # Additional tests for the PushFullData function that
            # intentionally allows data pushes to exceed the limit for
            # regression testing purposes.

            # 3-byte data push via OP_PUSHDATA_2.
            (
                    "push data len 32767 (non-canonical)",
                    BA([0x49] * 32767),
                    BA([opcode.OP_PUSHDATA2, 255, 127]) + BA([0x49] * 32767),
                    True
            ),

            # 5-byte data push via OP_PUSHDATA_4.
            (
                    "push data len 65536 (non-canonical)",
                    BA([0x49] * 65536),
                    BA([opcode.OP_PUSHDATA4, 0, 0, 1, 0]) + BA([0x49] * 65536),
                    True
            ),

        )

        builder = scriptbuilder.ScriptBuilder()
        for name, data, expected, use_full in tests:
            builder.Reset()
            if not use_full:
                builder.AddData(data)
            else:
                builder.AddFullData(data)

            if expected == b'':
                self.assertRaises(Exception, builder.Script, True)
            else:
                result, err = builder.Script()
                self.assertIs(None, err)
                self.assertEqual(expected, result)

    def test_exceed_max_script_size(self):
        # Construct a max-size script.
        builder = scriptbuilder.ScriptBuilder()
        builder.Reset().AddFullData(b'\x00' * (maxScriptSize - 3))
        orig_script, err = builder.Script()
        self.assertIs(None, err)

        # Ensure adding data that would exceed maximum size does not work.
        script, err = builder.AddData(b'\x00').Script()
        self.assertIsInstance(err, scriptbuilder.ScriptNonCanonicalError)
        self.assertEqual(script, orig_script)

        # Ensure adding an opcode that would exceed maximum size does not work.
        builder.Reset().AddFullData(b'\x00' * (maxScriptSize - 3))
        script, err = builder.AddOp(opcode.OP_0).Script()
        self.assertIsInstance(err, scriptbuilder.ScriptNonCanonicalError)
        self.assertEqual(script, orig_script)

        # Ensure adding an integer that would exceed maximum size does not work.
        builder.Reset().AddFullData(b'\x00' * (maxScriptSize - 3))
        script, err = builder.AddInt64(0).Script()
        self.assertIsInstance(err, scriptbuilder.ScriptNonCanonicalError)
        self.assertEqual(script, orig_script)

    def test_errored_script(self):
        builder = scriptbuilder.ScriptBuilder()
        builder.Reset().AddFullData(b'\x00' * (maxScriptSize - 8))
        orig_script, err = builder.Script()
        self.assertIs(None, err)

        script, err = builder.AddData(b'\x00' * 5).Script()
        self.assertIsInstance(err, scriptbuilder.ScriptNonCanonicalError)
        self.assertEqual(script, orig_script)

        # Ensure adding data using the non-canonical path to a script that has errored doesn't succeed.
        script, err = builder.AddFullData(b'\x00').Script()
        self.assertIsInstance(err, scriptbuilder.ScriptNonCanonicalError)
        self.assertEqual(script, orig_script)

        # Ensure adding data to a script that has errored doesn't succeed.
        script, err = builder.AddData(b'\x00').Script()
        self.assertIsInstance(err, scriptbuilder.ScriptNonCanonicalError)
        self.assertEqual(script, orig_script)

        # Ensure adding an opcode to a script that has errored doesn't succeed.
        script, err = builder.AddOp(opcode.OP_0).Script()
        self.assertIsInstance(err, scriptbuilder.ScriptNonCanonicalError)
        self.assertEqual(script, orig_script)

        # Ensure adding an integer to a script that has errored doesn't succeed.
        script, err = builder.AddInt64(0).Script()
        self.assertIsInstance(err, scriptbuilder.ScriptNonCanonicalError)
        self.assertEqual(script, orig_script)

        # Ensure the error has a message set.
        self.assertNotEqual('', err.message)
