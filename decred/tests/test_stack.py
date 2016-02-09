import unittest
from collections import namedtuple

from decred.core.script import stack
from decred.core.script.scriptnum import num2bytearray, math_op_code_max_script_num_len

# Byteify
def B(numbers):
    return map(num2bytearray, numbers)

# name: Test name.
# before: Stack state before test.
# operation: Function to perform.
# error: Expected error (or False if no error is expected).
# after: Expected stack state after test (or None if an error is expected).
TestItem = namedtuple('TestItem', ('name', 'before', 'operation', 'error', 'after'))

def _pop_test(tester, s, expected):
    val = s.pop_bytearray()
    tester.assertEqual(expected, val)

class StackTest(unittest.TestCase):
    def _pop_test(self, s):
        val = s.pop_bytearray()
        self.assertEqual(b'\x05', val)

    def _pop_everything_test(self, s):
        for i in range(0, 5):
            _ = s.pop_bytearray()

    def _pop_underflow_test(self, s):
        for i in range(0, 6):
            _ = s.pop_bytearray()

    def _pop_bool_test(self, s, is_truthy):
        val = s.pop_bool()
        if is_truthy:
            self.assertTrue(val)
        else:
            self.assertFalse(val)

    def _pop_int_test(self, s, expected_value):
        val = s.pop_int(math_op_code_max_script_num_len)
        self.assertEqual(expected_value, val)

    def _peek_int_test(self, s, expected_value):
        val = s.peek_int(0)
        self.assertEqual(expected_value, val)

    def _push_int(self, s, pushvalue):
        s.push_int(pushvalue)

    def _push_pop_bool(self, s, pushvalue, expected):
        s.push_bool(pushvalue)
        val = s.pop_bool()
        self.assertEqual(expected, val)

    def _push_int_pop_bool(self, s, pushvalue, expected):
        s.push_int(pushvalue)
        val = s.pop_bool()
        self.assertEqual(expected, val)

    def _peek_bool(self, s, idx, expected):
        val = s.peek_bool(idx)
        self.assertEqual(expected, val)

    def _peek_int(self, s, idx, expected):
        val = s.peek_int(idx)
        self.assertEqual(expected, val)

    def _push_int_pop_int(self, s, pushvalue, expected):
        s.push_int(pushvalue)
        val = s.pop_int(math_op_code_max_script_num_len)
        self.assertEqual(expected, val)

    def test_stack(self):
        test_items = (
            TestItem('noop', B([1,2,3,4,5]), lambda s: None, False, B([1,2,3,4,5])),
            TestItem('peek underflow (byte)', B([1,2,3,4,5]), lambda s: s.peek_bytearray(5), stack.StackUnderflowError, None),
            TestItem('peek underflow (int)', B([1,2,3,4,5]), lambda s: s.peek_int(5), stack.StackUnderflowError, None),
            TestItem('peek underflow (bool)', B([1,2,3,4,5]), lambda s: s.peek_bool(5), stack.StackUnderflowError, None),
            TestItem('pop', B([1,2,3,4,5]), lambda s: self._pop_test(s), False, B([1,2,3,4])),
            TestItem('pop everything', B([1,2,3,4,5]), lambda s: self._pop_everything_test(s), False, []),
            TestItem('pop underflow', B([1,2,3,4,5]), lambda s: self._pop_underflow_test(s), stack.StackUnderflowError, None),
            TestItem('pop bool', B([0]), lambda s: self._pop_bool_test(s, False), False, []),
            TestItem('pop bool', B([1]), lambda s: self._pop_bool_test(s, True), False, []),
            TestItem('pop underflow (bool)', [], lambda s: s.pop_bool(), stack.StackUnderflowError, None),
            TestItem('pop int 0', B([0]), lambda s: self._pop_int_test(s, 0), False, []),
            TestItem('pop int -0', [b'\x80'], lambda s: self._pop_int_test(s, 0), False, []),
            TestItem('pop int 1', B([1]), lambda s: self._pop_int_test(s, 1), False, []),
            TestItem('pop int 1 leading 0', [b'\x01\x00\x00\x00'], lambda s: self._pop_int_test(s, 1), False, []),
            TestItem('pop int -1', [b'\x81'], lambda s: self._pop_int_test(s, -1), False, []),
            TestItem('pop int -1 leading 0', [b'\x01\x00\x00\x80'], lambda s: self._pop_int_test(s, -1), False, []),
            # Triggers the multibyte case in asInt.
            TestItem('pop int -513', [b'\x01\x82'], lambda s: self._pop_int_test(s, -513), False, []),

            TestItem('peekint nomodify -1', [b'\x01\x00\x00\x80'], lambda s: self._peek_int_test(s, -1), False, [b'\x01\x00\x00\x80']),

            TestItem('push int 0', [], lambda s: self._push_int(s, 0), False, [b'']),
            TestItem('push int 1', [], lambda s: self._push_int(s, 1), False, B([1])),
            TestItem('push int -1', [], lambda s: self._push_int(s, -1), False, B([-1])),
            TestItem('push int two bytes', [], lambda s: self._push_int(s, 256), False, [b'\x00\x01']),
            TestItem('push int leading zeros', [], lambda s: self._push_int(s, 128), False, [b'\x80\x00']),

            TestItem('dup', B([1]), lambda s: s.dup(1), False, B([1, 1])),
            TestItem('dup 2', B([1, 2]), lambda s: s.dup(2), False, B([1, 2, 1, 2])),
            TestItem('dup 3', B([1, 2, 3]), lambda s: s.dup(3), False, B([1, 2, 3, 1, 2, 3])),
            TestItem('dup 0', B([1]), lambda s: s.dup(0), stack.StackInvalidArgsError, None),
            TestItem('dup -1', B([1]), lambda s: s.dup(-1), stack.StackInvalidArgsError, None),
            TestItem('dup too much', B([1]), lambda s: s.dup(2), stack.StackUnderflowError, None),

            TestItem('push bool true', [], lambda s: s.push_bool(True), False, B([1])),
            TestItem('push bool false', [], lambda s: s.push_bool(False), False, [b'\x00']),
            TestItem('push bool pop bool', [], lambda s: self._push_pop_bool(s, True, True), False, []),
            TestItem('push bool pop bool 2', [], lambda s: self._push_pop_bool(s, False, False), False, []),
            TestItem('push int pop bool', [], lambda s: self._push_int_pop_bool(s, 1, True), False, []),
            TestItem('push int pop bool 2', [], lambda s: self._push_int_pop_bool(s, 0, False), False, []),

            TestItem('nip top', B([1, 2, 3]), lambda s: s.nip(0), False, B([1, 2])),
            TestItem('nip middle', B([1, 2, 3]), lambda s: s.nip(1), False, B([1, 3])),
            TestItem('nip low', B([1, 2, 3]), lambda s: s.nip(2), False, B([2, 3])),
            TestItem('nip too much', B([1, 2, 3]), lambda s: s.nip(3), stack.StackUnderflowError, None),

            TestItem('keep on tucking', B([1, 2, 3]), lambda s: s.tuck(), False, B([1, 3, 2, 3])),
            TestItem('a little tucked up', B([1]), lambda s: s.tuck(), stack.StackUnderflowError, None),
            TestItem('all tucked up', [], lambda s: s.tuck(), stack.StackUnderflowError, None),

            TestItem('drop 1', B([1, 2, 3, 4]), lambda s: s.drop(1), False, B([1, 2, 3])),
            TestItem('drop 2', B([1, 2, 3, 4]), lambda s: s.drop(2), False, B([1, 2])),
            TestItem('drop 3', B([1, 2, 3, 4]), lambda s: s.drop(3), False, B([1])),
            TestItem('drop 4', B([1, 2, 3, 4]), lambda s: s.drop(4), False, []),
            TestItem('drop 4/5', B([1, 2, 3, 4]), lambda s: s.drop(5), stack.StackUnderflowError, None),
            TestItem('drop invalid', B([1, 2, 3, 4]), lambda s: s.drop(0), stack.StackInvalidArgsError, None),

            TestItem('rot 1', B([1, 2, 3, 4]), lambda s: s.rot(1), False, B([1, 3, 4, 2])),
            TestItem('rot 2', B([1, 2, 3, 4, 5, 6]), lambda s: s.rot(2), False, B([3, 4, 5, 6, 1, 2])),
            TestItem('rot too little', B([1, 2]), lambda s: s.rot(1), stack.StackUnderflowError, None),
            TestItem('rot 0', B([1, 2, 3]), lambda s: s.rot(0), stack.StackInvalidArgsError, None),

            TestItem('swap 1', B([1, 2, 3, 4]), lambda s: s.swap(1), False, B([1, 2, 4, 3])),
            TestItem('swap 2', B([1, 2, 3, 4]), lambda s: s.swap(2), False, B([3, 4, 1, 2])),
            TestItem('swap too little', B([1]), lambda s: s.swap(1), stack.StackUnderflowError, None),
            TestItem('swap 0', B([1, 2, 3]), lambda s: s.swap(0), stack.StackInvalidArgsError, None),

            TestItem('over 1', B([1, 2, 3, 4]), lambda s: s.over(1), False, B([1, 2, 3, 4, 3])),
            TestItem('over 2', B([1, 2, 3, 4]), lambda s: s.over(2), False, B([1, 2, 3, 4, 1, 2])),
            TestItem('over too little', B([1]), lambda s: s.over(1), stack.StackUnderflowError, None),
            TestItem('over 0', B([1, 2, 3]), lambda s: s.over(0), stack.StackInvalidArgsError, None),

            TestItem('pick 1', B([1, 2, 3, 4]), lambda s: s.pick(1), False, B([1, 2, 3, 4, 3])),
            TestItem('pick 2', B([1, 2, 3, 4]), lambda s: s.pick(2), False, B([1, 2, 3, 4, 2])),
            TestItem('pick too little', B([1]), lambda s: s.pick(1), stack.StackUnderflowError, None),

            TestItem('roll 1', B([1, 2, 3, 4]), lambda s: s.roll(1), False, B([1, 2, 4, 3])),
            TestItem('roll 2', B([1, 2, 3, 4]), lambda s: s.roll(2), False, B([1, 3, 4, 2])),
            TestItem('roll too little', B([1]), lambda s: s.roll(1), stack.StackUnderflowError, None),

            TestItem('peek bool', B([1]), lambda s: self._peek_bool(s, 0, True), False, B([1])),
            TestItem('peek bool 2', B([0]), lambda s: self._peek_bool(s, 0, False), False, B([0])),
            TestItem('peek int', B([1]), lambda s: self._peek_int(s, 0, 1), False, B([1])),
            TestItem('peek int 2', B([0]), lambda s: self._peek_int(s, 0, 0), False, B([0])),

            TestItem('push int pop int', [], lambda s: self._push_int_pop_int(s, 1, 1), False, []),
            TestItem('pop empty', [], lambda s: s.pop_int(math_op_code_max_script_num_len), stack.StackUnderflowError, None),
        )

        for test_item in test_items:
            s = stack.Stack()
            for i in test_item.before:
                s.push_bytearray(i)
            if test_item.error:
                self.assertRaises(test_item.error, test_item.operation, s)
            else:
                test_item.operation(s)

                self.assertEqual(len(test_item.after), s.depth())
                for i, v in enumerate(test_item.after):
                    actual = s.peek_bytearray(s.depth() - i - 1)
                    self.assertEqual(actual, v)
