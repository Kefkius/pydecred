from __future__ import absolute_import

from bitcoin.core.scripteval import _CastToBool

from .scriptnum import num2bytearray, script_num, math_op_code_max_script_num_len
from .errors import *

class Stack(object):
    def __init__(self, stack=None, verify_minimal_data=False):
        if stack is None:
            stack = []
        self.stack = stack
        self.verify_minimal_data = verify_minimal_data

    def __str__(self):
        return ' '.join([i.encode('hex') for i in self.stack])

    def depth(self):
        return len(self.stack)

    def push_bytearray(self, val):
        self.stack.append(val)

    def push_int(self, val):
        self.push_bytearray(num2bytearray(val))

    def push_bool(self, val):
        self.push_bytearray(b'\x01' if val else b'\x00')

    def pop_bytearray(self):
        return self.nip(0)

    def pop_int(self, max_len):
        val = self.pop_bytearray()
        return script_num(val, self.verify_minimal_data, max_len)

    def pop_bool(self):
        val = self.pop_bytearray()
        return _CastToBool(val)

    def peek_bytearray(self, idx):
        size = len(self.stack)
        if idx < 0 or idx >= size:
            raise StackUnderflowError()
        return self.stack[size - idx - 1]

    def peek_int(self, idx):
        val = self.peek_bytearray(idx)
        return script_num(val, self.verify_minimal_data, math_op_code_max_script_num_len)

    def peek_bool(self, idx):
        val = self.peek_bytearray(idx)
        return _CastToBool(val)

    def nip(self, idx):
        """Remove the idx-th stack item."""
        size = len(self.stack)
        if idx < 0 or idx > size - 1:
            raise StackUnderflowError()
        return self.stack.pop(size - idx - 1)

    def tuck(self):
        """Copy the top stack item to the second-to-top stack index."""
        val2 = self.pop_bytearray()
        val1 = self.pop_bytearray()
        self.push_bytearray(val2)
        self.push_bytearray(val1)
        self.push_bytearray(val2)

    def drop(self, n):
        """Remove the top n items from the stack."""
        if n < 1:
            raise StackInvalidArgsError()
        for i in range(n):
            self.pop_bytearray()

    def dup(self, n):
        """Duplicate the top n items on the stack."""
        if n < 1:
            raise StackInvalidArgsError()
        for i in range(n, 0, -1):
            val = self.peek_bytearray(n - 1)
            self.push_bytearray(val)

    def rot(self, n):
        """Rotate the top 3n items on the stack to the left n times."""
        if n < 1:
            raise StackInvalidArgsError()
        entry = 3*n - 1
        for i in range(n, 0, -1):
            val = self.nip(entry)
            self.push_bytearray(val)

    def swap(self, n):
        """Swap the top n items on the stack with those below them."""
        if n < 1:
            raise StackInvalidArgsError()
        entry = 2*n - 1
        for i in range(n, 0, -1):
            val = self.nip(entry)
            self.push_bytearray(val)

    def over(self, n):
        """Copy n items n items back to the top of the stack."""
        if n < 1:
            raise StackInvalidArgsError()
        entry = 2*n - 1
        while n > 0:
            val = self.peek_bytearray(entry)
            self.push_bytearray(val)
            n -= 1

    def pick(self, n):
        """Copy the item n items back in the stack to the top."""
        val = self.peek_bytearray(n)
        self.push_bytearray(val)

    def roll(self, n):
        """Move the item n items back in the stack to the top."""
        val = self.nip(n)
        self.push_bytearray(val)

