"""Script-related errors."""

class StackNumberTooBigError(Exception):
    def __init__(self, *args, **kwargs):
        super(StackNumberTooBigError, self).__init__('number is too big')

class StackMinimalDataError(Exception):
    def __init__(self, *args, **kwargs):
        super(StackMinimalDataError, self).__init__('non-minimally encoded script number')

class StackInvalidArgsError(Exception):
    def __init__(self, *args, **kwargs):
        super(StackInvalidArgsError, self).__init__('invalid argument')

class StackUnderflowError(Exception):
    def __init__(self, *args, **kwargs):
        super(StackUnderflowError, self).__init__('stack underflow')

class StackInvalidOpcodeError(Exception):
    def __init__(self, *args, **kwargs):
        super(StackInvalidOpcodeError, self).__init__('Invalid Opcode')

class StackOpDisabledError(Exception):
    def __init__(self, *args, **kwargs):
        super(StackOpDisabledError, self).__init__('Disabled Opcode')

class StackReservedOpcodeError(Exception):
    def __init__(self, *args, **kwargs):
        super(StackReservedOpcodeError, self).__init__('Reserved Opcode')

class StackNoIfError(Exception):
    def __init__(self, *args, **kwargs):
        super(StackNoIfError, self).__init__('OP_ELSE or OP_ENDIF with no matching OP_IF')

class StackVerifyFailedError(Exception):
    def __init__(self, *args, **kwargs):
        super(StackVerifyFailedError, self).__init__('Verify failed')

class StackEarlyReturnError(Exception):
    def __init__(self, *args, **kwargs):
        super(StackEarlyReturnError, self).__init__('Script returned early')

class StackElementTooBigError(Exception):
    def __init__(self, *args, **kwargs):
        super(StackElementTooBigError, self).__init__('Element in script too large')

class SubstrIdxOutOfBoundsError(Exception):
    def __init__(self, *args, **kwargs):
        super(SubstrIdxOutOfBoundsError, self).__init__('Out of bounds number given for substring index')

class SubstrIdxNegativeError(Exception):
    def __init__(self, *args, **kwargs):
        super(SubstrIdxNegativeError, self).__init__('Negative number given for substring index')

class NegativeRotationError(Exception):
    def __init__(self, *args, **kwargs):
        super(NegativeRotationError, self).__init__('Rotation depth negative')

class RotationOverflowError(Exception):
    def __init__(self, *args, **kwargs):
        super(RotationOverflowError, self).__init__('Rotation depth out of bounds')

class DivideByZeroError(Exception):
    def __init__(self, *args, **kwargs):
        super(DivideByZeroError, self).__init__('Division by zero')

class NegativeShiftError(Exception):
    def __init__(self, *args, **kwargs):
        super(NegativeShiftError, self).__init__('Shift depth negative')

class ShiftOverflowError(Exception):
    def __init__(self, *args, **kwargs):
        super(ShiftOverflowError, self).__init__('Shift depth out of bounds')

