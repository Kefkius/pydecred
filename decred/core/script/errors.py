"""Script-related errors."""

# Engine execution errors.

class EngineExecutionError(Exception):
    pass

class StackShortScriptError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'execute past end of script')

class StackLongScriptError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'script is longer than maximum allowed')

class StackUnderflowError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'stack underflow')

class StackInvalidArgsError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'invalid argument')

class StackOpDisabledError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'Disabled Opcode')

class StackVerifyFailedError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'Verify failed')

class StackNumberTooBigError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'number too big')

class StackInvalidOpcodeError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'Invalid Opcode')

class StackReservedOpcodeError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'Reserved Opcode')

class StackEarlyReturnError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'Script returned early')

class StackNoIfError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'OP_ELSE or OP_ENDIF with no matching OP_IF')

class StackMissingEndifError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'execute fail, in conditional execution')

class StackTooManyPubkeysError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'Invalid pubkey count in OP_CHECKMULTISIG')

class StackTooManyOperationsError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'Too many operations in script')

class StackElementTooBigError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'Element in script too large')

class StackUnknownAddressError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'non-recognised address')

class StackScriptFailedError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'execute fail, fail on stack')

class StackScriptUnfinishedError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'Error check when script unfinished')

class StackEmptyStackError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'Stack empty at end of execution')

class StackP2SHNonPushOnlyError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'pay to script hash with non-pushonly input')

class StackInvalidParseTypeError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'internal error: invalid parsetype found')

class StackInvalidAddrOffsetError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'internal error: invalid offset found')

class StackInvalidIndexError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'Invalid script index')

class StackNonPushOnlyError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'SigScript is non-pushonly')

class StackOverflowError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'Stacks overflowed')

class StackInvalidLowSSignatureError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'invalid low s signature')

class StackInvalidPubKeyError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'invalid strict pubkey')

class StackCleanStackError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'stack is not clean')

class StackMinimalDataError(EngineExecutionError):
    def __init__(self, *args, **kwargs):
        EngineExecutionError.__init__(self, 'non-minimally encoded script number')


# Engine script errors.
class EngineScriptError(Exception):
    pass

class InvalidFlagsError(EngineScriptError):
    def __init__(self, *args, **kwargs):
        EngineScriptError.__init__(self, 'invalid flags combination')

class InvalidIndexError(EngineScriptError):
    def __init__(self, *args, **kwargs):
        EngineScriptError.__init__(self, 'invalid input index')

class UnsupportedAddressError(EngineScriptError):
    def __init__(self, *args, **kwargs):
        EngineScriptError.__init__(self, 'unsupported address type')

class BadNumRequiredError(EngineScriptError):
    def __init__(self, *args, **kwargs):
        EngineScriptError.__init__(self, 'more signatures required than keys present')

class SighashSingleIdxError(EngineScriptError):
    def __init__(self, *args, **kwargs):
        EngineScriptError.__init__(self, 'invalid SIGHASH_SINGLE script index')

class SubstrIndexNegativeError(EngineScriptError):
    def __init__(self, *args, **kwargs):
        EngineScriptError.__init__(self, 'negative number given for substring index')

class SubstrIdxOutOfBoundsError(EngineScriptError):
    def __init__(self, *args, **kwargs):
        EngineScriptError.__init__(self, 'out of bounds number given for substring index')

class NegativeRotationError(EngineScriptError):
    def __init__(self, *args, **kwargs):
        EngineScriptError.__init__(self, 'rotation depth negative')

class RotationOverflowError(EngineScriptError):
    def __init__(self, *args, **kwargs):
        EngineScriptError.__init__(self, 'rotation depth out of bounds')

class NegativeShiftError(EngineScriptError):
    def __init__(self, *args, **kwargs):
        EngineScriptError.__init__(self, 'shift depth negative')

class ShiftOverflowError(EngineScriptError):
    def __init__(self, *args, **kwargs):
        EngineScriptError.__init__(self, 'shift depth out of bounds')

class DivideByZeroError(EngineScriptError):
    def __init__(self, *args, **kwargs):
        EngineScriptError.__init__(self, 'division by zero')

class P2SHStakeOpCodesError(EngineScriptError):
    def __init__(self, *args, **kwargs):
        EngineScriptError.__init__(self, 'stake opcodes were found in a p2sh script')

