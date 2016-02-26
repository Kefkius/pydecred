from __future__ import absolute_import
import sys
import binascii

from .script import *
from .opcode import *
from .stack import Stack
from .standard import *

_bord = ord
if sys.version > '3':
    _bord = lambda x: x

half_order = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0

class Engine(object):
    """Virtual machine that executes scripts."""
    def __init__(self, script_pub_key, tx, tx_idx, flags, script_version):
        self.script_idx = 0
        self.script_off = 0
        self.last_code_sep = 0
        self.dstack = Stack()
        self.astack = Stack()
        self.cond_stack = []
        self.num_ops = 0
        self.bip16 = False
        self.saved_first_stack = []

        if tx_idx < 0 or tx_idx >= len(tx.txins):
            raise InvalidIndexError()
        script_sig = tx.txins[tx_idx].sig_script

        # The clean stack flag (ScriptVerifyCleanStack) is not allowed without
        # the pay-to-script-hash (P2SH) evaluation (ScriptBip16) flag.
        #
        # Recall that evaluating a P2SH script without the flag set results in
        # non-P2SH evaluation which leaves the P2SH inputs on the stack.  Thus,
        # allowing the clean stack flag without the P2SH flag would make it
        # possible to have a situation where P2SH would not be a soft fork when
        # it should be.
        self.version = script_version
        self.flags = flags
        if self.has_flag(ScriptVerifyCleanStack) and not self.has_flag(ScriptBip16):
            raise InvalidFlagsError()

        # The signature script must only contain data pushes is the associated flag is set.
        if self.has_flag(ScriptVerifySigPushOnly) and not IsPushOnlyScript(script_sig):
            raise StackNonPushOnlyError()

        # Subscripts for P2SH outputs are not allowed to use any stake tag opcodes
        # if script version is 0.
        if script_version == DefaultScriptVersion:
            HasP2SHScriptSigStakeOpCodes(script_version, script_sig, script_pub_key)

        # The engine stores the scripts in parsed form.
        # This allows multiple scripts to be executed in sequence.
        scripts = [script_sig, script_pub_key]
        self.scripts = []
        for scr in scripts:
            if len(scr) > maxScriptSize:
                raise StackLongScriptError()
            self.scripts.append(parseScript(scr))

        # Advance the program counter to the public key script if the signature
        # script is empty since there is nothing to execute for it in that case.
        if len(scripts[0]) == 0:
            self.script_idx += 1

        if self.has_flag(ScriptBip16) and isAnyKindOfScriptHash(self.scripts[1]):
            if not isPushOnly(self.scripts[0]):
                raise StackP2SHNonPushOnlyError()
            self.bip16 = True
        if self.has_flag(ScriptVerifyMinimalData):
            self.dstack.verify_minimal_data = True
            self.astack.verify_minimal_data = True

        self.tx = tx
        self.tx_idx = tx_idx

    def has_flag(self, flag):
        return self.flags & flag == flag

    def is_branch_executing(self):
        """Returns whether the current conditional branch is actively executing.

        For example, when the data stack has an OP_FALSE on it and an
        OP_IF is encountered, the branch is inactive until an OP_ELSE or
        OP_ENDIF is encountered.
        """
        if len(self.cond_stack) == 0:
            return True
        return self.cond_stack[-1] == OpCondTrue

    def execute_opcode(self, pop):
        if pop.isDisabled():
            raise StackOpDisabledError()

        if pop.alwaysIllegal():
            raise StackReservedOpcodeError()

        # Note that this includes OP_RESERVED which counts as a push operation.
        if pop.opcode.value > OP_16:
            self.num_ops += 1
            if self.num_ops > MaxOpsPerScript:
                raise StackTooManyOperationsError()
        elif len(pop.data) > MaxScriptElementSize:
            raise StackElementTooBigError()

        # Nothing left to do when this is not a conditional opcode and it's not
        # in an executing branch.
        if not self.is_branch_executing() and not pop.isConditional():
            return

        # Ensure all executed data push opcods use minimal encoding if set.
        if self.dstack.verify_minimal_data and self.is_branch_executing() and \
                    pop.opcode.value >= 0 and pop.opcode.value <= OP_PUSHDATA4:
            pop.checkMinimalDataPush()

        return pop.opcode.opfunc(pop, self)

    def disasm(self, scriptIdx, scriptOff, verbose=True):
        """Helper function to produce the output for disasm_pc and disasm_script."""
        if verbose:
            return '%02x:%04x: %s' % (scriptIdx, scriptOff, self.scripts[scriptIdx][scriptOff].human_readable(oneline=False))
        return '%s' % self.scripts[scriptIdx][scriptOff].human_readable(oneline=False)

    def valid_pc(self):
        """Raises an exception if the current script position is valid for execution."""
        if self.script_idx >= len(self.scripts):
            raise Exception('past input scripts %s:%s %s:xxxx' % (self.script_idx, self.script_off, len(self.scripts)))

    def cur_pc(self):
        """Returns either the current script and offset or raises an error if the position isn't valid."""
        self.valid_pc()
        return self.script_idx, self.script_off

    def disasm_pc(self, verbose=True):
        """Returns the string for the disassembly of the opcode that will execute next when step() is called."""
        scriptIdx, scriptOff = self.cur_pc()
        return self.disasm(scriptIdx, scriptOff, verbose)

    def disasm_script(self, idx, verbose=True):
        """Returns the disassembly string for the script at offset idx.

        Index 0 is the signature script and 1 is the public key script.
        """
        if idx >= len(self.scripts):
            raise StackInvalidIndexError()

        disstr = ''
        for i in range(len(self.scripts[idx])):
            disstr += self.disasm(idx, i, verbose) + '\n'
        return disstr

    def check_error_condition(self, final_script):
        """Raises an exception if the script has not finished."""
        # Check execution is actually done.
        if self.script_idx < len(self.scripts):
            raise StackScriptUnfinishedError()
        if final_script and self.has_flag(ScriptVerifyCleanStack) and self.dstack.depth() != 1:
            raise StackCleanStackError()
        elif self.dstack.depth() < 1:
            raise StackEmptyStackError()

        v = self.dstack.peek_bool(0)
        if not v:
            raise StackScriptFailedError()

    def step(self):
        """Executes the next instruction and moves the program counter to the next opcode.

        Moves to the next script is the current one has ended. Step will return True
        if the last opcode was successfully executed.
        """
        self.valid_pc()
        opcode = self.scripts[self.script_idx][self.script_off]

        # Execute the opcode while taking into account several things such as
        # disabled opcodes, illegal opcodes, max allowed operations per script,
        # max script element sizes, and conditionals.
        self.execute_opcode(opcode)

        # The number of elements in the combination of the data and alt stacks must
        # not exceed the maximum number of stack elements allowed.
        if self.dstack.depth() + self.astack.depth() > maxStackSize:
            raise StackOverflowError()

        # Prepare for the next instruction.
        self.script_off += 1
        if self.script_off >= len(self.scripts[self.script_idx]):
            # Illegal to have an if that straddles two scripts.
            if len(self.cond_stack) != 0:
                raise StackMissingEndifError()

            # Alt stack doesn't persist.
            if self.astack.depth():
                self.astack.drop(self.astack.depth())

            self.num_ops = 0
            self.script_off = 0
            if self.script_idx == 0 and self.bip16:
                self.script_idx += 1
                self.saved_first_stack = self.get_stack()
            elif self.script_idx == 1 and self.bip16:
                # Put us past the end for check_error_condition()
                self.script_idx += 1
                # Check script ran successfully and pull the script
                # out of the first stack and execute that.
                self.check_error_condition(False)

                script = self.saved_first_stack[-1]
                pops = parseScript(script)
                self.scripts.append(pops)

                # Set stack to be the stack from the first script minus the script itself.
                self.set_stack(self.saved_first_stack[:-1])
            else:
                self.script_idx += 1

            # There are zero-length scripts in the wild.
            if (self.script_idx < len(self.scripts) and
                    self.script_off >= len(self.scripts[self.script_idx])):
                self.script_idx += 1

            self.last_code_sep = 0
            if self.script_idx >= len(self.scripts):
                return True

        return False

    def execute(self):
        """Execute all scripts in the engine and raise an exception if one occurs."""
        if self.version != DefaultScriptVersion:
            return

        done = False
        while done != True:
            done = self.step()

        return self.check_error_condition(True)

    def sub_script(self):
        """Returns the script since the last OP_CODESEPARATOR."""
        return self.scripts[self.script_idx][self.last_code_sep:]

    def check_hash_type_encoding(self, hash_type):
        """Raises an exception if the passed hashtype doesn't adhere to the strict encoding requirements (if enabled)."""
        if not self.has_flag(ScriptVerifyStrictEncoding):
            return

        sigHashType = hash_type & ~SigHashAnyOneCanPay
        if sigHashType < SigHashAll or sigHashType > SigHashSingle:
            raise Exception('invalid hashtype: 0x%x' % hash_type)

    def check_pubkey_encoding(self, pub_key):
        """Raises an exception if the passed public key doesn't adhere to the strict encoding requirements (if enabled)."""
        if not self.has_flag(ScriptVerifyStrictEncoding):
            return

        # Compressed public key.
        if len(pub_key) == 33 and (_bord(pub_key[0]) == 0x02 or _bord(pub_key[0]) == 0x03):
            return
        # Uncompressed public key.
        if len(pub_key) == 65 and _bord(pub_key[0]) == 0x04:
            return
        raise StackInvalidPubKeyError()

    def check_signature_encoding(self, sig):
        """Raises an exception if the passed signature doesn't adhere to the strict encoding requirements (if enabled)."""
        if (not self.has_flag(ScriptVerifyDERSignatures) and
            not self.has_flag(ScriptVerifyLowS) and
            not self.has_flag(ScriptVerifyStrictEncoding)):
            return

        # The format of a DER encoded signature is as follows:
        #
        # 0x30 <total length> 0x02 <length of R> <R> 0x02 <length of S> <S>
        #   - 0x30 is the ASN.1 identifier for a sequence
        #   - Total length is 1 byte and specifies length of all remaining data
        #   - 0x02 is the ASN.1 identifier that specifies an integer follows
        #   - Length of R is 1 byte and specifies how many bytes R occupies
        #   - R is the arbitrary length big-endian encoded number which
        #     represents the R value of the signature.  DER encoding dictates
        #     that the value must be encoded using the minimum possible number
        #     of bytes.  This implies the first byte can only be null if the
        #     highest bit of the next byte is set in order to prevent it from
        #     being interpreted as a negative number.
        #   - 0x02 is once again the ASN.1 integer identifier
        #   - Length of S is 1 byte and specifies how many bytes S occupies
        #   - S is the arbitrary length big-endian encoded number which
        #     represents the S value of the signature.  The encoding rules are
        #     identical as those for R.

        # Minimum length is when both numbers are 1 byte each.
        # 0x30 + <1-byte> + 0x02 + 0x01 + <byte> + 0x2 + 0x01 + <byte>
        if len(sig) < 8:
            raise Exception('malformed signature: too short: %d < 8' % len(sig))

        # Maximum length is when both numbers are 33 bytes each.  It is 33
        # bytes because a 256-bit integer requires 32 bytes and an additional
        # leading null byte might required if the high bit is set in the value.
        # 0x30 + <1-byte> + 0x02 + 0x21 + <33 bytes> + 0x2 + 0x21 + <33 bytes>
        if len(sig) > 72:
            raise Exception('malformed signature: too long: %d > 72' % len(sig))

        if _bord(sig[0]) != 0x30:
            raise Exception('malformed signature: format has wrong type: 0x%x' % sig[0])

        if _bord(sig[1]) != len(sig) - 2:
            raise Exception('malformed signature: bad length: %d != %d' % (sig[1], len(sig)-2))

        rlen = _bord(sig[3])

        # Make sure S is inside the signature.
        if rlen + 5 > len(sig):
            raise Exception('malformed signature: S out of bounds')

        slen = _bord(sig[rlen+5])

        # The length of the elements does not match the length of the signature.
        if rlen + slen + 6 != len(sig):
            raise Exception('malformed signature: invalid R length')

        # R elements must be integers.
        if _bord(sig[2]) != 0x02:
            raise Exception('malformed signature: missing first integer marker')

        # Zero-length integers are not allowed for R.
        if rlen == 0:
            raise Exception('malformed signature: R length is zero')

        # R must not be negative
        if _bord(sig[4]) & 0x80 != 0:
            raise Exception('malformed signature: R value is negative')

        # Null bytes at the start of R are not allowed unless R would
        # otherwise be interpreted as a negative number.
        if rlen > 1 and _bord(sig[4]) == 0x00 and _bord(sig[5]) & 0x80 == 0:
            raise Exception('malformed signature: invalid R value')

        # S elements must be integers.
        if _bord(sig[rlen+4]) != 0x02:
            raise Exception('malformed signature: missing second integer marker')

        # Zero-length integers are not allowed for S.
        if slen == 0:
            raise Exception('malformed signature: S length is zero')

        # S must not be negative.
        if _bord(sig[rlen+6]) & 0x80 != 0:
            raise Exception('malformed signature: S value is negative')

        # Null bytes at the start of S are not allowed unless S would
        # otherwise be interpreted as a negative number.
        if slen > 1 and _bord(sig[rlen+6]) == 0x00 and _bord(sig[rlen+7]) & 0x80 == 0:
            raise Exception('malformed signature: invalid S value')

        # Verify the S value is <= half the order of the curve.  This check is
        # done because when it is higher, the complement modulo the order can
        # be used instead which is a shorter encoding by 1 byte.  Further,
        # without enforcing this, it is possible to replace a signature in a
        # valid transaction with the complement while still being a valid
        # signature that verifies.  This would result in changing the
        # transaction hash and thus is source of malleability.
        if self.has_flag(ScriptVerifyLowS):
            svalue = int(binascii.hexlify(sig[rlen+6 : rlen+6+slen]), 16)
            if svalue > half_order:
                raise StackInvalidLowSSignatureError()
            pass

    def get_stack(self):
        """Returns the contents of the primary stack."""
        return get_stack(self.dstack)

    def set_stack(self, data):
        """Sets the contents of the primary stack."""
        set_stack(self.dstack, data)

    def get_alt_stack(self):
        """Returns the contents of the alt stack."""
        return get_stack(self.astack)

    def set_alt_stack(self, data):
        """Sets the contents of the alt stack."""
        set_stack(self.astack, data)

def get_stack(stack):
    arr = []
    for i in range(stack.depth()):
        arr.append(stack.peek_bytearray(i))
    arr.reverse()
    return b''.join(arr)

def set_stack(stack, data):
    stack.drop(stack.depth())
    for i in data:
        stack.push_bytearray(i)
