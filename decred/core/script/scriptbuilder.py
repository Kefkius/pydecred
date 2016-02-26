from __future__ import absolute_import
import sys
import struct

from .errors import *
from .opcode import *
from .scriptnum import num2bytearray
from .constants import maxScriptSize, MaxScriptElementSize

_bchr = chr
_bord = ord
if sys.version > '3':
    _bchr = lambda x: bytes([x])
    _bord = lambda x: x

# defaultScriptAlloc is the default size used for the backing array
# for a script being built by the ScriptBuilder.  The array will
# dynamically grow as needed, but this figure is intended to provide
# enough space for vast majority of scripts without needing to grow the
# backing array multiple times.
defaultScriptAlloc = 500

# ErrScriptNotCanonical identifies a non-canonical script.  The caller can use
# a type assertion to detect this error type.
##type ErrScriptNotCanonical string

#// Error implements the error interface.
#func (e ErrScriptNotCanonical) Error() string {
#	return string(e)
#}

class ScriptNonCanonicalError(Exception):
    pass

# ScriptBuilder provides a facility for building custom scripts.  It allows
# you to push opcodes, ints, and data while respecting canonical encoding.  In
# general it does not ensure the script will execute correctly, however any
# data pushes which would exceed the maximum allowed script engine limits and
# are therefore guaranteed not to execute will not be pushed and will result in
# the Script function returning an error.
#
# For example, the following would build a 2-of-3 multisig script for usage in
# a pay-to-script-hash (although in this situation MultiSigScript() would be a
# better choice to generate the script):
# 	builder := txscript.NewScriptBuilder()
# 	builder.AddOp(txscript.OP_2).AddData(pubKey1).AddData(pubKey2)
# 	builder.AddData(pubKey3).AddOp(txscript.OP_3)
# 	builder.AddOp(txscript.OP_CHECKMULTISIG)
# 	script, err := builder.Script()
# 	if err != nil {
# 		// Handle the error.
# 		return
# 	}
# 	fmt.Printf("Final multi-sig script: %x\n", script)
class ScriptBuilder(object):
    def __init__(self):
        self.script = []
        self.err = None

    def AddOp(self, opcode):
        """AddOp pushes the passed opcode to the end of the script.

        The script will not be modified if pushing the opcode would cause
        the script to exceed the maximum allowed script engine size.
        """
        if self.err:
            return self

        if len(self._makeScript()) + 1 > maxScriptSize:
            self.err = ScriptNonCanonicalError('adding an opcode would exceed the maximum allowed canonical script length')
            return self

        self.script.append(_bchr(opcode))
        return self

    def canonicalDataSize(self, data):
        """Returns the number of bytes the canonical encoding of data will take."""
        dl = len(data)

	# When the data consists of a single number that can be represented
	# by one of the "small integer" opcodes, that opcode will be instead
	# of a data push opcode followed by the number.
        if dl == 0:
            return 1
        elif dl == 1 and _bord(data[0]) <= 16:
            return 1
        elif dl == 1 and _bord(data[0]) == 0x81:
            return 1

        if dl < OP_PUSHDATA1:
            return 1 + dl
        elif dl <= 0xff:
            return 2 + dl
        elif dl <= 0xffff:
            return 3 + dl

        return 5 + dl

    def _addData(self, data):
        dl = len(data)

	# When the data consists of a single number that can be represented
	# by one of the "small integer" opcodes, use that opcode instead of
	# a data push opcode followed by the number.
        if dl == 0 or dl == 1 and _bord(data[0]) == 0:
            self.script.append(_bchr(OP_0))
            return self
        elif dl == 1 and _bord(data[0]) <= 16:
            self.script.append(_bchr((OP_1-1)+_bord(data[0])))
            return self
        elif dl == 1 and _bord(data[0]) == 0x81:
            self.script.append(_bchr(OP_1NEGATE))
            return self

	# Use one of the OP_DATA_# opcodes if the length of the data is small
	# enough so the data push instruction is only a single byte.
	# Otherwise, choose the smallest possible OP_PUSHDATA# opcode that
	# can represent the length of the data.
        if dl < OP_PUSHDATA1:
            self.script.append(_bchr((OP_DATA_1-1)+dl))
        elif dl <= 0xff:
            self.script.append(_bchr(OP_PUSHDATA1))
            self.script.append(_bchr(dl))
        elif dl <= 0xffff:
            buf = struct.pack(b'<H', dl)
            self.script.append(_bchr(OP_PUSHDATA2))
            self.script.append(buf)
        else:
            buf = struct.pack(b'<I', dl)
            self.script.append(_bchr(OP_PUSHDATA4))
            self.script.append(buf)

        # Append the actual data.
        self.script.append(data)
        return self

    def AddFullData(self, data):
        """AddFullData should not typically be used by ordinary users as it does not
        include the checks which prevent data pushes larger than the maximum allowed
        sizes which leads to scripts that can't be executed.  This is provided for
        testing purposes such as regression tests where sizes are intentionally made
        larger than allowed.

        Use AddData instead.
        """
        if self.err:
            return self

        return self._addData(data)

    def AddData(self, data):
        """AddData pushes the passed data to the end of the script.
        
        It automatically chooses canonical opcodes depending on the length of the data.
        A zero length buffer will lead to a push of empty data onto the stack (OP_0) and any push
        of data greater than MaxScriptElementSize will not modify the script since
        that is not allowed by the script engine.  Also, the script will not be
        modified if pushing the data would cause the script to exceed the maximum
        allowed script engine size.
        """
        if self.err:
            return self

        # Pushes that would cause the script to exceed the largest allowed
        # script size would result in a non-canonical script.
        dsize = self.canonicalDataSize(data)
        if len(self._makeScript()) + dsize > maxScriptSize:
            self.err = ScriptNonCanonicalError('adding %d bytes of data would exceed the maximum allowed canonical script length' % dsize)
            return self

        # Pushes larger than the max script element size would result in a
        # script that is not canonical.
        dl = len(data)
        if dl > MaxScriptElementSize:
            self.err = ScriptNonCanonicalError('adding a data element of %d bytes would exceed the maximum allowed canonical script length' % dl)
            return self

        return self._addData(data)

    def AddInt64(self, val):
        """Pushes the passed integer to the end of the script.

        The script will not be modified if pushing the data would cause
        the script to exceed the maximum allowed script engine size.
        """
        if self.err:
            return self

	# Pushes that would cause the script to exceed the largest allowed
	# script size would result in a non-canonical script.
        if len(self._makeScript()) + 1 > maxScriptSize:
            self.err = ScriptNonCanonicalError('adding an integer would exceed the maximum allowed canonical script length')
            return self

        # Fast path for small integers and OP_1NEGATE
        if val == 0:
            self.script.append(_bchr(OP_0))
            return self
        if val == -1 or (val >= 1 and val <= 16):
            self.script.append(_bchr((OP_1-1)+val))
            return self

        return self.AddData(num2bytearray(val))

    def Reset(self):
        """Resets the script so it has no contents."""
        self.script = self.script[0:0]
        self.err = None
        return self

    def _makeScript(self):
        return ''.join(self.script)

    def Script(self, raise_on_error=False):
        """Returns the currently built script.

        When any errors occurred while building the script, the script will
        be returned up to the point of the first error.
        """
        if raise_on_error and self.err:
            raise self.err
        return self._makeScript(), self.err

    def get_script(self):
        s, _ = self.Script(raise_on_error=True)
        return s
