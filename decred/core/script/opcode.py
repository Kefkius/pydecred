from __future__ import absolute_import
from collections import namedtuple
import sys
import struct
import hashlib
import binascii

from bitcoin.core.scripteval import _CastToBool

from decred.core.chaincfg import sig_hash_optimization
from decred.core.key import ECTypeSecp256k1, ECTypeEdwards, ECTypeSecSchnorr
from decred.core.serialize import DecredHash, Hash160
from .scriptnum import StackMinimalDataError, script_num, math_op_code_max_script_num_len, int_32
from .errors import *
from .constants import MaxScriptElementSize

_bchr = chr
_bord = ord
if sys.version > '3':
    _bchr = lambda x: bytes([x])
    _bord = lambda x: x

optimize_sig_verification = sig_hash_optimization

# An opcode defines the information related to a txscript opcode.  opfunc if
# present is the function to call to perform the opcode on the script.  The
# current script is passed in as a slice with the first member being the opcode
# itself.
Opcode = namedtuple('Opcode', ('value', 'name', 'length', 'opfunc'))

# These constants are the values of the official opcodes used on the btc wiki,
# in bitcoin core and in most if not all other references and software related
# to handling DCR scripts.
OP_0                   = 0x00 # 0
OP_FALSE               = 0x00 # 0 - AKA OP_0
OP_DATA_1              = 0x01 # 1
OP_DATA_2              = 0x02 # 2
OP_DATA_3              = 0x03 # 3
OP_DATA_4              = 0x04 # 4
OP_DATA_5              = 0x05 # 5
OP_DATA_6              = 0x06 # 6
OP_DATA_7              = 0x07 # 7
OP_DATA_8              = 0x08 # 8
OP_DATA_9              = 0x09 # 9
OP_DATA_10             = 0x0a # 10
OP_DATA_11             = 0x0b # 11
OP_DATA_12             = 0x0c # 12
OP_DATA_13             = 0x0d # 13
OP_DATA_14             = 0x0e # 14
OP_DATA_15             = 0x0f # 15
OP_DATA_16             = 0x10 # 16
OP_DATA_17             = 0x11 # 17
OP_DATA_18             = 0x12 # 18
OP_DATA_19             = 0x13 # 19
OP_DATA_20             = 0x14 # 20
OP_DATA_21             = 0x15 # 21
OP_DATA_22             = 0x16 # 22
OP_DATA_23             = 0x17 # 23
OP_DATA_24             = 0x18 # 24
OP_DATA_25             = 0x19 # 25
OP_DATA_26             = 0x1a # 26
OP_DATA_27             = 0x1b # 27
OP_DATA_28             = 0x1c # 28
OP_DATA_29             = 0x1d # 29
OP_DATA_30             = 0x1e # 30
OP_DATA_31             = 0x1f # 31
OP_DATA_32             = 0x20 # 32
OP_DATA_33             = 0x21 # 33
OP_DATA_34             = 0x22 # 34
OP_DATA_35             = 0x23 # 35
OP_DATA_36             = 0x24 # 36
OP_DATA_37             = 0x25 # 37
OP_DATA_38             = 0x26 # 38
OP_DATA_39             = 0x27 # 39
OP_DATA_40             = 0x28 # 40
OP_DATA_41             = 0x29 # 41
OP_DATA_42             = 0x2a # 42
OP_DATA_43             = 0x2b # 43
OP_DATA_44             = 0x2c # 44
OP_DATA_45             = 0x2d # 45
OP_DATA_46             = 0x2e # 46
OP_DATA_47             = 0x2f # 47
OP_DATA_48             = 0x30 # 48
OP_DATA_49             = 0x31 # 49
OP_DATA_50             = 0x32 # 50
OP_DATA_51             = 0x33 # 51
OP_DATA_52             = 0x34 # 52
OP_DATA_53             = 0x35 # 53
OP_DATA_54             = 0x36 # 54
OP_DATA_55             = 0x37 # 55
OP_DATA_56             = 0x38 # 56
OP_DATA_57             = 0x39 # 57
OP_DATA_58             = 0x3a # 58
OP_DATA_59             = 0x3b # 59
OP_DATA_60             = 0x3c # 60
OP_DATA_61             = 0x3d # 61
OP_DATA_62             = 0x3e # 62
OP_DATA_63             = 0x3f # 63
OP_DATA_64             = 0x40 # 64
OP_DATA_65             = 0x41 # 65
OP_DATA_66             = 0x42 # 66
OP_DATA_67             = 0x43 # 67
OP_DATA_68             = 0x44 # 68
OP_DATA_69             = 0x45 # 69
OP_DATA_70             = 0x46 # 70
OP_DATA_71             = 0x47 # 71
OP_DATA_72             = 0x48 # 72
OP_DATA_73             = 0x49 # 73
OP_DATA_74             = 0x4a # 74
OP_DATA_75             = 0x4b # 75
OP_PUSHDATA1           = 0x4c # 76
OP_PUSHDATA2           = 0x4d # 77
OP_PUSHDATA4           = 0x4e # 78
OP_1NEGATE             = 0x4f # 79
OP_RESERVED            = 0x50 # 80
OP_1                   = 0x51 # 81 - AKA OP_TRUE
OP_TRUE                = 0x51 # 81
OP_2                   = 0x52 # 82
OP_3                   = 0x53 # 83
OP_4                   = 0x54 # 84
OP_5                   = 0x55 # 85
OP_6                   = 0x56 # 86
OP_7                   = 0x57 # 87
OP_8                   = 0x58 # 88
OP_9                   = 0x59 # 89
OP_10                  = 0x5a # 90
OP_11                  = 0x5b # 91
OP_12                  = 0x5c # 92
OP_13                  = 0x5d # 93
OP_14                  = 0x5e # 94
OP_15                  = 0x5f # 95
OP_16                  = 0x60 # 96
OP_NOP                 = 0x61 # 97
OP_VER                 = 0x62 # 98
OP_IF                  = 0x63 # 99
OP_NOTIF               = 0x64 # 100
OP_VERIF               = 0x65 # 101
OP_VERNOTIF            = 0x66 # 102
OP_ELSE                = 0x67 # 103
OP_ENDIF               = 0x68 # 104
OP_VERIFY              = 0x69 # 105
OP_RETURN              = 0x6a # 106
OP_TOALTSTACK          = 0x6b # 107
OP_FROMALTSTACK        = 0x6c # 108
OP_2DROP               = 0x6d # 109
OP_2DUP                = 0x6e # 110
OP_3DUP                = 0x6f # 111
OP_2OVER               = 0x70 # 112
OP_2ROT                = 0x71 # 113
OP_2SWAP               = 0x72 # 114
OP_IFDUP               = 0x73 # 115
OP_DEPTH               = 0x74 # 116
OP_DROP                = 0x75 # 117
OP_DUP                 = 0x76 # 118
OP_NIP                 = 0x77 # 119
OP_OVER                = 0x78 # 120
OP_PICK                = 0x79 # 121
OP_ROLL                = 0x7a # 122
OP_ROT                 = 0x7b # 123
OP_SWAP                = 0x7c # 124
OP_TUCK                = 0x7d # 125
OP_CAT                 = 0x7e # 126
OP_SUBSTR              = 0x7f # 127
OP_LEFT                = 0x80 # 128
OP_RIGHT               = 0x81 # 129
OP_SIZE                = 0x82 # 130
OP_INVERT              = 0x83 # 131
OP_AND                 = 0x84 # 132
OP_OR                  = 0x85 # 133
OP_XOR                 = 0x86 # 134
OP_EQUAL               = 0x87 # 135
OP_EQUALVERIFY         = 0x88 # 136
OP_ROTR                = 0x89 # 137
OP_ROTL                = 0x8a # 138
OP_1ADD                = 0x8b # 139
OP_1SUB                = 0x8c # 140
OP_2MUL                = 0x8d # 141
OP_2DIV                = 0x8e # 142
OP_NEGATE              = 0x8f # 143
OP_ABS                 = 0x90 # 144
OP_NOT                 = 0x91 # 145
OP_0NOTEQUAL           = 0x92 # 146
OP_ADD                 = 0x93 # 147
OP_SUB                 = 0x94 # 148
OP_MUL                 = 0x95 # 149
OP_DIV                 = 0x96 # 150
OP_MOD                 = 0x97 # 151
OP_LSHIFT              = 0x98 # 152
OP_RSHIFT              = 0x99 # 153
OP_BOOLAND             = 0x9a # 154
OP_BOOLOR              = 0x9b # 155
OP_NUMEQUAL            = 0x9c # 156
OP_NUMEQUALVERIFY      = 0x9d # 157
OP_NUMNOTEQUAL         = 0x9e # 158
OP_LESSTHAN            = 0x9f # 159
OP_GREATERTHAN         = 0xa0 # 160
OP_LESSTHANOREQUAL     = 0xa1 # 161
OP_GREATERTHANOREQUAL  = 0xa2 # 162
OP_MIN                 = 0xa3 # 163
OP_MAX                 = 0xa4 # 164
OP_WITHIN              = 0xa5 # 165
OP_RIPEMD160           = 0xa6 # 166
OP_SHA1                = 0xa7 # 167
OP_SHA256              = 0xa8 # 168
OP_HASH160             = 0xa9 # 169
OP_HASH256             = 0xaa # 170
OP_CODESEPARATOR       = 0xab # 171
OP_CHECKSIG            = 0xac # 172
OP_CHECKSIGVERIFY      = 0xad # 173
OP_CHECKMULTISIG       = 0xae # 174
OP_CHECKMULTISIGVERIFY = 0xaf # 175
OP_NOP1                = 0xb0 # 176
OP_NOP2                = 0xb1 # 177
OP_CHECKLOCKTIMEVERIFY = 0xb1 # 177 - AKA OP_NOP2
OP_NOP3                = 0xb2 # 178
OP_NOP4                = 0xb3 # 179
OP_NOP5                = 0xb4 # 180
OP_NOP6                = 0xb5 # 181
OP_NOP7                = 0xb6 # 182
OP_NOP8                = 0xb7 # 183
OP_NOP9                = 0xb8 # 184
OP_NOP10               = 0xb9 # 185
OP_SSTX                = 0xba # 186 DECRED
OP_SSGEN               = 0xbb # 187 DECRED
OP_SSRTX               = 0xbc # 188 DECRED
OP_SSTXCHANGE          = 0xbd # 189 DECRED
OP_CHECKSIGALT         = 0xbe # 190 DECRED
OP_CHECKSIGALTVERIFY   = 0xbf # 191 DECRED
OP_UNKNOWN192          = 0xc0 # 192
OP_UNKNOWN193          = 0xc1 # 193
OP_UNKNOWN194          = 0xc2 # 194
OP_UNKNOWN195          = 0xc3 # 195
OP_UNKNOWN196          = 0xc4 # 196
OP_UNKNOWN197          = 0xc5 # 197
OP_UNKNOWN198          = 0xc6 # 198
OP_UNKNOWN199          = 0xc7 # 199
OP_UNKNOWN200          = 0xc8 # 200
OP_UNKNOWN201          = 0xc9 # 201
OP_UNKNOWN202          = 0xca # 202
OP_UNKNOWN203          = 0xcb # 203
OP_UNKNOWN204          = 0xcc # 204
OP_UNKNOWN205          = 0xcd # 205
OP_UNKNOWN206          = 0xce # 206
OP_UNKNOWN207          = 0xcf # 207
OP_UNKNOWN208          = 0xd0 # 208
OP_UNKNOWN209          = 0xd1 # 209
OP_UNKNOWN210          = 0xd2 # 210
OP_UNKNOWN211          = 0xd3 # 211
OP_UNKNOWN212          = 0xd4 # 212
OP_UNKNOWN213          = 0xd5 # 213
OP_UNKNOWN214          = 0xd6 # 214
OP_UNKNOWN215          = 0xd7 # 215
OP_UNKNOWN216          = 0xd8 # 216
OP_UNKNOWN217          = 0xd9 # 217
OP_UNKNOWN218          = 0xda # 218
OP_UNKNOWN219          = 0xdb # 219
OP_UNKNOWN220          = 0xdc # 220
OP_UNKNOWN221          = 0xdd # 221
OP_UNKNOWN222          = 0xde # 222
OP_UNKNOWN223          = 0xdf # 223
OP_UNKNOWN224          = 0xe0 # 224
OP_UNKNOWN225          = 0xe1 # 225
OP_UNKNOWN226          = 0xe2 # 226
OP_UNKNOWN227          = 0xe3 # 227
OP_UNKNOWN228          = 0xe4 # 228
OP_UNKNOWN229          = 0xe5 # 229
OP_UNKNOWN230          = 0xe6 # 230
OP_UNKNOWN231          = 0xe7 # 231
OP_UNKNOWN232          = 0xe8 # 232
OP_UNKNOWN233          = 0xe9 # 233
OP_UNKNOWN234          = 0xea # 234
OP_UNKNOWN235          = 0xeb # 235
OP_UNKNOWN236          = 0xec # 236
OP_UNKNOWN237          = 0xed # 237
OP_UNKNOWN238          = 0xee # 238
OP_UNKNOWN239          = 0xef # 239
OP_UNKNOWN240          = 0xf0 # 240
OP_UNKNOWN241          = 0xf1 # 241
OP_UNKNOWN242          = 0xf2 # 242
OP_UNKNOWN243          = 0xf3 # 243
OP_UNKNOWN244          = 0xf4 # 244
OP_UNKNOWN245          = 0xf5 # 245
OP_UNKNOWN246          = 0xf6 # 246
OP_UNKNOWN247          = 0xf7 # 247
OP_UNKNOWN248          = 0xf8 # 248
OP_SMALLDATA           = 0xf9 # 249 - bitcoin core internal
OP_SMALLINTEGER        = 0xfa # 250 - bitcoin core internal
OP_PUBKEYS             = 0xfb # 251 - bitcoin core internal
OP_UNKNOWN252          = 0xfc # 252
OP_PUBKEYHASH          = 0xfd # 253 - bitcoin core internal
OP_PUBKEY              = 0xfe # 254 - bitcoin core internal
OP_INVALIDOPCODE       = 0xff # 255 - bitcoin core internal

# Conditional execution constants.
OpCondFalse = 0
OpCondTrue  = 1
OpCondSkip  = 2

class ParsedOpcode(object):
    """Represents an opcode that has been parsed and includes any potential data associated with it."""
    def __init__(self, opcode, data):
        self.opcode = opcode
        self.data = data

    def human_readable(self, oneline=False):
	# The reference implementation one-line disassembly replaces opcodes
	# which represent values (e.g. OP_0 through OP_16 and OP_1NEGATE)
	# with the raw value.  However, when not doing a one-line dissassembly,
	# we prefer to show the actual opcode names.  Thus, only replace the
	# opcodes in question when the oneline flag is set.
        opcode_name = self.opcode.name
        if oneline:
            repl_name = opcodeOnelineRepls.get(opcode_name)
            if repl_name:
                opcode_name = repl_name

            # Nothing more to do for non-data push opcodes.
            if self.opcode.length == 1:
                return opcode_name

            return '%x' % self.data

        # Nothing more to do for non-data push opcodes.
        if self.opcode.length == 1:
            return opcode_name

        # Add length for the OP_PUSHDATA* opcodes.
        ret_string = opcode_name
        if self.opcode.length == -1:
            ret_string += ' 0x%02x' % len(self.data)
        elif self.opcode.length == -2:
            ret_string += ' 0x%04x' % len(self.data)
        elif self.opcode.length == -4:
            ret_string += ' 0x%08x' % len(self.data)

        return '%s 0x%02s' % (ret_string, binascii.hexlify(self.data))

    def __str__(self):
        return self.human_readable()

    def isDisabled(self):
        """Returns whether or not the opcode is disabled."""
        if self.opcode.value == OP_CODESEPARATOR:
            return True
        return False

    def alwaysIllegal(self):
        """Returns whether or not the opcode is always illegal.

        If so, it is illegal even in a non-executed branch.
        """
        if self.opcode.value in [OP_VERIF, OP_VERNOTIF]:
            return True
        return False


    def isConditional(self):
        """Returns whether or not the opcode is a conditional opcode.

        Conditional opcodes change the conditional execution stack.
        """
        if self.opcode.value in [OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF]:
            return True
        return False

    def checkMinimalDataPush(self):
        """checkMinimalDataPush returns whether or not the current data push uses the
        smallest possible opcode to represent it.

        For example, the value 15 could be pushed with OP_DATA_1 15 (among other variations);
        however, OP_15 is a single opcode that represents the same value and is only a single
        byte versus two bytes.
        """
        data = self.data
        data_len = len(self.data)
        opcode = self.opcode.value

        if data_len == 0 and opcode != OP_0:
            raise StackMinimalDataError()
        elif data_len == 1 and data[0] >= 1 and data[0] <= 16:
            # Should have used OP_1 ... OP_16
            raise StackMinimalDataError()
        elif data_len == 1 and data[0] == 0x81:
            if opcode != OP_1NEGATE:
                raise StackMinimalDataError()
        elif data_len <= 75:
            if int(opcode) != data_len:
                # Should have used a direct push.
                raise StackMinimalDataError()
        elif data_len <= 255:
            if opcode != OP_PUSHDATA1:
                raise StackMinimalDataError()
        elif data_len <= 65535:
            if opcode != OP_PUSHDATA2:
                raise StackMinimalDataError()

    def as_bytes(self):
        """Returns any data associated with the opcode.

        Data is encoded as it would be in a script. This is used for
        unparsing scripts from parsed opcodes.
        """
        ret_bytes = b''

        # ret_bytes[0]
        ret_bytes += _bchr(self.opcode.value)

        if self.opcode.length == 1:
            if len(self.data) != 0:
                raise StackInvalidOpcodeError()
            return ret_bytes

        n_bytes = self.opcode.length
        if self.opcode.length < 0:
            data_len = len(self.data)
            if self.opcode.length == -1:
                ret_bytes += _bchr(data_len)
                n_bytes = _bord(ret_bytes[1]) + len(ret_bytes)
            elif self.opcode.length == -2:
                ret_bytes += _bchr(data_len & 0xff) + _bchr(data_len >> 8 & 0xff)
                n_bytes = struct.unpack(b'<H', ret_bytes[1:])[0] + len(ret_bytes)
            elif self.opcode.length == -4:
                ret_bytes += _bchr(data_len & 0xff) + _bchr((data_len >> 8) & 0xff) + \
                             _bchr((data_len >> 16) & 0xff) + _bchr((data_len >> 24) & 0xff)
                n_bytes = struct.unpack(b'<I', ret_bytes[1:])[0] + len(ret_bytes)

        ret_bytes += self.data

        if len(ret_bytes) != n_bytes:
            raise StackInvalidOpcodeError()

        return ret_bytes


# *******************************************
# Opcode implementation functions start here.
# *******************************************

# opcodeDisabled is a common handler for disabled opcodes.  It returns an
# appropriate error indicating the opcode is disabled.  While it would
# ordinarily make more sense to detect if the script contains any disabled
# opcodes before executing in an initial parse step, the consensus rules
# dictate the script doesn't fail until the program counter passes over a
# disabled opcode (even when they appear in a branch that is not executed).
def opcodeDisabled(op, vm):
#    return StackOpDisabledError
    raise StackOpDisabledError()

# opcodeReserved is a common handler for all reserved opcodes.  It returns an
# appropriate error indicating the opcode is reserved.
def opcodeReserved(op, vm):
    raise StackReservedOpcodeError()

# opcodeInvalid is a common handler for all invalid opcodes.  It returns an
# appropriate error indicating the opcode is invalid.
def opcodeInvalid(op, vm):
    raise StackInvalidOpcodeError()

# opcodeFalse pushes an empty array to the data stack to represent false.  Note
# that 0, when encoded as a number according to the numeric encoding consensus
# rules, is an empty array.
def opcodeFalse(op, vm):
    vm.dstack.push_bytearray(b'')

# opcodePushData is a common handler for the vast majority of opcodes that push
# raw data (bytes) to the data stack.
def opcodePushData(op, vm):
    vm.dstack.push_bytearray(op.data)

# opcode1Negate pushes -1, encoded as a number, to the data stack.
def opcode1Negate(op, vm):
    vm.dstack.push_int(-1)

# opcodeN is a common handler for the small integer data push opcodes.  It
# pushes the numeric value the opcode represents (which will be from 1 to 16)
# onto the data stack.
def opcodeN(op, vm):
    # The opcodes are all defined consecutively, so the numeric value is
    # the difference.
    vm.dstack.push_int(op.opcode.value - (OP_1 - 1))

# opcodeNop is a common handler for the NOP family of opcodes.  As the name
# implies it generally does nothing, however, it will return an error when
# the flag to discourage use of NOPs is set for select opcodes.
def opcodeNop(op, vm):
    if op.opcode.value in [OP_NOP1, OP_NOP3,
                OP_NOP4, OP_NOP5, OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10,
                OP_UNKNOWN192, OP_UNKNOWN193, OP_UNKNOWN194, OP_UNKNOWN195,
		OP_UNKNOWN196, OP_UNKNOWN197, OP_UNKNOWN198, OP_UNKNOWN199,
		OP_UNKNOWN200, OP_UNKNOWN201, OP_UNKNOWN202, OP_UNKNOWN203,
		OP_UNKNOWN204, OP_UNKNOWN205, OP_UNKNOWN206, OP_UNKNOWN207,
		OP_UNKNOWN208, OP_UNKNOWN209, OP_UNKNOWN210, OP_UNKNOWN211,
		OP_UNKNOWN212, OP_UNKNOWN213, OP_UNKNOWN214, OP_UNKNOWN215,
		OP_UNKNOWN216, OP_UNKNOWN217, OP_UNKNOWN218, OP_UNKNOWN219,
		OP_UNKNOWN220, OP_UNKNOWN221, OP_UNKNOWN222, OP_UNKNOWN223,
		OP_UNKNOWN224, OP_UNKNOWN225, OP_UNKNOWN226, OP_UNKNOWN227,
		OP_UNKNOWN228, OP_UNKNOWN229, OP_UNKNOWN230, OP_UNKNOWN231,
		OP_UNKNOWN232, OP_UNKNOWN233, OP_UNKNOWN234, OP_UNKNOWN235,
		OP_UNKNOWN236, OP_UNKNOWN237, OP_UNKNOWN238, OP_UNKNOWN239,
		OP_UNKNOWN240, OP_UNKNOWN241, OP_UNKNOWN242, OP_UNKNOWN243,
		OP_UNKNOWN244, OP_UNKNOWN245, OP_UNKNOWN246, OP_UNKNOWN247,
                OP_UNKNOWN248
                ]:
        if vm.has_flag(ScriptDiscourageUpgradableNops):
            raise Exception('OP_NOP at %d reserved for soft-fork upgrades' % op.opcode.value)

# opcodeIf treats the top item on the data stack as a boolean and removes it.
#
# An appropriate entry is added to the conditional stack depending on whether
# the boolean is true and whether this if is on an executing branch in order
# to allow proper execution of further opcodes depending on the conditional
# logic.  When the boolean is true, the first branch will be executed (unless
# this opcode is nested in a non-executed branch).
#
# <expression> if [statements] [else [statements]] endif
#
# Note that, unlike for all non-conditional opcodes, this is executed even when
# it is on a non-executing branch so proper nesting is maintained.
#
# Data stack transformation: [... bool] -> [...]
# Conditional stack transformation: [...] -> [... OpCondValue]
def opcodeIf(op, vm):
    cond_val = OpCondFalse
    if vm.is_branch_executing():
        top_value = vm.dstack.pop_bool()
        if top_value:
            cond_val = OpCondTrue
    else:
        cond_val = OpCondSkip
    vm.cond_stack.append(cond_val)

# opcodeNotIf treats the top item on the data stack as a boolean and removes
# it.
#
# An appropriate entry is added to the conditional stack depending on whether
# the boolean is true and whether this if is on an executing branch in order
# to allow proper execution of further opcodes depending on the conditional
# logic.  When the boolean is false, the first branch will be executed (unless
# this opcode is nested in a non-executed branch).
#
# <expression> notif [statements] [else [statements]] endif
#
# Note that, unlike for all non-conditional opcodes, this is executed even when
# it is on a non-executing branch so proper nesting is maintained.
#
# Data stack transformation: [... bool] -> [...]
# Conditional stack transformation: [...] -> [... OpCondValue]
def opcodeNotIf(op, vm):
    cond_val = OpCondFalse
    if vm.is_branch_executing():
        top_value = vm.dstack.pop_bool()
        if not top_value:
            cond_val = OpCondTrue
    else:
        cond_val = OpCondSkip
    vm.cond_stack.append(cond_val)

# opcodeElse inverts conditional execution for other half of if/else/endif.
#
# An error is returned if there has not already been a matching OP_IF.
#
# Conditional stack transformation: [... OpCondValue] -> [... !OpCondValue]
def opcodeElse(op, vm):
    if len(vm.cond_stack) == 0:
        raise StackNoIfError()

    if vm.cond_stack[-1] == OpCondTrue:
        vm.cond_stack[-1] = OpCondFalse
    elif vm.cond_stack[-1] == OpCondFalse:
        vm.cond_stack[-1] = OpCondTrue

# opcodeEndif terminates a conditional block, removing the value from the
# conditional execution stack.
#
# An error is returned if there has not already been a matching OP_IF.
#
# Conditional stack transformation: [... OpCondValue] -> [...]
def opcodeEndif(op, vm):
    if len(vm.cond_stack) == 0:
        raise StackNoIfError()

    vm.cond_stack = vm.cond_stack[:-1]

# opcodeVerify examines the top item on the data stack as a boolean value and
# verifies it evaluates to true.  An error is returned if it does not.
def opcodeVerify(op, vm):
    verified = vm.dstack.pop_bool()
    if verified != True:
        raise StackVerifyFailedError()

# opcodeReturn returns an appropriate error since it is always an error to
# return early from a script.
def opcodeReturn(op, vm):
    raise StackEarlyReturnError()

def opcodeCheckLockTimeVerify(op, vm):
    # if ScriptVerifyCheckLockTimeVerify is not set, treat opcode as OP_NOP2.
    if not vm.has_flag(ScriptVerifyCheckLockTimeVerify):
        if vm.has_flag(ScriptDiscourageUpgradableNops):
            raise Exception('OP_NOP2 reserved for soft-fork upgrades')

    # The current transaction locktime is a uint32 resulting in a maximum
    # locktime of 2^32-1 (the year 2106).  However, scriptNums are signed
    # and therefore a standard 4-byte scriptNum would only support up to a
    # maximum of 2^31-1 (the year 2038).  Thus, a 5-byte scriptNum is used
    # here since it will support up to 2^39-1 which allows dates beyond the
    # current locktime limit.
    #
    # PeekByteArray is used here instead of PeekInt because we do not want
    # to be limited to a 4-byte integer for reasons specified above.
    so = vm.dstack.peek_bytearray(0)
    lockTime = script_num(so, vm.dstack.verifyMinimalData, 5)

    # In the rare event that the argument may be < 0 due to some arithmetic
    # being done first, you can always use 0 OP_MAX OP_CHECKLOCKTIMEVERIFY.
    if lockTime < 0:
        raise Exception('Negative locktime: %d' % lockTime)

    # The lock time field of a transaction is either a block height at
    # which the transaction is finalized or a timestamp depending on if the
    # value is before the txscript.LockTimeThreshold.  When it is under the
    # threshold it is a block height.
    #
    # The lockTimes in both the script and transaction must be of the same
    # type.
    if not ((vm.tx.locktime < LockTimeThreshold and lockTime < LockTimeThreshold) or
            (vm.tx.locktime >= LockTimeThreshold and lockTime >= LockTimeThreshold)):
        raise Exception('mismatched locktime types')

    if lockTime > vm.tx.locktime:
        raise Exception('locktime requirement not satisfied')

    # The lock time feature can also be disabled, thereby bypassing
    # OP_CHECKLOCKTIMEVERIFY, if every transaction input has been finalized by
    # setting its sequence to the maximum value (wire.MaxTxInSequenceNum).  This
    # condition would result in the transaction being allowed into the blockchain
    # making the opcode ineffective.
    #
    # This condition is prevented by enforcing that the input being used by
    # the opcode is unlocked (its sequence number is less than the max
    # value).  This is sufficient to prove correctness without having to
    # check every input.
    #
    # NOTE: This implies that even if the transaction is not finalized due to
    # another input being unlocked, the opcode execution will still fail when the
    # input being used by the opcode is locked.
    if vm.tx.txins[vm.tx_idx].sequence == MaxTxInSequenceNum:
        raise Exception('transaction input is finalized')

# opcodeToAltStack removes the top item from the main data stack and pushes it
# onto the alternate data stack.
#
# Main data stack transformation: [... x1 x2 x3] -> [... x1 x2]
# Alt data stack transformation:  [... y1 y2 y3] -> [... y1 y2 y3 x3]
def opcodeToAltStack(op, vm):
    val = vm.dstack.pop_bytearray()
    vm.astack.push_bytearray(val)

# opcodeFromAltStack removes the top item from the alternate data stack and
# pushes it onto the main data stack.
#
# Main data stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 y1]
# Alt data stack transformation:  [... y1 y2 y3] -> [... y1 y2]
def opcodeFromAltStack(op, vm):
    val = vm.astack.pop_bytearray()
    vm.dstack.push_bytearray(val)

# opcode2Drop removes the top 2 items from the data stack.
#
# Stack transformation: [... x1 x2 x3] -> [... x1]
def opcode2Drop(op, vm):
    return vm.dstack.drop(n)

# opcode2Dup duplicates the top 2 items on the data stack.
#
# Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x2 x3]
def opcode2Dup(op, vm):
    return vm.dstack.dup(2)

# opcode3Dup duplicates the top 3 items on the data stack.
#
# Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x1 x2 x3]
def opcode3Dup(op, vm):
    return vm.dstack.dup(3)

# opcode2Over duplicates the 2 items before the top 2 items on the data stack.
#
# Stack transformation: [... x1 x2 x3 x4] -> [... x1 x2 x3 x4 x1 x2]
def opcode2Over(op, vm):
    return vm.stack.over(2)

# opcode2Rot rotates the top 6 items on the data stack to the left twice.
#
# Stack transformation: [... x1 x2 x3 x4 x5 x6] -> [... x3 x4 x5 x6 x1 x2]
def opcode2Rot(op, vm):
    return vm.dstack.rot(2)

# opcode2Swap swaps the top 2 items on the data stack with the 2 that come
# before them.
#
# Stack transformation: [... x1 x2 x3 x4] -> [... x3 x4 x1 x2]
def opcode2Swap(op, vm):
    return vm.dstack.swap(2)

# opcodeIfDup duplicates the top item of the stack if it is not zero.
#
# Stack transformation (x1==0): [... x1] -> [...]
# Stack transformation (x1!=0): [... x1] -> [... x1]
def opcodeIfDup(op, vm):
    val = vm.dstack.peek_bytearray(0)
    if _CastToBool(val):
        vm.dstack.push_bytearray(val)

# opcodeDepth pushes the depth of the data stack prior to executing this
# opcode, encoded as a number, onto the data stack.
#
# Stack transformation: [...] -> [... <num of items on the stack>]
# Example with 2 items: [x1 x2] -> [x1 x2 2]
# Example with 3 items: [x1 x2 x3] -> [x1 x2 x3 3]
def opcodeDepth(op, vm):
    vm.dstack.push_int(vm.dstack.depth())

# opcodeDrop removes the top item from the data stack.
#
# Stack transformation: [... x1 x2 x3] -> [... x1 x2]
def opcodeDrop(op, vm):
    return vm.dstack.drop(1)

# opcodeDup duplicates the top item on the data stack.
#
# Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x3]
def opcodeDup(op, vm):
    return vm.dstack.dup(1)

# opcodeNip removes the item before the top item on the data stack.
#
# Stack transformation: [... x1 x2 x3] -> [... x1 x3]
def opcodeNip(op, vm):
    return vm.dstack.nip(1)

# opcodeOver duplicates the item before the top item on the data stack.
#
# Stack transformation: [... x1 x2 x3] -> [... x1 x2 x3 x2]
def opcodeOver(op, vm):
    return vm.dstack.over(1)

# opcodePick treats the top item on the data stack as an integer and duplicates
# the item on the stack that number of items back to the top.
#
# Stack transformation: [xn ... x2 x1 x0 n] -> [xn ... x2 x1 x0 xn]
# Example with n=1: [x2 x1 x0 1] -> [x2 x1 x0 x1]
# Example with n=2: [x2 x1 x0 2] -> [x2 x1 x0 x2]
def opcodePick(op, vm):
    val = vm.dstack.pop_int(math_op_code_max_script_num_len)
    return vm.dstack.pick(int_32(val))

# opcodeRoll treats the top item on the data stack as an integer and moves
# the item on the stack that number of items back to the top.
#
# Stack transformation: [xn ... x2 x1 x0 n] -> [... x2 x1 x0 xn]
# Example with n=1: [x2 x1 x0 1] -> [x2 x0 x1]
# Example with n=2: [x2 x1 x0 2] -> [x1 x0 x2]
def opcodeRoll(op, vm):
    val = vm.dstack.pop_int(math_op_code_max_script_num_len)
    return vm.dstack.roll(int_32(val))

# opcodeRot rotates the top 3 items on the data stack to the left.
#
# Stack transformation: [... x1 x2 x3] -> [... x2 x3 x1]
def opcodeRot(op, vm):
    return vm.dstack.rot(1)

# opcodeSwap swaps the top two items on the stack.
#
# Stack transformation: [... x1 x2] -> [... x2 x1]
def opcodeSwap(op, vm):
    return vm.dstack.swap(1)

# opcodeTuck inserts a duplicate of the top item of the data stack before the
# second-to-top item.
#
# Stack transformation: [... x1 x2] -> [... x2 x1 x2]
def opcodeTuck(op, vm):
    return vm.dstack.tuck()

# opcodeCat concatenates the top two stack elements after popping them off, then
# pushes the result back onto the stack. The opcode fails if the concatenated
# stack element is too large.
# Stack transformation: [... x1 x2] -> [... x1 || x2]
def opcodeCat(op, vm):
    a = vm.dstack.pop_bytearray() # x2
    b = vm.dstack.pop_bytearray() # x1

    # Handle zero-length byte slice cases. If one or both are empty,
    # it's impossible for them to overflow when either is pushed back on.
    if len(a) == 0 and len(b) > 0:
        vm.dstack.push_bytearray(b)
    elif len(b) == 0 and len(a) > 0:
        vm.dstack.push_bytearray(a)
    # If both are empty, push an empty byte slice back onto the stack.
    elif len(b) == 0 and len(a) == 0:
        vm.dstack.push_bytearray(b'')

    # Don't overflow the maximum stack size.
    if len(a) + len(b) > MaxScriptElementSize:
        raise StackElementTooBigError()

    c = b + a
    vm.dstack.push_bytearray(c)

# opcodeSubstr pops off the top two stack elements and interprets them as
# integers. If the indices indicated exist within the next stack item that is
# also popped off, return the relevant substring based on the given start and
# end indexes.
# Stack transformation: [... x1 x2 x3] -> [... x1[x3:x2]]
def opcodeSubstr(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x3
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x2
    a = vm.dstack.pop_bytearray() # x1
    a_len = len(a)

    # Assume that we can get whatever we need from a slice within the
    # boundaries of an int32 register.
    v0_recast = int_32(v0)
    v1_recast = int_32(v1)

    if a_len == 0:
        vm.dstack.push_bytearray(b'')
        return
    if v0_recast < 0 or v1_recast < 0:
        raise SubstrIdxNegativeError()
    if v0_recast > a_len:
        raise SubstrIdxOutOfBoundsError()
    if v1_recast > a_len:
        raise SubstrIdxOutOfBoundsError()
    if v0_recast > v1_recast:
        raise SubstrIdxOutOfBoundsError()

    # A substr of the same indices return an empty stack item.
    if v0_recast == v1_recast:
        vm.dstack.push_bytearray(b'')
        return
    vm.dstack.push_bytearray(a[v0_recast:v1_recast])

# opcodeLeft pops the first item off the stack as an int and the second item off
# the stack as a slice. The opcode then prunes the second item from the start
# index to the given int. Similar to substr, see above comments.
# Stack transformation: [... x1 x2] -> [... x1[:x2]]
def opcodeLeft(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x2
    a = vm.dstack.pop_bytearray() # x1
    a_len = len(a)

    v0_recast = int_32(v0)
    
    if a_len == 0:
        vm.dstack.push_bytearray(b'')
        return
    if v0_recast < 0:
        raise SubstrIdxNegativeError()
    if v0_recast > a_len:
        raise SubstrIdxOutOfBoundsError()

    # x1[:0]
    if v0_recast == 0:
        vm.dstack.push_bytearray(b'')
        return
    vm.dstack.push_bytearray(a[:v0_recast])

# opcodeRight pops the first item off the stack as an int and the second item off
# the stack as a slice. The opcode then prunes the second item from the given int
# index to ending index. Similar to substr, see above comments.
# Stack transformation: [... x1 x2] -> [... x1[x2:]]
def opcodeRight(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x2
    a = vm.dstack.pop_bytearray() # x1
    a_len = len(a)
    v0_recast = int_32(v0)

    if a_len == 0:
        vm.dstack.push_bytearray(b'')
        return
    if v0_recast < 0:
        raise SubstrIdxNegativeError()
    if v0_recast > a_len:
        raise SubstrIdxOutOfBoundsError()

    # x1[len(a):]
    if v0_recast == a_len:
        vm.dstack.push_bytearray(b'')
        return
    vm.dstack.push_bytearray(a[v0_recast:])

# opcodeSize pushes the size of the top item of the data stack onto the data
# stack.
#
# Stack transformation: [... x1] -> [... x1 len(x1)]
def opcodeSize(op, vm):
    val = vm.dstack.peek_bytearray(0)
    vm.dstack.push_int(len(val))

# opcodeInvert pops the top item off the stack, interprets it as an int32,
# inverts the bits, and then pushes it back to the stack.
# Stack transformation: [... x1] -> [... ~x1]
def opcodeInvert(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len)
    vm.dstack.push_int(~int_32(v0))

# opcodeAnd pops the top two items off the stack, interprets them as int32s,
# bitwise ANDs the value, and then pushes the result back to the stack.
# Stack transformation: [... x1 x2] -> [... x1 & x2]
def opcodeAnd(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len)
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len)

    vm.dstack.push_int(int_32(v0) & int_32(v1))

# opcodeOr pops the top two items off the stack, interprets them as int32s,
# bitwise ORs the value, and then pushes the result back to the stack.
# Stack transformation: [... x1 x2] -> [... x1 | x2]
def opcodeOr(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len)
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len)

    vm.dstack.push_int(int_32(v0) | int_32(v1))

# opcodeXor pops the top two items off the stack, interprets them as int32s,
# bitwise XORs the value, and then pushes the result back to the stack.
# Stack transformation: [... x1 x2] -> [... x1 ^ x2]
def opcodeXor(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len)
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len)

    vm.dstack.push_int(int_32(v0) ^ int_32(v1))

# opcodeEqual removes the top 2 items of the data stack, compares them as raw
# bytes, and pushes the result, encoded as a boolean, back to the stack.
#
# Stack transformation: [... x1 x2] -> [... bool]
def opcodeEqual(op, vm):
    a = vm.dstack.pop_bytearray()
    b = vm.dstack.pop_bytearray()

    vm.dstack.push_bool(a == b)

# opcodeEqualVerify is a combination of opcodeEqual and opcodeVerify.
# Specifically, it removes the top 2 items of the data stack, compares them,
# and pushes the result, encoded as a boolean, back to the stack.  Then, it
# examines the top item on the data stack as a boolean value and verifies it
# evaluates to true.  An error is returned if it does not.
#
# Stack transformation: [... x1 x2] -> [... bool] -> [...]
def opcodeEqualVerify(op, vm):
    opcodeEqual(op, vm)
    opcodeVerify(op, vm)

def rotate_right(value, count):
    return (value >> count) | (value << (32 - count))

# opcodeRotr pushes the top two items off the stack as integers. Both ints are
# interpreted as int32s. The first item becomes the depth to rotate (up to 31),
# while the second item is rotated to the right after recasting to a uint32. The
# rotated item is pushed back to the stack.
# Stack transformation: [... x1 x2] -> [... rotr(x1, x2)]
def opcodeRotr(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len)
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len)

    v032 = int_32(v0)
    v132 = int_32(v1)

    # Don't allow invalid or pointless rotations.
    if v032 < 0:
        raise NegativeRotationError()
    if v032 > 31:
        raise RotationOverflowError()

    vm.dstack.push_int(rotate_right(v132, v032))

def rotate_left(value, count):
    return (value << count) | (value >> (32 - count))

# opcodeRotl pushes the top two items off the stack as integers. Both ints are
# interpreted as int32s. The first item becomes the depth to rotate (up to 31),
# while the second item is rotated to the left after recasting to a uint32. The
# rotated item is pushed back to the stack.
# Stack transformation: [... x1 x2] -> [... rotl(x1, x2)]
def opcodeRotl(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len)
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len)

    v032 = int_32(v0)
    v132 = int_32(v1)

    # Don't allow invalid or pointless rotations.
    if v032 < 0:
        raise NegativeRotationError()
    if v032 > 31:
        raise RotationOverflowError()

    vm.dstack.push_int(rotate_left(v132, v032))

# opcode1Add treats the top item on the data stack as an integer and replaces
# it with its incremented value (plus 1).
#
# Stack transformation: [... x1 x2] -> [... x1 x2+1]
def opcode1Add(op, vm):
    m = vm.dstack.pop_int(math_op_code_max_script_num_len)
    vm.dstack.push_int(m + 1)

# opcode1Sub treats the top item on the data stack as an integer and replaces
# it with its decremented value (minus 1).
#
# Stack transformation: [... x1 x2] -> [... x1 x2-1]
def opcode1Sub(op, vm):
    m = vm.dstack.pop_int(math_op_code_max_script_num_len)
    vm.dstack.push_int(m - 1)

# opcodeNegate treats the top item on the data stack as an integer and replaces
# it with its negation.
#
# Stack transformation: [... x1 x2] -> [... x1 -x2]
def opcodeNegate(op, vm):
    m = vm.dstack.pop_int(math_op_code_max_script_num_len)
    vm.dstack.push_int(-m)

# opcodeAbs treats the top item on the data stack as an integer and replaces it
# it with its absolute value.
#
# Stack transformation: [... x1 x2] -> [... x1 abs(x2)]
def opcodeAbs(op, vm):
    m = vm.dstack.pop_int(math_op_code_max_script_num_len)
    if m < 0:
        m = -m
    vm.dstack.push_int(m)

# opcodeNot treats the top item on the data stack as an integer and replaces
# it with its "inverted" value (0 becomes 1, non-zero becomes 0).
#
# NOTE: While it would probably make more sense to treat the top item as a
# boolean, and push the opposite, which is really what the intention of this
# opcode is, it is extremely important that is not done because integers are
# interpreted differently than booleans and the consensus rules for this opcode
# dictate the item is interpreted as an integer.
#
# Stack transformation (x2==0): [... x1 0] -> [... x1 1]
# Stack transformation (x2!=0): [... x1 1] -> [... x1 0]
# Stack transformation (x2!=0): [... x1 17] -> [... x1 0]
def opcodeNot(op, vm):
    m = vm.dstack.pop_int(math_op_code_max_script_num_len)
    if m == 0:
        vm.dstack.push_int(0)
    else:
        vm.dstack.push_int(1)

# opcode0NotEqual treats the top item on the data stack as an integer and
# replaces it with either a 0 if it is zero, or a 1 if it is not zero.
#
# Stack transformation (x2==0): [... x1 0] -> [... x1 0]
# Stack transformation (x2!=0): [... x1 1] -> [... x1 1]
# Stack transformation (x2!=0): [... x1 17] -> [... x1 1]
def opcode0NotEqual(op, vm):
    m = vm.dstack.pop_int(math_op_code_max_script_num_len)
    if m != 0:
        m = 1
    vm.dstack.push_int(m)

# opcodeAdd treats the top two items on the data stack as integers and replaces
# them with their sum.
#
# Stack transformation: [... x1 x2] -> [... x1+x2]
def opcodeAdd(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len)
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len)

    vm.dstack.push_int(v0 + v1)

# opcodeSub treats the top two items on the data stack as integers and replaces
# them with the result of subtracting the top entry from the second-to-top
# entry.
#
# Stack transformation: [... x1 x2] -> [... x1-x2]
def opcodeSub(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len)
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len)

    vm.dstack.push_int(v1 - v0)

# opcodeMul treats the top two items on the data stack as integers and replaces
# them with the result of multiplying the top entry with the second-to-top
# entry as 4-byte integers.
#
# Stack transformation: [... x1 x2] -> [... x1*x2]
def opcodeMul(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len)
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len)

    v2 = int_32(v0) * int_32(v1)
    vm.dstack.push_int(v2)

# opcodeDiv treats the top two items on the data stack as integers and replaces
# them with the result of dividing the top entry by the second-to-top entry as
# 4-byte integers.
#
# Stack transformation: [... x1 x2] -> [... x1/x2]
def opcodeDiv(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len)
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len)

    if int_32(v0) == 0:
        raise DivideByZeroError()

    v2 = int_32(v1) / int_32(v0)
    vm.dstack.push_int(v2)

# opcodeMod treats the top two items on the data stack as integers and replaces
# them with the result of the modulus the top entry by the second-to-top entry as
# 4-byte integers.
#
# Stack transformation: [... x1 x2] -> [... x1/x2]
def opcodeMod(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len)
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len)

    if int_32(v0) == 0:
        raise DivideByZeroError()

    v2 = int_32(v1) % int_32(v0)
    vm.dstack.push_int(v2)

# opcodeLShift pushes the top two items off the stack as integers. Both ints are
# interpreted as int32s. The first item becomes the depth to shift left, while
# the second item is shifted that depth to the left. The shifted item is pushed
# back to the stack as an integer.
# Stack transformation: [... x1 x2] -> [... x1 << x2]
def opcodeLShift(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x2
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x1

    v032 = int_32(v0)
    v132 = int_32(v1)

    # Don't allow invalid or pointless shifts.
    if v032 < 0:
        raise NegativeShiftError()
    if v032 > 32:
        raise ShiftOverflowError()

    vm.dstack.push_int(v132 << v032)

# opcodeRShift pushes the top two items off the stack as integers. Both ints are
# interpreted as int32s. The first item becomes the depth to shift right, while
# the second item is shifted that depth to the right. The shifted item is pushed
# back to the stack as an integer.
# Stack transformation: [... x1 x2] -> [... x1 << x2]
def opcodeRShift(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x2
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x1

    v032 = int_32(v0)
    v132 = int_32(v1)

    # Don't allow invalid or pointless shifts.
    if v032 < 0:
        raise NegativeShiftError()
    if v032 > 32:
        raise ShiftOverflowError()

    vm.dstack.push_int(v132 >> v032)

# opcodeBoolAnd treats the top two items on the data stack as integers.  When
# both of them are not zero, they are replaced with a 1, otherwise a 0.
#
# Stack transformation (x1==0, x2==0): [... 0 0] -> [... 0]
# Stack transformation (x1!=0, x2==0): [... 5 0] -> [... 0]
# Stack transformation (x1==0, x2!=0): [... 0 7] -> [... 0]
# Stack transformation (x1!=0, x2!=0): [... 4 8] -> [... 1]
def opcodeBoolAnd(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x2
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x1

    if v0 != 0 and v1 != 0:
        vm.dstack.push_int(1)
    else:
        vm.dstack.push_int(0)

# opcodeBoolOr treats the top two items on the data stack as integers.  When
# either of them are not zero, they are replaced with a 1, otherwise a 0.
#
# Stack transformation (x1==0, x2==0): [... 0 0] -> [... 0]
# Stack transformation (x1!=0, x2==0): [... 5 0] -> [... 1]
# Stack transformation (x1==0, x2!=0): [... 0 7] -> [... 1]
# Stack transformation (x1!=0, x2!=0): [... 4 8] -> [... 1]
def opcodeBoolOr(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x2
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x1

    if v0 != 0 or v1 != 0:
        vm.dstack.push_int(1)
    else:
        vm.dstack.push_int(0)

# opcodeNumEqual treats the top two items on the data stack as integers.  When
# they are equal, they are replaced with a 1, otherwise a 0.
#
# Stack transformation (x1==x2): [... 5 5] -> [... 1]
# Stack transformation (x1!=x2): [... 5 7] -> [... 0]
def opcodeNumEqual(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x2
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x1

    if v0 == v1:
        vm.dstack.push_int(1)
    else:
        vm.dstack.push_int(0)

# opcodeNumEqualVerify is a combination of opcodeNumEqual and opcodeVerify.
#
# Specifically, treats the top two items on the data stack as integers.  When
# they are equal, they are replaced with a 1, otherwise a 0.  Then, it examines
# the top item on the data stack as a boolean value and verifies it evaluates
# to true.  An error is returned if it does not.
#
# Stack transformation: [... x1 x2] -> [... bool] -> [...]
def opcodeNumEqualVerify(op, vm):
    opcodeNumEqual(op, vm)
    opcodeVerify(op, vm)

# opcodeNumNotEqual treats the top two items on the data stack as integers.
# When they are NOT equal, they are replaced with a 1, otherwise a 0.
#
# Stack transformation (x1==x2): [... 5 5] -> [... 0]
# Stack transformation (x1!=x2): [... 5 7] -> [... 1]
def opcodeNumNotEqual(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x2
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x1

    if v0 != v1:
        vm.dstack.push_int(1)
    else:
        vm.dstack.push_int(0)

# opcodeLessThan treats the top two items on the data stack as integers.  When
# the second-to-top item is less than the top item, they are replaced with a 1,
# otherwise a 0.
#
# Stack transformation: [... x1 x2] -> [... bool]
def opcodeLessThan(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x2
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x1

    if v1 < v0:
        vm.dstack.push_int(1)
    else:
        vm.dstack.push_int(0)

# opcodeGreaterThan treats the top two items on the data stack as integers.
# When the second-to-top item is greater than the top item, they are replaced
# with a 1, otherwise a 0.
#
# Stack transformation: [... x1 x2] -> [... bool]
def opcodeGreaterThan(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x2
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x1

    if v1 > v0:
        vm.dstack.push_int(1)
    else:
        vm.dstack.push_int(0)

# opcodeLessThanOrEqual treats the top two items on the data stack as integers.
# When the second-to-top item is less than or equal to the top item, they are
# replaced with a 1, otherwise a 0.
#
# Stack transformation: [... x1 x2] -> [... bool]
def opcodeLessThanOrEqual(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x2
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x1

    if v1 <= v0:
        vm.dstack.push_int(1)
    else:
        vm.dstack.push_int(0)

# opcodeGreaterThanOrEqual treats the top two items on the data stack as
# integers.  When the second-to-top item is greater than or equal to the top
# item, they are replaced with a 1, otherwise a 0.
#
# Stack transformation: [... x1 x2] -> [... bool]
def opcodeGreaterThanOrEqual(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x2
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x1

    if v1 >= v0:
        vm.dstack.push_int(1)
    else:
        vm.dstack.push_int(0)

# opcodeMin treats the top two items on the data stack as integers and replaces
# them with the minimum of the two.
#
# Stack transformation: [... x1 x2] -> [... min(x1, x2)]
def opcodeMin(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x2
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x1

    if v1 < v0:
        vm.dstack.push_int(v1)
    else:
        vm.dstack.push_int(v0)

# opcodeMax treats the top two items on the data stack as integers and replaces
# them with the maximum of the two.
#
# Stack transformation: [... x1 x2] -> [... max(x1, x2)]
def opcodeMax(op, vm):
    v0 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x2
    v1 = vm.dstack.pop_int(math_op_code_max_script_num_len) # x1

    if v1 > v0:
        vm.dstack.push_int(v1)
    else:
        vm.dstack.push_int(v0)

# opcodeWithin treats the top 3 items on the data stack as integers.  When the
# value to test is within the specified range (left inclusive), they are
# replaced with a 1, otherwise a 0.
#
# The top item is the max value, the second-top-item is the minimum value, and
# the third-to-top item is the value to test.
#
# Stack transformation: [... x1 min max] -> [... bool]
def opcodeWithin(op, vm):
    max_val = vm.dstack.pop_int(math_op_code_max_script_num_len)
    min_val = vm.dstack.pop_int(math_op_code_max_script_num_len)
    x = vm.dstack.pop_int(math_op_code_max_script_num_len)

    if x >= min_val and x < max_val:
        vm.dstack.push_int(1)
    else:
        vm.dstack.push_int(0)

# opcodeRipemd160 treats the top item of the data stack as raw bytes and
# replaces it with ripemd160(data).
#
# Stack transformation: [... x1] -> [... ripemd160(x1)]
def opcodeRipemd160(op, vm):
    buf = vm.dstack.pop_bytearray()
    h = hashlib.new('ripemd160')
    h.update(buf)
    vm.dstack.push_bytearray(h.digest())

# opcodeSha1 treats the top item of the data stack as raw bytes and replaces it
# with sha1(data).
#
# Stack transformation: [... x1] -> [... sha1(x1)]
def opcodeSha1(op, vm):
    buf = vm.dstack.pop_bytearray()
    vm.dstack.push_bytearray(hashlib.sha1(buf).digest())

# opcodeSha256 treats the top item of the data stack as raw bytes and replaces
# it with hash256(data).
#
# Stack transformation: [... x1] -> [... hash256(x1)]
def opcodeSha256(op, vm):
    buf = vm.dstack.pop_bytearray()
    vm.dstack.push_bytearray(hashlib.sha256(buf).digest())

# opcodeHash160 treats the top item of the data stack as raw bytes and replaces
# it with ripemd160(hash256(data)).
#
# Stack transformation: [... x1] -> [... ripemd160(hash256(x1))]
def opcodeHash160(op, vm):
    buf = vm.dstack.pop_bytearray()
    vm.dstack.push_bytearray(Hash160(buf))

# opcodeHash256 treats the top item of the data stack as raw bytes and replaces
# it with hash256(hash256(data)).
#
# Stack transformation: [... x1] -> [... hash256(hash256(x1))]
def opcodeHash256(op, vm):
    buf = vm.dstack.pop_bytearray()
    vm.dstack.push_bytearray(DecredHash(buf))

# opcodeCodeSeparator stores the current script offset as the most recently
# seen OP_CODESEPARATOR which is used during signature checking.
#
# This opcode does not change the contents of the data stack.
# This opcode is disabled in Decred, as it always returns an engine error.
def opcodeCodeSeparator(op, vm):
    vm.last_code_sep = vm.script_off

# TODO
def opcodeCheckSig(op, vm):
    raise Exception('Not implemented')
"""
// opcodeCheckSig treats the top 2 items on the stack as a public key and a
// signature and replaces them with a bool which indicates if the signature was
// successfully verified.
//
// The process of verifying a signature requires calculating a signature hash in
// the same way the transaction signer did.  It involves hashing portions of the
// transaction based on the hash type byte (which is the final byte of the
// signature) and the portion of the script starting from the most recent
// OP_CODESEPARATOR (or the beginning of the script if there are none) to the
// end of the script (with any other OP_CODESEPARATORs removed).  Once this
// "script hash" is calculated, the signature is checked using standard
// cryptographic methods against the provided public key.
//
// Stack transformation: [... signature pubkey] -> [... bool]
func opcodeCheckSig(op *parsedOpcode, vm *Engine) error {
	pkBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	fullSigBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// The signature actually needs needs to be longer than this, but at
	// least 1 byte is needed for the hash type below.  The full length is
	// checked depending on the script flags and upon parsing the signature.
	if len(fullSigBytes) < 1 {
		vm.dstack.PushBool(false)
		return nil
	}

	// Trim off hashtype from the signature string and check if the
	// signature and pubkey conform to the strict encoding requirements
	// depending on the flags.
	//
	// NOTE: When the strict encoding flags are set, any errors in the
	// signature or public encoding here result in an immediate script error
	// (and thus no result bool is pushed to the data stack).  This differs
	// from the logic below where any errors in parsing the signature is
	// treated as the signature failure resulting in false being pushed to
	// the data stack.  This is required because the more general script
	// validation consensus rules do not have the new strict encoding
	// requirements enabled by the flags.
	hashType := SigHashType(fullSigBytes[len(fullSigBytes)-1])
	sigBytes := fullSigBytes[:len(fullSigBytes)-1]
	if err := vm.checkHashTypeEncoding(hashType); err != nil {
		return err
	}
	if err := vm.checkSignatureEncoding(sigBytes); err != nil {
		return err
	}
	if err := vm.checkPubKeyEncoding(pkBytes); err != nil {
		return err
	}

	// Get script starting from the most recent OP_CODESEPARATOR.
	subScript := vm.subScript()

	// Remove the signature since there is no way for a signature to sign
	// itself.
	subScript = removeOpcodeByData(subScript, fullSigBytes)

	// Generate the signature hash based on the signature hash type.
	var prefixHash *chainhash.Hash
	if hashType&sigHashMask == SigHashAll {
		if optimizeSigVerification {
			ph := vm.tx.CachedTxSha()
			prefixHash = ph
		}
	}
	hash, err := calcSignatureHash(subScript, hashType, &vm.tx, vm.txIdx,
		prefixHash)
	if err != nil {
		vm.dstack.PushBool(false)
		return nil
	}

	pubKey, err := chainec.Secp256k1.ParsePubKey(pkBytes)
	if err != nil {
		vm.dstack.PushBool(false)
		return nil
	}

	var signature chainec.Signature
	if vm.hasFlag(ScriptVerifyStrictEncoding) ||
		vm.hasFlag(ScriptVerifyDERSignatures) {
		signature, err = chainec.Secp256k1.ParseDERSignature(sigBytes)
	} else {
		signature, err = chainec.Secp256k1.ParseSignature(sigBytes)
	}
	if err != nil {
		vm.dstack.PushBool(false)
		return nil
	}

	ok := chainec.Secp256k1.Verify(pubKey, hash, signature.GetR(),
		signature.GetS())
	vm.dstack.PushBool(ok)
	return nil
}
"""

# opcodeCheckSigVerify is a combination of opcodeCheckSig and opcodeVerify.
# The opcodeCheckSig function is invoked followed by opcodeVerify.  See the
# documentation for each of those opcodes for more details.
#
# Stack transformation: signature pubkey] -> [... bool] -> [...]
def opcodeCheckSigVerify(op, vm):
    opcodeCheckSig(op, vm)
    opcodeVerify(op, vm)

# TODO
"""
// parsedSigInfo houses a raw signature along with its parsed form and a flag
// for whether or not it has already been parsed.  It is used to prevent parsing
// the same signature multiple times when verify a multisig.
type parsedSigInfo struct {
	signature       []byte
	parsedSignature chainec.Signature
	parsed          bool
}
"""

def opcodeCheckMultiSig(op, vm):
    raise Exception('Not implemented')
"""
// opcodeCheckMultiSig treats the top item on the stack as an integer number of
// public keys, followed by that many entries as raw data representing the public
// keys, followed by the integer number of signatures, followed by that many
// entries as raw data representing the signatures.
//
// All of the aforementioned stack items are replaced with a bool which
// indicates if the requisite number of signatures were successfully verified.
//
// See the opcodeCheckSigVerify documentation for more details about the process
// for verifying each signature.
//
// Stack transformation:
// [... dummy [sig ...] numsigs [pubkey ...] numpubkeys] -> [... bool]
func opcodeCheckMultiSig(op *parsedOpcode, vm *Engine) error {
	numKeys, err := vm.dstack.PopInt(mathOpCodeMaxScriptNumLen)
	if err != nil {
		return err
	}

	numPubKeys := int(numKeys.Int32())
	if numPubKeys < 0 || numPubKeys > MaxPubKeysPerMultiSig {
		return ErrStackTooManyPubkeys
	}
	vm.numOps += numPubKeys
	if vm.numOps > MaxOpsPerScript {
		return ErrStackTooManyOperations
	}

	pubKeys := make([][]byte, 0, numPubKeys)
	for i := 0; i < numPubKeys; i++ {
		pubKey, err := vm.dstack.PopByteArray()
		if err != nil {
			return err
		}
		pubKeys = append(pubKeys, pubKey)
	}

	numSigs, err := vm.dstack.PopInt(mathOpCodeMaxScriptNumLen)
	if err != nil {
		return err
	}
	numSignatures := int(numSigs.Int32())
	if numSignatures < 0 {
		return fmt.Errorf("number of signatures '%d' is less than 0",
			numSignatures)
	}
	if numSignatures > numPubKeys {
		return fmt.Errorf("more signatures than pubkeys: %d > %d",
			numSignatures, numPubKeys)
	}

	signatures := make([]*parsedSigInfo, 0, numSignatures)
	for i := 0; i < numSignatures; i++ {
		signature, err := vm.dstack.PopByteArray()
		if err != nil {
			return err
		}
		sigInfo := &parsedSigInfo{signature: signature}
		signatures = append(signatures, sigInfo)
	}

	// Get script starting from the most recent OP_CODESEPARATOR.
	script := vm.subScript()

	// Remove any of the signatures since there is no way for a signature to
	// sign itself.
	for _, sigInfo := range signatures {
		script = removeOpcodeByData(script, sigInfo.signature)
	}

	success := true
	numPubKeys++
	pubKeyIdx := -1
	signatureIdx := 0
	for numSignatures > 0 {
		// When there are more signatures than public keys remaining,
		// there is no way to succeed since too many signatures are
		// invalid, so exit early.
		pubKeyIdx++
		numPubKeys--
		if numSignatures > numPubKeys {
			success = false
			break
		}

		sigInfo := signatures[signatureIdx]
		pubKey := pubKeys[pubKeyIdx]

		// The order of the signature and public key evaluation is
		// important here since it can be distinguished by an
		// OP_CHECKMULTISIG NOT when the strict encoding flag is set.

		rawSig := sigInfo.signature
		if len(rawSig) == 0 {
			// Skip to the next pubkey if signature is empty.
			continue
		}

		// Split the signature into hash type and signature components.
		hashType := SigHashType(rawSig[len(rawSig)-1])
		signature := rawSig[:len(rawSig)-1]

		// Only parse and check the signature encoding once.
		var parsedSig chainec.Signature
		if !sigInfo.parsed {
			if err := vm.checkHashTypeEncoding(hashType); err != nil {
				return err
			}
			if err := vm.checkSignatureEncoding(signature); err != nil {
				return err
			}

			// Parse the signature.
			var err error
			if vm.hasFlag(ScriptVerifyStrictEncoding) ||
				vm.hasFlag(ScriptVerifyDERSignatures) {

				parsedSig, err = chainec.Secp256k1.ParseDERSignature(signature)
			} else {
				parsedSig, err = chainec.Secp256k1.ParseSignature(signature)
			}
			sigInfo.parsed = true
			if err != nil {
				continue
			}
			sigInfo.parsedSignature = parsedSig
		} else {
			// Skip to the next pubkey if the signature is invalid.
			if sigInfo.parsedSignature == nil {
				continue
			}

			// Use the already parsed signature.
			parsedSig = sigInfo.parsedSignature
		}

		if err := vm.checkPubKeyEncoding(pubKey); err != nil {
			return err
		}

		// Parse the pubkey.
		parsedPubKey, err := chainec.Secp256k1.ParsePubKey(pubKey)
		if err != nil {
			continue
		}

		// Generate the signature hash based on the signature hash type.
		var prefixHash *chainhash.Hash
		if hashType&sigHashMask == SigHashAll {
			if optimizeSigVerification {
				ph := vm.tx.CachedTxSha()
				prefixHash = ph
			}
		}
		hash, err := calcSignatureHash(script, hashType, &vm.tx, vm.txIdx,
			prefixHash)
		if err != nil {
			return err
		}

		//if parsedSig.Verify(hash, parsedPubKey) {
		if chainec.Secp256k1.Verify(parsedPubKey, hash, parsedSig.GetR(),
			parsedSig.GetS()) {
			// PubKey verified, move on to the next signature.
			signatureIdx++
			numSignatures--
		}
	}

	vm.dstack.PushBool(success)
	return nil
}
"""

# opcodeCheckMultiSigVerify is a combination of opcodeCheckMultiSig and
# opcodeVerify.  The opcodeCheckMultiSig is invoked followed by opcodeVerify.
# See the documentation for each of those opcodes for more details.
#
# Stack transformation:
# [... dummy [sig ...] numsigs [pubkey ...] numpubkeys] -> [... bool] -> [...]
def opcodeCheckMultiSigVerify(op, vm):
    opcodeCheckMultiSig(op, vm)
    opcodeVerify(op, vm)

# TODO
def opcodeCheckSigAlt(op, vm):
    raise Exception('Not implemented')

# ECDSA signature schemes encoded as a single byte. Secp256k1 traditional
# is non-accessible through CheckSigAlt, but is used elsewhere for in the
# sign function to indicate the type of signature to generate.
secp = ECTypeSecp256k1
edwards = ECTypeEdwards
secSchnorr = ECTypeSecSchnorr

"""
// opcodeCheckSigAlt accepts a three item stack and pops off the first three
// items. The first item is a signature type (1-255, can not be zero or the
// soft fork will fail). Any unused signature types return true, so that future
// alternative signature methods may be added. The second item popped off the
// stack is the public key; wrong size pubkeys return false. The third item to
// be popped off the stack is the signature along with the hash type at the
// end; wrong sized signatures also return false.
// Failing to parse a pubkey or signature results in false.
// After parsing, the signature and pubkey are verified against the message
// (the hash of this transaction and its input).
func opcodeCheckSigAlt(op *parsedOpcode, vm *Engine) error {
	sigType, err := vm.dstack.PopInt(altSigSuitesMaxscriptNumLen)
	if err != nil {
		return err
	}

	switch sigTypes(sigType) {
	case sigTypes(0):
		// Zero case; pre-softfork clients will return 0 in this case as well.
		vm.dstack.PushBool(false)
		return nil
	case edwards:
		break
	case secSchnorr:
		break
	default:
		// Caveat: All unknown signature types return true, allowing for future
		// softforks with other new signature types.
		vm.dstack.PushBool(true)
		return nil
	}

	pkBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// Check the public key lengths. Only 33-byte compressed secp256k1 keys
	// are allowed for secp256k1 Schnorr signatures, which 32 byte keys
	// are used for Curve25519.
	switch sigTypes(sigType) {
	case edwards:
		if len(pkBytes) != 32 {
			vm.dstack.PushBool(false)
			return nil
		}
	case secSchnorr:
		if len(pkBytes) != 33 {
			vm.dstack.PushBool(false)
			return nil
		}
	}

	fullSigBytes, err := vm.dstack.PopByteArray()
	if err != nil {
		return err
	}

	// Schnorr signatures are 65 bytes in length (64 bytes for [r,s] and
	// 1 byte appened to the end for hashType).
	switch sigTypes(sigType) {
	case edwards:
		if len(fullSigBytes) != 65 {
			vm.dstack.PushBool(false)
			return nil
		}
	case secSchnorr:
		if len(fullSigBytes) != 65 {
			vm.dstack.PushBool(false)
			return nil
		}
	}

	// Trim off hashtype from the signature string and check if the
	// signature and pubkey conform to the strict encoding requirements
	// depending on the flags.
	//
	// NOTE: When the strict encoding flags are set, any errors in the
	// signature or public encoding here result in an immediate script error
	// (and thus no result bool is pushed to the data stack).  This differs
	// from the logic below where any errors in parsing the signature is
	// treated as the signature failure resulting in false being pushed to
	// the data stack.  This is required because the more general script
	// validation consensus rules do not have the new strict encoding
	// requirements enabled by the flags.
	hashType := SigHashType(fullSigBytes[len(fullSigBytes)-1])
	sigBytes := fullSigBytes[:len(fullSigBytes)-1]
	if err := vm.checkHashTypeEncoding(hashType); err != nil {
		return err
	}

	// Get the subscript.
	subScript := vm.subScript()

	// Remove the signature since there is no way for a signature to sign
	// itself.
	subScript = removeOpcodeByData(subScript, fullSigBytes)

	// Generate the signature hash based on the signature hash type.
	var prefixHash *chainhash.Hash
	if hashType&sigHashMask == SigHashAll {
		if optimizeSigVerification {
			ph := vm.tx.CachedTxSha()
			prefixHash = ph
		}
	}
	hash, err := calcSignatureHash(subScript, hashType, &vm.tx, vm.txIdx,
		prefixHash)
	if err != nil {
		vm.dstack.PushBool(false)
		return nil
	}

	// Get the public key from bytes.
	var pubKey chainec.PublicKey
	switch sigTypes(sigType) {
	case edwards:
		pubKeyEd, err := chainec.Edwards.ParsePubKey(pkBytes)
		if err != nil {
			vm.dstack.PushBool(false)
			return nil
		}
		pubKey = pubKeyEd
	case secSchnorr:
		pubKeySec, err := chainec.SecSchnorr.ParsePubKey(pkBytes)
		if err != nil {
			vm.dstack.PushBool(false)
			return nil
		}
		pubKey = pubKeySec
	}

	// Get the signature from bytes.
	var signature chainec.Signature
	switch sigTypes(sigType) {
	case edwards:
		sigEd, err := chainec.Edwards.ParseSignature(sigBytes)
		if err != nil {
			vm.dstack.PushBool(false)
			return nil
		}
		signature = sigEd
	case secSchnorr:
		sigSec, err := chainec.SecSchnorr.ParseSignature(sigBytes)
		if err != nil {
			vm.dstack.PushBool(false)
			return nil
		}
		signature = sigSec
	default:
		vm.dstack.PushBool(false)
		return nil
	}

	// Attempt to validate the signature.
	switch sigTypes(sigType) {
	case edwards:
		ok := chainec.Edwards.Verify(pubKey, hash, signature.GetR(),
			signature.GetS())
		vm.dstack.PushBool(ok)
		return nil
	case secSchnorr:
		ok := chainec.SecSchnorr.Verify(pubKey, hash, signature.GetR(),
			signature.GetS())
		vm.dstack.PushBool(ok)
		return nil
	}

	// Fallthrough of somekind automatically results in false, but
	// this should never be hit.
	vm.dstack.PushBool(false)
	return nil
}
"""

# opcodeCheckSigAltVerify is a combination of opcodeCheckSigAlt and
# opcodeVerify.  The opcodeCheckSigAlt is invoked followed by opcodeVerify.
def opcodeCheckSigAltVerify(op, vm):
    opcodeCheckSigAlt(op, vm)
    opcodeVerify(op, vm)

# opcodeArray holds details about all possible opcodes such as how many bytes
# the opcode and any associated data should take, its human-readable name, and
# the handler function.
opcodeArray = [
    # Data push opcodes.
    Opcode(OP_FALSE, "OP_0", 1, opcodeFalse),
    Opcode(OP_DATA_1, "OP_DATA_1", 2, opcodePushData),
    Opcode(OP_DATA_2, "OP_DATA_2", 3, opcodePushData),
    Opcode(OP_DATA_3, "OP_DATA_3", 4, opcodePushData),
    Opcode(OP_DATA_4, "OP_DATA_4", 5, opcodePushData),
    Opcode(OP_DATA_5, "OP_DATA_5", 6, opcodePushData),
    Opcode(OP_DATA_6, "OP_DATA_6", 7, opcodePushData),
    Opcode(OP_DATA_7, "OP_DATA_7", 8, opcodePushData),
    Opcode(OP_DATA_8, "OP_DATA_8", 9, opcodePushData),
    Opcode(OP_DATA_9, "OP_DATA_9", 10, opcodePushData),
    Opcode(OP_DATA_10, "OP_DATA_10", 11, opcodePushData),
    Opcode(OP_DATA_11, "OP_DATA_11", 12, opcodePushData),
    Opcode(OP_DATA_12, "OP_DATA_12", 13, opcodePushData),
    Opcode(OP_DATA_13, "OP_DATA_13", 14, opcodePushData),
    Opcode(OP_DATA_14, "OP_DATA_14", 15, opcodePushData),
    Opcode(OP_DATA_15, "OP_DATA_15", 16, opcodePushData),
    Opcode(OP_DATA_16, "OP_DATA_16", 17, opcodePushData),
    Opcode(OP_DATA_17, "OP_DATA_17", 18, opcodePushData),
    Opcode(OP_DATA_18, "OP_DATA_18", 19, opcodePushData),
    Opcode(OP_DATA_19, "OP_DATA_19", 20, opcodePushData),
    Opcode(OP_DATA_20, "OP_DATA_20", 21, opcodePushData),
    Opcode(OP_DATA_21, "OP_DATA_21", 22, opcodePushData),
    Opcode(OP_DATA_22, "OP_DATA_22", 23, opcodePushData),
    Opcode(OP_DATA_23, "OP_DATA_23", 24, opcodePushData),
    Opcode(OP_DATA_24, "OP_DATA_24", 25, opcodePushData),
    Opcode(OP_DATA_25, "OP_DATA_25", 26, opcodePushData),
    Opcode(OP_DATA_26, "OP_DATA_26", 27, opcodePushData),
    Opcode(OP_DATA_27, "OP_DATA_27", 28, opcodePushData),
    Opcode(OP_DATA_28, "OP_DATA_28", 29, opcodePushData),
    Opcode(OP_DATA_29, "OP_DATA_29", 30, opcodePushData),
    Opcode(OP_DATA_30, "OP_DATA_30", 31, opcodePushData),
    Opcode(OP_DATA_31, "OP_DATA_31", 32, opcodePushData),
    Opcode(OP_DATA_32, "OP_DATA_32", 33, opcodePushData),
    Opcode(OP_DATA_33, "OP_DATA_33", 34, opcodePushData),
    Opcode(OP_DATA_34, "OP_DATA_34", 35, opcodePushData),
    Opcode(OP_DATA_35, "OP_DATA_35", 36, opcodePushData),
    Opcode(OP_DATA_36, "OP_DATA_36", 37, opcodePushData),
    Opcode(OP_DATA_37, "OP_DATA_37", 38, opcodePushData),
    Opcode(OP_DATA_38, "OP_DATA_38", 39, opcodePushData),
    Opcode(OP_DATA_39, "OP_DATA_39", 40, opcodePushData),
    Opcode(OP_DATA_40, "OP_DATA_40", 41, opcodePushData),
    Opcode(OP_DATA_41, "OP_DATA_41", 42, opcodePushData),
    Opcode(OP_DATA_42, "OP_DATA_42", 43, opcodePushData),
    Opcode(OP_DATA_43, "OP_DATA_43", 44, opcodePushData),
    Opcode(OP_DATA_44, "OP_DATA_44", 45, opcodePushData),
    Opcode(OP_DATA_45, "OP_DATA_45", 46, opcodePushData),
    Opcode(OP_DATA_46, "OP_DATA_46", 47, opcodePushData),
    Opcode(OP_DATA_47, "OP_DATA_47", 48, opcodePushData),
    Opcode(OP_DATA_48, "OP_DATA_48", 49, opcodePushData),
    Opcode(OP_DATA_49, "OP_DATA_49", 50, opcodePushData),
    Opcode(OP_DATA_50, "OP_DATA_50", 51, opcodePushData),
    Opcode(OP_DATA_51, "OP_DATA_51", 52, opcodePushData),
    Opcode(OP_DATA_52, "OP_DATA_52", 53, opcodePushData),
    Opcode(OP_DATA_53, "OP_DATA_53", 54, opcodePushData),
    Opcode(OP_DATA_54, "OP_DATA_54", 55, opcodePushData),
    Opcode(OP_DATA_55, "OP_DATA_55", 56, opcodePushData),
    Opcode(OP_DATA_56, "OP_DATA_56", 57, opcodePushData),
    Opcode(OP_DATA_57, "OP_DATA_57", 58, opcodePushData),
    Opcode(OP_DATA_58, "OP_DATA_58", 59, opcodePushData),
    Opcode(OP_DATA_59, "OP_DATA_59", 60, opcodePushData),
    Opcode(OP_DATA_60, "OP_DATA_60", 61, opcodePushData),
    Opcode(OP_DATA_61, "OP_DATA_61", 62, opcodePushData),
    Opcode(OP_DATA_62, "OP_DATA_62", 63, opcodePushData),
    Opcode(OP_DATA_63, "OP_DATA_63", 64, opcodePushData),
    Opcode(OP_DATA_64, "OP_DATA_64", 65, opcodePushData),
    Opcode(OP_DATA_65, "OP_DATA_65", 66, opcodePushData),
    Opcode(OP_DATA_66, "OP_DATA_66", 67, opcodePushData),
    Opcode(OP_DATA_67, "OP_DATA_67", 68, opcodePushData),
    Opcode(OP_DATA_68, "OP_DATA_68", 69, opcodePushData),
    Opcode(OP_DATA_69, "OP_DATA_69", 70, opcodePushData),
    Opcode(OP_DATA_70, "OP_DATA_70", 71, opcodePushData),
    Opcode(OP_DATA_71, "OP_DATA_71", 72, opcodePushData),
    Opcode(OP_DATA_72, "OP_DATA_72", 73, opcodePushData),
    Opcode(OP_DATA_73, "OP_DATA_73", 74, opcodePushData),
    Opcode(OP_DATA_74, "OP_DATA_74", 75, opcodePushData),
    Opcode(OP_DATA_75, "OP_DATA_75", 76, opcodePushData),
    Opcode(OP_PUSHDATA1, "OP_PUSHDATA1", -1, opcodePushData),
    Opcode(OP_PUSHDATA2, "OP_PUSHDATA2", -2, opcodePushData),
    Opcode(OP_PUSHDATA4, "OP_PUSHDATA4", -4, opcodePushData),
    Opcode(OP_1NEGATE, "OP_1NEGATE", 1, opcode1Negate),
    Opcode(OP_RESERVED, "OP_RESERVED", 1, opcodeReserved),
    Opcode(OP_TRUE, "OP_1", 1, opcodeN),
    Opcode(OP_2, "OP_2", 1, opcodeN),
    Opcode(OP_3, "OP_3", 1, opcodeN),
    Opcode(OP_4, "OP_4", 1, opcodeN),
    Opcode(OP_5, "OP_5", 1, opcodeN),
    Opcode(OP_6, "OP_6", 1, opcodeN),
    Opcode(OP_7, "OP_7", 1, opcodeN),
    Opcode(OP_8, "OP_8", 1, opcodeN),
    Opcode(OP_9, "OP_9", 1, opcodeN),
    Opcode(OP_10, "OP_10", 1, opcodeN),
    Opcode(OP_11, "OP_11", 1, opcodeN),
    Opcode(OP_12, "OP_12", 1, opcodeN),
    Opcode(OP_13, "OP_13", 1, opcodeN),
    Opcode(OP_14, "OP_14", 1, opcodeN),
    Opcode(OP_15, "OP_15", 1, opcodeN),
    Opcode(OP_16, "OP_16", 1, opcodeN),

    # Control opcodes.
    Opcode(OP_NOP, "OP_NOP", 1, opcodeNop),
    Opcode(OP_VER, "OP_VER", 1, opcodeReserved),
    Opcode(OP_IF, "OP_IF", 1, opcodeIf),
    Opcode(OP_NOTIF, "OP_NOTIF", 1, opcodeNotIf),
    Opcode(OP_VERIF, "OP_VERIF", 1, opcodeReserved),
    Opcode(OP_VERNOTIF, "OP_VERNOTIF", 1, opcodeReserved),
    Opcode(OP_ELSE, "OP_ELSE", 1, opcodeElse),
    Opcode(OP_ENDIF, "OP_ENDIF", 1, opcodeEndif),
    Opcode(OP_VERIFY, "OP_VERIFY", 1, opcodeVerify),
    Opcode(OP_RETURN, "OP_RETURN", 1, opcodeReturn),

    # Stack opcodes.
    Opcode(OP_TOALTSTACK, "OP_TOALTSTACK", 1, opcodeToAltStack),
    Opcode(OP_FROMALTSTACK, "OP_FROMALTSTACK", 1, opcodeFromAltStack),
    Opcode(OP_2DROP, "OP_2DROP", 1, opcode2Drop),
    Opcode(OP_2DUP, "OP_2DUP", 1, opcode2Dup),
    Opcode(OP_3DUP, "OP_3DUP", 1, opcode3Dup),
    Opcode(OP_2OVER, "OP_2OVER", 1, opcode2Over),
    Opcode(OP_2ROT, "OP_2ROT", 1, opcode2Rot),
    Opcode(OP_2SWAP, "OP_2SWAP", 1, opcode2Swap),
    Opcode(OP_IFDUP, "OP_IFDUP", 1, opcodeIfDup),
    Opcode(OP_DEPTH, "OP_DEPTH", 1, opcodeDepth),
    Opcode(OP_DROP, "OP_DROP", 1, opcodeDrop),
    Opcode(OP_DUP, "OP_DUP", 1, opcodeDup),
    Opcode(OP_NIP, "OP_NIP", 1, opcodeNip),
    Opcode(OP_OVER, "OP_OVER", 1, opcodeOver),
    Opcode(OP_PICK, "OP_PICK", 1, opcodePick),
    Opcode(OP_ROLL, "OP_ROLL", 1, opcodeRoll),
    Opcode(OP_ROT, "OP_ROT", 1, opcodeRot),
    Opcode(OP_SWAP, "OP_SWAP", 1, opcodeSwap),
    Opcode(OP_TUCK, "OP_TUCK", 1, opcodeTuck),

    # Splice opcodes.
    Opcode(OP_CAT, "OP_CAT", 1, opcodeCat),
    Opcode(OP_SUBSTR, "OP_SUBSTR", 1, opcodeSubstr),
    Opcode(OP_LEFT, "OP_LEFT", 1, opcodeLeft),
    Opcode(OP_RIGHT, "OP_RIGHT", 1, opcodeRight),
    Opcode(OP_SIZE, "OP_SIZE", 1, opcodeSize),

    # Bitwise logic opcodes for int32 registers derived from the stack.
    Opcode(OP_INVERT, "OP_INVERT", 1, opcodeInvert),
    Opcode(OP_AND, "OP_AND", 1, opcodeAnd),
    Opcode(OP_OR, "OP_OR", 1, opcodeOr),
    Opcode(OP_XOR, "OP_XOR", 1, opcodeXor),

    # Bytewise comparison function opcodes for byte strings.
    Opcode(OP_EQUAL, "OP_EQUAL", 1, opcodeEqual),
    Opcode(OP_EQUALVERIFY, "OP_EQUALVERIFY", 1, opcodeEqualVerify),

    # Bitwise rotation opcodes for an int32 register derived from the stack.
    Opcode(OP_ROTR, "OP_ROTR", 1, opcodeRotr),
    Opcode(OP_ROTL, "OP_ROTL", 1, opcodeRotl),

    # Numeric related opcodes.
    Opcode(OP_1ADD, "OP_1ADD", 1, opcode1Add),
    Opcode(OP_1SUB, "OP_1SUB", 1, opcode1Sub),
    Opcode(OP_2MUL, "OP_2MUL", 1, opcodeNop),
    Opcode(OP_2DIV, "OP_2DIV", 1, opcodeNop),
    Opcode(OP_NEGATE, "OP_NEGATE", 1, opcodeNegate),
    Opcode(OP_ABS, "OP_ABS", 1, opcodeAbs),
    Opcode(OP_NOT, "OP_NOT", 1, opcodeNot),
    Opcode(OP_0NOTEQUAL, "OP_0NOTEQUAL", 1, opcode0NotEqual),
    Opcode(OP_ADD, "OP_ADD", 1, opcodeAdd),
    Opcode(OP_SUB, "OP_SUB", 1, opcodeSub),
    Opcode(OP_MUL, "OP_MUL", 1, opcodeMul),
    Opcode(OP_DIV, "OP_DIV", 1, opcodeDiv),
    Opcode(OP_MOD, "OP_MOD", 1, opcodeMod),
    Opcode(OP_LSHIFT, "OP_LSHIFT", 1, opcodeLShift),
    Opcode(OP_RSHIFT, "OP_RSHIFT", 1, opcodeRShift),
    Opcode(OP_BOOLAND, "OP_BOOLAND", 1, opcodeBoolAnd),
    Opcode(OP_BOOLOR, "OP_BOOLOR", 1, opcodeBoolOr),
    Opcode(OP_NUMEQUAL, "OP_NUMEQUAL", 1, opcodeNumEqual),
    Opcode(OP_NUMEQUALVERIFY, "OP_NUMEQUALVERIFY", 1, opcodeNumEqualVerify),
    Opcode(OP_NUMNOTEQUAL, "OP_NUMNOTEQUAL", 1, opcodeNumNotEqual),
    Opcode(OP_LESSTHAN, "OP_LESSTHAN", 1, opcodeLessThan),
    Opcode(OP_GREATERTHAN, "OP_GREATERTHAN", 1, opcodeGreaterThan),
    Opcode(OP_LESSTHANOREQUAL, "OP_LESSTHANOREQUAL", 1, opcodeLessThanOrEqual),
    Opcode(OP_GREATERTHANOREQUAL, "OP_GREATERTHANOREQUAL", 1, opcodeGreaterThanOrEqual),
    Opcode(OP_MIN, "OP_MIN", 1, opcodeMin),
    Opcode(OP_MAX, "OP_MAX", 1, opcodeMax),
    Opcode(OP_WITHIN, "OP_WITHIN", 1, opcodeWithin),

    # Crypto opcodes.
    Opcode(OP_RIPEMD160, "OP_RIPEMD160", 1, opcodeRipemd160),
    Opcode(OP_SHA1, "OP_SHA1", 1, opcodeSha1),
    Opcode(OP_SHA256, "OP_SHA256", 1, opcodeSha256),
    Opcode(OP_HASH160, "OP_HASH160", 1, opcodeHash160),
    Opcode(OP_HASH256, "OP_HASH256", 1, opcodeHash256),
    Opcode(OP_CODESEPARATOR, "OP_CODESEPARATOR", 1, opcodeDisabled), # Disabled
    Opcode(OP_CHECKSIG, "OP_CHECKSIG", 1, opcodeCheckSig),
    Opcode(OP_CHECKSIGVERIFY, "OP_CHECKSIGVERIFY", 1, opcodeCheckSigVerify),
    Opcode(OP_CHECKMULTISIG, "OP_CHECKMULTISIG", 1, opcodeCheckMultiSig),
    Opcode(OP_CHECKMULTISIGVERIFY, "OP_CHECKMULTISIGVERIFY", 1, opcodeCheckMultiSigVerify),

    # Reserved opcodes.
    Opcode(OP_NOP1, "OP_NOP1", 1, opcodeNop),
    Opcode(OP_CHECKLOCKTIMEVERIFY, "OP_CHECKLOCKTIMEVERIFY", 1, opcodeCheckLockTimeVerify),
    Opcode(OP_NOP3, "OP_NOP3", 1, opcodeNop),
    Opcode(OP_NOP4, "OP_NOP4", 1, opcodeNop),
    Opcode(OP_NOP5, "OP_NOP5", 1, opcodeNop),
    Opcode(OP_NOP6, "OP_NOP6", 1, opcodeNop),
    Opcode(OP_NOP7, "OP_NOP7", 1, opcodeNop),
    Opcode(OP_NOP8, "OP_NOP8", 1, opcodeNop),
    Opcode(OP_NOP9, "OP_NOP9", 1, opcodeNop),
    Opcode(OP_NOP10, "OP_NOP10", 1, opcodeNop),

    # SS* opcodes.
    Opcode(OP_SSTX, "OP_SSTX", 1, opcodeNop),
    Opcode(OP_SSGEN, "OP_SSGEN", 1, opcodeNop),
    Opcode(OP_SSRTX, "OP_SSRTX", 1, opcodeNop),
    Opcode(OP_SSTXCHANGE, "OP_SSTXCHANGE", 1, opcodeNop),

    # Alternative checksig opcode.
    Opcode(OP_CHECKSIGALT, "OP_CHECKSIGALT", 1, opcodeCheckSigAlt),
    Opcode(OP_CHECKSIGALTVERIFY, "OP_CHECKSIGALTVERIFY", 1, opcodeCheckSigAltVerify),

    # Undefined opcodes.
    Opcode(OP_UNKNOWN192, "OP_UNKNOWN192", 1, opcodeNop),
    Opcode(OP_UNKNOWN193, "OP_UNKNOWN193", 1, opcodeNop),
    Opcode(OP_UNKNOWN194, "OP_UNKNOWN194", 1, opcodeNop),
    Opcode(OP_UNKNOWN195, "OP_UNKNOWN195", 1, opcodeNop),
    Opcode(OP_UNKNOWN196, "OP_UNKNOWN196", 1, opcodeNop),
    Opcode(OP_UNKNOWN197, "OP_UNKNOWN197", 1, opcodeNop),
    Opcode(OP_UNKNOWN198, "OP_UNKNOWN198", 1, opcodeNop),
    Opcode(OP_UNKNOWN199, "OP_UNKNOWN199", 1, opcodeNop),
    Opcode(OP_UNKNOWN200, "OP_UNKNOWN200", 1, opcodeNop),
    Opcode(OP_UNKNOWN201, "OP_UNKNOWN201", 1, opcodeNop),
    Opcode(OP_UNKNOWN202, "OP_UNKNOWN202", 1, opcodeNop),
    Opcode(OP_UNKNOWN203, "OP_UNKNOWN203", 1, opcodeNop),
    Opcode(OP_UNKNOWN204, "OP_UNKNOWN204", 1, opcodeNop),
    Opcode(OP_UNKNOWN205, "OP_UNKNOWN205", 1, opcodeNop),
    Opcode(OP_UNKNOWN206, "OP_UNKNOWN206", 1, opcodeNop),
    Opcode(OP_UNKNOWN207, "OP_UNKNOWN207", 1, opcodeNop),
    Opcode(OP_UNKNOWN208, "OP_UNKNOWN208", 1, opcodeNop),
    Opcode(OP_UNKNOWN209, "OP_UNKNOWN209", 1, opcodeNop),
    Opcode(OP_UNKNOWN210, "OP_UNKNOWN210", 1, opcodeNop),
    Opcode(OP_UNKNOWN211, "OP_UNKNOWN211", 1, opcodeNop),
    Opcode(OP_UNKNOWN212, "OP_UNKNOWN212", 1, opcodeNop),
    Opcode(OP_UNKNOWN213, "OP_UNKNOWN213", 1, opcodeNop),
    Opcode(OP_UNKNOWN214, "OP_UNKNOWN214", 1, opcodeNop),
    Opcode(OP_UNKNOWN215, "OP_UNKNOWN215", 1, opcodeNop),
    Opcode(OP_UNKNOWN216, "OP_UNKNOWN216", 1, opcodeNop),
    Opcode(OP_UNKNOWN217, "OP_UNKNOWN217", 1, opcodeNop),
    Opcode(OP_UNKNOWN218, "OP_UNKNOWN218", 1, opcodeNop),
    Opcode(OP_UNKNOWN219, "OP_UNKNOWN219", 1, opcodeNop),
    Opcode(OP_UNKNOWN220, "OP_UNKNOWN220", 1, opcodeNop),
    Opcode(OP_UNKNOWN221, "OP_UNKNOWN221", 1, opcodeNop),
    Opcode(OP_UNKNOWN222, "OP_UNKNOWN222", 1, opcodeNop),
    Opcode(OP_UNKNOWN223, "OP_UNKNOWN223", 1, opcodeNop),
    Opcode(OP_UNKNOWN224, "OP_UNKNOWN224", 1, opcodeNop),
    Opcode(OP_UNKNOWN225, "OP_UNKNOWN225", 1, opcodeNop),
    Opcode(OP_UNKNOWN226, "OP_UNKNOWN226", 1, opcodeNop),
    Opcode(OP_UNKNOWN227, "OP_UNKNOWN227", 1, opcodeNop),
    Opcode(OP_UNKNOWN228, "OP_UNKNOWN228", 1, opcodeNop),
    Opcode(OP_UNKNOWN229, "OP_UNKNOWN229", 1, opcodeNop),
    Opcode(OP_UNKNOWN230, "OP_UNKNOWN230", 1, opcodeNop),
    Opcode(OP_UNKNOWN231, "OP_UNKNOWN231", 1, opcodeNop),
    Opcode(OP_UNKNOWN232, "OP_UNKNOWN232", 1, opcodeNop),
    Opcode(OP_UNKNOWN233, "OP_UNKNOWN233", 1, opcodeNop),
    Opcode(OP_UNKNOWN234, "OP_UNKNOWN234", 1, opcodeNop),
    Opcode(OP_UNKNOWN235, "OP_UNKNOWN235", 1, opcodeNop),
    Opcode(OP_UNKNOWN236, "OP_UNKNOWN236", 1, opcodeNop),
    Opcode(OP_UNKNOWN237, "OP_UNKNOWN237", 1, opcodeNop),
    Opcode(OP_UNKNOWN238, "OP_UNKNOWN238", 1, opcodeNop),
    Opcode(OP_UNKNOWN239, "OP_UNKNOWN239", 1, opcodeNop),
    Opcode(OP_UNKNOWN240, "OP_UNKNOWN240", 1, opcodeNop),
    Opcode(OP_UNKNOWN241, "OP_UNKNOWN241", 1, opcodeNop),
    Opcode(OP_UNKNOWN242, "OP_UNKNOWN242", 1, opcodeNop),
    Opcode(OP_UNKNOWN243, "OP_UNKNOWN243", 1, opcodeNop),
    Opcode(OP_UNKNOWN244, "OP_UNKNOWN244", 1, opcodeNop),
    Opcode(OP_UNKNOWN245, "OP_UNKNOWN245", 1, opcodeNop),
    Opcode(OP_UNKNOWN246, "OP_UNKNOWN246", 1, opcodeNop),
    Opcode(OP_UNKNOWN247, "OP_UNKNOWN247", 1, opcodeNop),
    Opcode(OP_UNKNOWN248, "OP_UNKNOWN248", 1, opcodeNop),

    # Bitcoin Core internal use opcode.  Defined here for completeness.
    Opcode(OP_SMALLDATA, "OP_SMALLDATA", 1, opcodeInvalid),
    Opcode(OP_SMALLINTEGER, "OP_SMALLINTEGER", 1, opcodeInvalid),
    Opcode(OP_PUBKEYS, "OP_PUBKEYS", 1, opcodeInvalid),
    Opcode(OP_UNKNOWN252, "OP_UNKNOWN252", 1, opcodeInvalid),
    Opcode(OP_PUBKEYHASH, "OP_PUBKEYHASH", 1, opcodeInvalid),
    Opcode(OP_PUBKEY, "OP_PUBKEY", 1, opcodeInvalid),

    Opcode(OP_INVALIDOPCODE, "OP_INVALIDOPCODE", 1, opcodeInvalid),
]

# opcodeOnelineRepls defines opcode names which are replaced when doing a
# one-line disassembly.  This is done to match the output of the reference
# implementation while not changing the opcode names in the nicer full
# disassembly.
opcodeOnelineRepls = {
    "OP_1NEGATE": "-1",
    "OP_0":       "0",
    "OP_1":       "1",
    "OP_2":       "2",
    "OP_3":       "3",
    "OP_4":       "4",
    "OP_5":       "5",
    "OP_6":       "6",
    "OP_7":       "7",
    "OP_8":       "8",
    "OP_9":       "9",
    "OP_10":      "10",
    "OP_11":      "11",
    "OP_12":      "12",
    "OP_13":      "13",
    "OP_14":      "14",
    "OP_15":      "15",
    "OP_16":      "16",
}

OpcodeByName = {}
for op in opcodeArray:
    OpcodeByName[op.name] = op.value
OpcodeByName['OP_FALSE'] = OP_FALSE
OpcodeByName['OP_TRUE'] = OP_TRUE
OpcodeByName['OP_NOP2'] = OP_CHECKLOCKTIMEVERIFY

