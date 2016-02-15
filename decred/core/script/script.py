from __future__ import absolute_import
from io import BytesIO
import struct
import sys

from decred.core.chaincfg import sig_hash_optimization
from decred.core.serialize import DecredHash
from .opcode import *
from .constants import *

_bord = ord
if sys.version > '3':
    _bord = lambda x: x

def isSmallInt(op):
    """Returns whether or not op is considered a small integer."""
    if op.value == OP_0 or (op.value >= OP_1 and op.value <= OP_16):
        return True
    return False

def IsPayToScriptHash(script):
    """Returns whether script is in the standard P2SH format."""
    pops = parseScript(script)
    return isScriptHash(pops)

def isPushOnly(pops):
    """Returns whether the script only pushes data."""
    for pop in pops:
        if pop.opcode.value > OP_16:
            return False
    return True

def IsPushOnlyScript(script):
    pops = parseScript(script)
    return isPushOnly(pops)

#def HasP2SHScriptSigStakeOpCodes(version, scriptSig, scriptPubKey):
# Moved to standard.py

def parseScriptTemplate(script, opcodes):
    retScript = []
    i = 0
    while i < len(script):
        instr = _bord(script[i])
        op = opcodes[instr]
        pop = ParsedOpcode(op, b'')
        # Parse data out of instruction.

        # No additional data.
        if op.length == 1:
            i += 1
        # Data pushes of specific length (e.g. OP_DATA_20)
        elif op.length > 1:
            if len(script[i:]) < op.length:
                raise StackShortScriptError()
            pop.data = script[i+1 : i+op.length]
            i += op.length
        # Data pushes with parsed lengths (e.g. OP_PUDHDATAP1)
        elif op.length < 0:
            L = 0
            off = i + 1
            if len(script[off:]) < -op.length:
                raise StackShortScriptError()

            # Next -length bytes are little endian length of data.
            if op.length == -1:
                L = script[off]
            elif op.length == -2:
                L = (script[off+1] << 8) | script[off]
            elif op.length == -4:
                L = (script[off+3] << 24) | (script[off+2] << 16) | (script[off+1] << 8) | script[off]
            else:
                raise Exception('invalid opcode length: %d' % op.length)

            # Move offset to beginning of the data.
            off += -op.length

            # Disallow entries that do not fit script or were sign extended.
            if L > len(script[off:]) or L < 0:
                raise StackShortScriptError()

            pop.data = script[off: off+L]
            i += 1 - op.length + L

        retScript.append(pop)

    return retScript

def ParseScript(script):
    return parseScriptTemplate(script, opcodeArray)

def parseScript(script):
    """Preparses the script in bytes into a list of ParsedOpcodes while applying sanity checks."""
    return parseScriptTemplate(script, opcodeArray)

def unparseScript(pops):
    """Reverses the action of parseScript."""
    script = b''
    for pop in pops:
        b = pop.as_bytes()
        script += b
    return script

def DisasmString(buf):
    """Formats the disassembled script for one line printing."""
    disbuf = ''
    opcodes = parseScript(buf)
    for pop in opcodes:
        disbuf += pop.human_readable(oneline=True)
    if disbuf:
        disbuf = disbuf[:-1]
    return disbuf

def removeOpcode(pkscript, opcode):
    """Removes any occurrence of opcode from pkscript."""
    retScript = b''
    for pop in pkscript:
        if pop.opcode.value != opcode:
            retScript += pop
    return retScript

def canonicalPush(pop):
    """Returns True if either not a push instruction or the push is canonical."""
    op = pop.opcode.value
    data = pop.data
    dlen = len(pop.data)

    if op > OP_16:
        return True

    if op < OP_PUSHDATA1 and op > OP_0 and (dlen == 1 and data[0] <= 16):
        return False
    if op == OP_PUSHDATA1 and dlen < OP_PUSHDATA1:
        return False
    if op == OP_PUSHDATA2 and dlen <= 0xff:
        return False
    if op == OP_PUSHDATA4 and dlen <= 0xffff:
        return False
    return True

def removeOpcodeByData(pkscript, data):
    """Returns the script minus any opcodes that would push data."""
    retScript = b''
    for pop in pkscript:
        if not canonicalPush(pop) or not data in pop.data:
            retScript += pop
    return retScript

def CalcSignatureHash(script, hashType, tx, idx, cachedPrefix):
    return calcSignatureHash(script, hashType, tx, idx, cachedPrefix)

def calcSignatureHash(script, hashType, tx, idx, cachedPrefix):
    """Calculate the signature hash to be used for signing and verification."""
    pass

    # The SigHashSingle signature type signs only the corresponding input
    # and output (the output with the same index number as the input).
    #
    # Since transactions can have more inputs than outputs, this means it
    # is improper to use SigHashSingle on input indices that don't have a
    # corresponding output.
    #
    # A bug in the original Satoshi client implementation means specifying
    # an index that is out of range results in a signature hash of 1 (as a
    # uint256 little endian).  The original intent appeared to be to
    # indicate failure, but unfortunately, it was never checked and thus is
    # treated as the actual signature hash.  This buggy behavior is now
    # part of the consensus and a hard fork would be required to fix it.
    #
    # Due to this, care must be taken by software that creates transactions
    # which make use of SigHashSingle because it can lead to an extremely
    # dangerous situation where the invalid inputs will end up signing a
    # hash of 1.  This in turn presents an opportunity for attackers to
    # cleverly construct transactions which can steal those coins provided
    # they can reuse signatures.
    #
    # Decred mitigates this by actually returning an error instead.
    if hashType&sigHashMask == SigHashSingle and idx >= len(tx.TxOut):
            raise SighashSingleIdxError()

    # Remove all instances of OP_CODESEPARATOR from the script.
    script = removeOpcode(script, OP_CODESEPARATOR)

    # Make a deep copy of the transaction, zeroing out the script for all
    # inputs that are not currently being processed.
    txCopy = Transaction.from_tx(tx)
    for i in range(len(txCopy.txins)):
        txIn = txCopy.txins[i]
        if i == idx:
            sigScript = unparseScript(script)
            txCopy.txins[idx].sig_script = sigScript
        else:
            txCopy.txins[i].sig_script = b''

    # Default behavior has all outputs set up.
    # for i := range txCopy.TxOut {
    #         var txOut wire.TxOut
    #         txOut = *txCopy.TxOut[i]
    #         txCopy.TxOut[i] = &txOut
    # }

    htype = hashType & sigHashMask
    if htype == SigHashNone:
        txCopy.txouts = txCopy.txouts[0:0] # Empty slice.
        for i, txin in enumerate(txCopy.txins):
            if i != idx:
                txin.sequence = 0
    elif htype == SigHashSingle:
        # Resize outputs to up to and including requested index.
        txCopy.txouts = txCopy.txouts[:idx+1]

        # All but the current output gets zeroed out.
        for i, txout in enumerate(txCopy.txouts):
            if i < idx:
                txout.value = -1
                txout.pk_script = b''

        # Sequence on all other inputs is 0, too.
        for i, txin in enumerate(txCopy.txins):
            if i != idx:
                txin.sequence = 0

    if hashType & SigHashAnyOneCanPay != 0:
        txCopy.txins = txCopy.txins[idx : idx+1]
        idx = 0

    # The final hash (message to sign) is the hash of:
    # 1) hash of the prefix ||
    # 2) hash of the witness for signing ||
    # 3) the hash type (encoded as a 4-byte little-endian value)
    buf = BytesIO()
    buf.write(struct.pack(b'<I', hashType))

    # Optimization for SIGHASH_ALL. In this case, the prefix hash is
    # the same as the transaction hash because only the inputs have
    # been modified, so don't bother to do the wasteful O(N^2) extra
    # hash here.
    # The caching only works if the "anyone can pay flag" is also
    # disabled.
    if cachedPrefix and \
            (hashType & sigHashMask == SigHashAll) and \
            (hashType & SigHashAnyOneCanPay == 0) and \
            sig_hash_optimization:
        prefixHash = cachedPrefix
    else:
        prefixHash = txCopy.tx_sha()

    # If the ValueIn is to be included in what we're signing, sign
    # the witness hash that includes it. Otherwise, just sign the
    # prefix and signature scripts.
    if hashType & sigHashMask != SigHashAllValue:
        witnessHash = txCopy.tx_sha_witness_signing()
    else:
        witnessHash = txCopy.tx_sha_witness_value_signing()

    buf.write(prefixHash)
    buf.write(witnessHash)
    buf.seek(0) # Necessary?
    return DecredHash(buf.read())

def asSmallInt(op):
    """Returns the passed opcode as an integer."""
    if op.value == OP_0:
        return 0
    return op.value - (OP_1 - 1)

def getSigOpCount(pops, precise):
    """Counts the number of signature operations.

    If precise is True, then we attempt to count the number of operations
    for a multisig op. Otherwise we use the maximum.
    """
    nSigs = 0
    for i, pop in enumerate(pops):
        if pop.opcode.value in [OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGALT, OP_CHECKSIGALTVERIFY,
                                OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY]:
            # If precise, look for familiar patterns for multisig.
            if precise and i > 0 and \
                    pops[i-1].opcode.value >= OP_1 and \
                    pops[i-1].opcode.value <= OP_16:
                nSigs += asSmallInt(pops[i-1].opcode)
            else:
                nSigs += MaxPubKeysPerMultiSig

    return nSigs

def GetSigOpCount(script):
    """Count the signature operations in a script.

    CHECKSIG counts as 1. CHECK_MULTISIG counts as 20.
    """
    pops = parseScript(script)
    return getSigOpCount(pops, False)

def GetPreciseSigOpCount(scriptSig, scriptPubKey, bip16):
    """Returns the number of signature operations in scriptPubKey.

    If bip16 is True, then scriptSig may be searched for the P2SH script
    in order to find the precise number of signature operations.
    """
    pops = parseScript(scriptPubKey)

    # Treat non-P2SH as normal.
    if not (bip16 and isScriptHash(pops)):
        return getSigOpCount(pops, True)

    # The public key script is P2SH. Parse the signature script.
    # Scripts that fail to parse count as 0 signature operations.
    try:
        sigPops = parseScript(scriptSig)
    except Exception:
        return 0
    # The signature script must only push data to the stack.
    if not isPushOnly(sigPops) or len(sigPops) == 0:
        return 0

    # P2SH script is the last item the signature script pushes.
    shScript = sigPops[-1].data
    if len(shScript) == 0:
        return 0

    # Parse the P2SH script.
    shPops = parseScript(shScript)
    return getSigOpCount(shPops, True)

