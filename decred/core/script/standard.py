from __future__ import absolute_import

from .script import *
from .engine import *
from .opcode import *
from .scriptbuilder import *
from .constants import *

### TODO ###
# This file is only partially ported from dcrd. #
############

# Max bytes allowed in pushed data for a nulldate transaction.
maxDataCarrierSize = 256

StandardVerifyFlags = ScriptBip16 | \
        ScriptVerifyDERSignatures | \
        ScriptVerifyStrictEncoding | \
        ScriptVerifyMinimalData | \
        ScriptDiscourageUpgradableNops | \
        ScriptVerifyCleanStack | \
        ScriptVerifyCheckLockTimeVerify | \
        ScriptVerifyLowS


# Classes of script payment known about in the blockchain.
NonStandardTy       = 0             # None of the recognized forms.
PubKeyTy            = 1             # Pay pubkey.
PubKeyHashTy        = 2             # Pay pubkey hash.
ScriptHashTy        = 3             # Pay to script hash.
MultiSigTy          = 4             # Multi signature.
NullDataTy          = 5             # Empty data-only (provably prunable).
StakeSubmissionTy   = 6             # Stake submission.
StakeGenTy          = 7             # Stake generation
StakeRevocationTy   = 8             # Stake revocation.
StakeSubChangeTy    = 9             # Change for stake submission tx.
PubkeyAltTy         = 10            # Alternative signature pubkey.
PubkeyHashAltTy     = 11            # Alternative signature pubkey hash.

scriptClassToName = {
    NonStandardTy:     "nonstandard",
    PubKeyTy:          "pubkey",
    PubkeyAltTy:       "pubkeyalt",
    PubKeyHashTy:      "pubkeyhash",
    PubkeyHashAltTy:   "pubkeyhashalt",
    ScriptHashTy:      "scripthash",
    MultiSigTy:        "multisig",
    NullDataTy:        "nulldata",
    StakeSubmissionTy: "stakesubmission",
    StakeGenTy:        "stakegen",
    StakeRevocationTy: "stakerevoke",
    StakeSubChangeTy:  "sstxchange",
}

# Moved here from script.py
def HasP2SHScriptSigStakeOpCodes(version, scriptSig, scriptPubKey):
    _class = GetScriptClass(version, scriptPubKey)
    if IsStakeOutput(scriptPubKey):
        _class = GetStakeOutSubclass(scriptPubKey)
    if _class == ScriptHashTy:
        # Obtain the embedded pkScript from scriptSig.
        # Ensure it does not use and stake tagging opcodes.
        shScript = GetPkScriptFromP2SHSigScript(scriptSig)
        hasStakeOpCodes = ContainsStakeOpCodes(shScript)
        if hasStakeOpCodes:
            raise P2SHStakeOpCodesError()

def isPubkey(pops):
    """Returns true if the script passed is a pay-to-pubkey transaction."""
    return (len(pops) == 2 and
        (len(pops[0].data) == 33 or len(pops[0].data) == 65) and
        pops[1].opcode.value == OP_CHECKSIG)

def isOneByteMaxDataPush(po):
    """Returns true if the parsed opcode pushed exactly one byte to the stack."""
    return po.opcode.value in [OP_1, OP_2, OP_3, OP_4, OP_5, OP_6,
            OP_7, OP_8, OP_9, OP_10, OP_11, OP_12, OP_13, OP_14,
            OP_15, OP_16, OP_DATA_1]

def isPubkeyAlt(pops):
    """Returns true if the script is an alternative pay-to-pubkey transaction."""
    return (len(pops) == 3 and
        len(pops[0].data) < 512 and
        isOneByteMaxDataPush(pops[1]) and
        pops[2].opcode.value == OP_CHECKSIGALT)

def isPubkeyHash(pops):
    """Returns true if the script is a pay-to-pubkey-hash transaction."""
    return (len(pops) == 5 and
        pops[0].opcode.value == OP_DUP and
        pops[1].opcode.value == OP_HASH160 and
        pops[2].opcode.value == OP_DATA_20 and
        pops[3].opcode.value == OP_EQUALVERIFY and
        pops[4].opcode.value == OP_CHECKSIG)

def isPubkeyHashAlt(pops):
    """Returns true if the script is a pay-to-pubkey-hash transaction."""
    return (len(pops) == 6 and
        pops[0].opcode.value == OP_DUP and
        pops[1].opcode.value == OP_HASH160 and
        pops[2].opcode.value == OP_DATA_20 and
        pops[3].opcode.value == OP_EQUALVERIFY and
        isOneByteMaxDataPush(pops[4]) and
        pops[5].opcode.value == OP_CHECKSIGALT)

def isScriptHash(pops):
    """Returns true is the script is a pay-to-script-hash transaction."""
    return (len(pops) == 3 and
        pops[0].opcode.value == OP_HASH160 and
        pops[1].opcode.value == OP_DATA_20 and
        pops[2].opcode.value == OP_EQUAL)

def isAnyKindOfScriptHash(pops):
    """Returns true if the script is a pay-to-script-hash or stake pay-to-script-hash transaction."""
    standardP2SH = (len(pops) == 3 and
        pops[0].opcode.value == OP_HASH160 and
        pops[1].opcode.value == OP_DATA_20 and
        pops[2].opcode.value == OP_EQUAL)
    if standardP2SH:
        return True

    stakeP2SH = (len(pops) == 4 and
        (pops[0].opcode.value >= 186 and pops[0].opcode.value <= 189) and
        pops[1].opcode.value == OP_HASH160 and
        pops[2].opcode.value == OP_DATA_20 and
        pops[3].opcode.value == OP_EQUAL)
    if stakeP2SH:
        return True
    return False

def isMultiSig(pops):
    """Returns true if the script is a multisig transaction."""
    # Absolute minimum is 1 pubkey.
    if len(pops) < 4:
        return False
    if not isSmallInt(pops[0].opcode):
        return False
    if not isSmallInt(pops[-2].opcode):
        return False
    if pops[-1].opcode.value != OP_CHECKMULTISIG:
        return False

    # Verify the number of pubkeys specified matches the actual number provided.
    if len(pops) - 3 != asSmallInt(pops[-2].opcode):
        return False

    for pop in pops[1:-2]:
        if len(pop.data) != 33 and len(pop.data) != 65:
            return False
    return True

def isMultisigScript(script):
    """Returns whether script is a multisignature script."""
    pops = parseScript(script)
    return isMultiSig(pops)

def isMultisigSigScript(script):
    """Returns whether script is a multisignature script."""
    if len(script) == 0 or script is None:
        return False
    pops = parseScript(script)
    subPops = parseScript(pops[-1].data)
    return isMultiSig(subPops)

def isNullData(pops):
    """Returns whether script is a null data transaction."""
    if len(pops) == 1 and pops[0].opcode.value == OP_RETURN:
        return True

    return (len(pops) == 2 and
        pops[0].opcode.value == OP_RETURN and
        pops[1].opcode.value <= OP_PUSHDATA4 and
        len(pops[1].data) <= maxDataCarrierSize)

def isStakeSubmission(pops):
    """Returns whether script is a stake submission transaction."""
    if (len(pops) == 6 and
            pops[0].opcode.value == OP_SSTX and
            pops[1].opcode.value == OP_DUP and
            pops[2].opcode.value == OP_HASH160 and
            pops[3].opcode.value == OP_DATA_20 and
            pops[4].opcode.value == OP_EQUALVERIFY and
            pops[5].opcode.value == OP_CHECKSIG):
        return True

    if (len(pops) == 4 and
            pops[0].opcode.value == OP_SSTX and
            pops[1].opcode.value == OP_HASH160 and
            pops[2].opcode.value == OP_DATA_20 and
            pops[3].opcode.value == OP_EQUAL):
        return True

    return False

def isStakeGen(pops):
    """Returns whether the script is a stake generation transaction."""
    if (len(pops) == 6 and
            pops[0].opcode.value == OP_SSGEN and
            pops[1].opcode.value == OP_DUP and
            pops[2].opcode.value == OP_HASH160 and
            pops[3].opcode.value == OP_DATA_20 and
            pops[4].opcode.value == OP_EQUALVERIFY and
            pops[5].opcode.value == OP_CHECKSIG):
        return True

    if (len(pops) == 4 and
            pops[0].opcode.value == OP_SSGEN and
            pops[1].opcode.value == OP_HASH160 and
            pops[2].opcode.value == OP_DATA_20 and
            pops[3].opcode.value == OP_EQUAL):
        return True

    return False

def isStakeRevocation(pops):
    """Returns whether the script is a stake submission revocation transaction."""
    if (len(pops) == 6 and
            pops[0].opcode.value == OP_SSRTX and
            pops[1].opcode.value == OP_DUP and
            pops[2].opcode.value == OP_HASH160 and
            pops[3].opcode.value == OP_DATA_20 and
            pops[4].opcode.value == OP_EQUALVERIFY and
            pops[5].opcode.value == OP_CHECKSIG):
        return True

    if (len(pops) == 4 and
            pops[0].opcode.value == OP_SSRTX and
            pops[1].opcode.value == OP_HASH160 and
            pops[2].opcode.value == OP_DATA_20 and
            pops[3].opcode.value == OP_EQUAL):
        return True

    return False

def isSStxChange(pops):
    """Returns whether script is a stake submission change transaction."""
    if (len(pops) == 6 and
            pops[0].opcode.value == OP_SSTXCHANGE and
            pops[1].opcode.value == OP_DUP and
            pops[2].opcode.value == OP_HASH160 and
            pops[3].opcode.value == OP_DATA_20 and
            pops[4].opcode.value == OP_EQUALVERIFY and
            pops[5].opcode.value == OP_CHECKSIG):
        return True

    if (len(pops) == 4 and
            pops[0].opcode.value == OP_SSTXCHANGE and
            pops[1].opcode.value == OP_HASH160 and
            pops[2].opcode.value == OP_DATA_20 and
            pops[3].opcode.value == OP_EQUAL):
        return True

    return False

def typeOfScript(pops):
    """Returns the type of the script being inspected from the known standard types."""
    if isPubkey(pops):
        return PubKeyTx
    elif isPubkeyAlt(pops):
        return PubkeyAltTy
    elif isPubkeyHashAlt(pops):
        return PubkeyHashAlt
    elif isScriptHash(pops):
        return ScriptHashTy
    elif isMultiSig(pops):
        return MultiSigTy
    elif isNullData(pops):
        return NullDataTy
    elif isStakeSubmission(pops):
        return StakeSubmissionTy
    elif isStakeGen(pops):
        return StakeGenTy
    elif isStakeRevocation(pops):
        return StakeRevocationTy
    elif isSStxChange(pops):
        return StakeSubChangeTy

    return NonStandardTy

def GetScriptClass(version, script):
    """Returns the class of the script.

    If the script does not parse, NonStandardTy is returned.
    """
    # NullDataTy outputs can have non-default script versions.
    if version != DefaultScriptVersion:
        return NonStandardTy

    try:
        pops = parseScript(script)
    except Exception:
        return NonStandardTy
    else:
        return typeOfScript(pops)

def expectedInputs(pops, _class, subclass):
    """Returns the number of arguments required by a script.

    If the script is of unknown type such that the number can not be determined
    then -1 is returned. We are an internal function and thus assume that class
    is the real class of pops (and we can thus assume things that were determined
    while finding out the type).
    """
    if _class == PubKeyTy:
        return 1
    elif _class == PubKeyHashTy:
        return 2
    elif _class == StakeSubmissionTy:
        if subclass == PubKeyHashTy:
            return 2
        return 1 # P2SH
    elif _class == StakeGenTy:
        if subclass == PubKeyHashTy:
            return 2
        return 1 # P2SH
    elif _class == StakeRevocationTy:
        if subclass == PubKeyHashTy:
            return 2
        return 1 # P2SH
    elif _class == StakeSubChangeTy:
        if subclass == PubKeyHashTy:
            return 2
        return 1 # P2SH
    elif _class == ScriptHashTy:
        # Not including script, handled below.
        return 1
    elif _class == MultiSigTy:
        # Standard multisig pushes a small int for the number of sigs
        # and number of keys.
        return asSmallInt(pops[0].opcode)

    elif _class == NullDataTy:
        pass

    return -1

class ScriptInfo(object):
    def __init__(self, PkScriptClass=0, NumInputs=0, ExpectedInputs=0, SigOps=0):
        self.PkScriptClass = PkScriptClass
        self.NumInputs = NumInputs
        self.ExpectedInputs = ExpectedInputs
        self.SigOps = SigOps

def IsStakeOutput(pkScript):
    """Returns whether an output script is a stake type."""
    pkPops = parseScript(pkScript)

    _class = typeOfScript(pkPops)
    return _class in [StakeSubmissionTy, StakeGenTy, StakeRevocationTy, StakeSubChangeTy]

def GetStakeOutSubclass(pkScript):
    """Extracts the subclass (P2PKH or P2SH) from a stake output."""
    pkPops = parseScript(pkScript)

    _class = typeOfScript(pkPops)
    isStake = _class in [StakeSubmissionTy, StakeGenTy, StakeRevocationTy, StakeSubChangeTy]
    if isStake:
        stakeSubscript = []
        for pop in pkPops:
            if pop.opcode.value >= 186 and pop.opcode.value <= 189:
                continue
            stakeSubscript.append(pop)
        subClass = typeOfScript(stakeSubscript)
    else:
        return 0

    return subClass

def getStakeOutSubscript(pkScript):
    """Extracts the subscript (P2PKH or P2SH) from a stake output."""
    return pkScript[1:]

def GetPkScriptFromP2SHSigScript(sigScript):
    """Returns the embedded pkScript from the signature script of a P2SH-spending tx."""
    sigPops = parseScript(sigScript)
    # The pay-to-hash-script is the final data push.
    return sigPops[-1].data

def ContainsStakeOpCodes(pkScript):
    """Returns whether a pkScript contains stake tagging opcodes."""
    shPops = parseScript(pkScript)
    for pop in shPops:
        if pop.opcode.value >= 186 and pop.opcode.value <= 189:
            return True

    return False

def CalcScriptInfo(sigScript, pkScript, bip16):
    """Returns a structure providing data about the provided script pair."""
    sigPops = parseScript(sigScript)
    pkPops = parseScript(pkScript)

    pkScriptClass = typeOfScript(pkPops)
    if not isPushOnly(sigPops):
        raise StackNonPushOnlyError()

    subClass = ScriptClass(0)
    if pkScriptClass in [StakeSubmissionTy, StakeGenTy, StakeRevocationTy, StakeSubChangeTy]:
        subClass = GetStakeOutSubclass(pkScript)

    ExpectedInputs = expectedInputs(pkPops, pkScriptClass, subClass)
    NumInputs = len(sigPops)

    if pkScriptClass == ScriptHashTy and bip16:
        # P2SH is the final data push.
        script = sigPops[-1].data
        shPops = parseScript(script)

        shInputs = expectedInputs(shPops, typeOfScript(shPops), 0)
        if shInputs == -1:
            ExpectedInputs = -1
        else:
            ExpectedInputs += shInputs
        SigOps = getSigOpCount(shPops, True)
    else:
        SigOps = getSigOpCount(pkPops, True)

    return ScriptInfo(pkScriptClass, NumInputs, ExpectedInputs, SigOps)

def CalcMultiSigStats(script):
    """Returns the number of pubkeys and sigs from a multisig script.

    The script MUST already be known to be a multisig script.
    """
    pops = parseScript(script)
    if len(pops) < 4:
        raise StackUnderflowError()

    numSigs = asSmallInt(pops[0].opcode)
    numPubKeys = asSmallInt(pops[-2].opcode)
    return numPubKeys, numSigs

def MultisigRedeemScriptFromScriptSig(script):
    """Extracts a redeem script from a P2SH-redeeming input."""
    pops = parseScript(script)
    return pops[-1].data

def payToPubKeyHashScript(pubKeyHash):
    """Creates a new output script to a 20-byte pubkey hash."""
    builder = ScriptBuilder()
    return builder.AddOp(OP_DUP).AddOp(OP_HASH160).AddData(pubKeyHash).AddOp(OP_EQUALVERIFY).AddOp(OP_CHECKSIG).Script()

def payToPubKeyHashEdwardsScript(pubKeyHash):
    """Creates a new output script to a 20-byte Edwards pubkey hash."""
    edwardsData = _bchr(edwards)
    builder = ScriptBuilder()
    return builder.AddOp(OP_DUP).AddOp(OP_HASH160).AddData(pubKeyHash).AddOp(OP_EQUALVERIFY).AddData(edwardsData).AddOp(OP_CHECKSIGALT).Script()

def payToPubKeyHashSchnorrScript(pubKeyHash):
    """Creates a new output script to a 20-byte pubkey hash.

    Expects a schnorr signature instead of a secp256k1 signature.
    """
    schnorrData = _bchr(secSchnorr)
    builder = ScriptBuilder()
    return builder.AddOp(OP_DUP).AddOp(OP_HASH160).AddData(pubKeyHash).AddOp(OP_EQUALVERIFY).AddData(schnorrData).AddOp(OP_CHECKSIGALT).Script()

def payToScriptHash(scriptHash):
    """Creates a new output script to pay to a script hash."""
    builder = ScriptBuilder()
    return builder.AddOp(OP_HASH160).AddData(scriptHash).AddOp(OP_EQUAL).Script()

def GetScriptHashFromP2SHScript(pkScript):
    """Extracts the script hash from a valid P2SH pkScript."""
    pops = parseScript(pkScript)
    reachedHash160DataPush = False

    sh = b''
    for p in pops:
        if p.opcode.value == OP_HASH160:
            reachedHash160DataPush = True
            continue
        if reachedHash160DataPush:
            sh = p.data

    return sh

def PayToScriptHashScript(scriptHash):
    return payToScriptHashScript(scriptHash)

def payToPubKeyScript(serializedPubKey):
    """Creates a new output script to pay to a public key."""
    builder = ScriptBuilder()
    return builder.AddData(serializedPubKey).AddOp(OP_CHECKSIG).Script()

def payToEdwardsPubKeyScript(serializedPubKey):
    """Creates a new output script to pay to an Ed25519 public key."""
    builder = ScriptBuilder()
    edwardsData = _bchr(edwards)
    return builder.AddData(serializedPubKey).AddData(edwardsData).AddOp(OP_CHECKSIGALT).Script()

def payToSchnorrPubKeyScript(serializedPubKey):
    """Creates a new output script to pay to a public key, but to be signed with a Schnorr signature."""
    builder = ScriptBuilder()
    schnorrData = _bchr(secSchnorr)
    return builder.AddData(serializedPubKey).AddData(schnorrData).AddOp(OP_CHECKSIGALT).Script()

def PayToSStx(addr):
    """Creates a script to pay to a script hash or pubkey hash, but tags the output with OP_SSTX."""
    raise Exception('Not implemented')
