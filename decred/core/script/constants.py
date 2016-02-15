
# These are here to avoid circular imports.


# Script Flags #

# ScriptBip16 defines whether the bip16 threshhold has passed and thus
# pay-to-script hash transactions will be fully validated.
ScriptBip16 = 1

# ScriptStrictMultiSig defines whether to verify the stack item
# used by CHECKMULTISIG is zero length.
ScriptStrictMultiSig = 1 << 1

# ScriptDiscourageUpgradableNops defines whether to verify that
# NOP1 through NOP10 are reserved for future soft-fork upgrades.  This
# flag must not be used for consensus critical code nor applied to
# blocks as this flag is only for stricter standard transaction
# checks.  This flag is only applied when the above opcodes are
# executed.
ScriptDiscourageUpgradableNops = 1 << 2

# ScriptVerifyCheckLockTimeVerify defines whether to verify that
# a transaction output is spendable based on the locktime.
# This is BIP0065.
ScriptVerifyCheckLockTimeVerify = 1 << 3

# ScriptVerifyCleanStack defines that the stack must contain only
# one stack element after evaluation and that the element must be
# true if interpreted as a boolean.  This is rule 6 of BIP0062.
# This flag should never be used without the ScriptBip16 flag.
ScriptVerifyCleanStack = 1 << 4

# ScriptVerifyDERSignatures defines that signatures are required
# to compily with the DER format.
ScriptVerifyDERSignatures = 1 << 5

# ScriptVerifyLowS defines that signtures are required to comply with
# the DER format and whose S value is <= order / 2.  This is rule 5
# of BIP0062.
ScriptVerifyLowS = 1 << 6

# ScriptVerifyMinimalData defines that signatures must use the smallest
# push operator. This is both rules 3 and 4 of BIP0062.
ScriptVerifyMinimalData = 1 << 7

# ScriptVerifySigPushOnly defines that signature scripts must contain
# only pushed data.  This is rule 2 of BIP0062.
ScriptVerifySigPushOnly = 1 << 8

# ScriptVerifyStrictEncoding defines that signature scripts and
# public keys must follow the strict encoding requirements.
ScriptVerifyStrictEncoding = 1 << 9

maxStackSize = 1024
maxScriptSize = 16384
DefaultScriptVersion = 0


SigHashOld = 0x0
SigHashAll = 0x1
SigHashNone = 0x2
SigHashSingle = 0x3
SigHashAllValue = 0x4
SigHashAnyOneCanPay = 0x80
sigHashMask = 0x1f

MaxOpsPerScript = 255
MaxPubKeysPerMultiSig = 20
MaxScriptElementSize = 2048

