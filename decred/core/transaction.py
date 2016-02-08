from __future__ import absolute_import
import struct
from io import BytesIO

from bitcoin.core import b2lx, b2x
from bitcoin.core.serialize import (ser_read, Serializable, BytesSerializer,
        VectorSerializer, VarIntSerializer)

TX_SERIALIZE_FULL = 0
TX_SERIALIZE_NO_WITNESS = 1
TX_SERIALIZE_ONLY_WITNESS = 2
TX_SERIALIZE_WITNESS_SIGNING = 3
TX_SERIALIZE_WITNESS_VALUE_SIGNING = 4

def tx_version_to_vars(version):
    """Converts an int32 representation into serialization type and version."""
    f = BytesIO()
    f.write(struct.pack(b'<I', version))
    f.seek(0)
    version_value = struct.unpack(b'<H', ser_read(f, 2))[0]
    serialization_type = struct.unpack(b'<H', ser_read(f, 2))[0]
    return (version_value, serialization_type)

def vars_to_tx_version(version_value, serialization_type):
    """Converts serialization type and tx version into a 32 bit int."""
    f = BytesIO()
    f.write(struct.pack(b'<H', version_value))
    f.write(struct.pack(b'<H', serialization_type))
    f.seek(0)
    version = struct.unpack(b'<i', ser_read(f, 4))[0]
    return version

class OutPoint(Serializable):
    """A Decred previous transaction output."""
    __slots__ = ['hash', 'index', 'tree']

    def __init__(self, hash=b'\x00'*32, index=0, tree=0):
        if not len(hash) == 32:
            raise ValueError('Previous hash must be 32 bytes.')
        object.__setattr__(self, 'hash', hash)
        object.__setattr__(self, 'index', index)
        object.__setattr__(self, 'tree', tree)

    def __repr__(self):
        return 'OutPoint(hash=lx(%r), index=%d, tree=%d)' % (b2lx(self.hash), self.index, self.tree)

    @classmethod
    def from_outpoint(cls, outpoint):
        return cls(outpoint.hash, outpoint.index, outpoint.tree)

    @classmethod
    def stream_deserialize(cls, f):
        hash = ser_read(f, 32)
        index = struct.unpack(b'<I', ser_read(f, 4))[0]
        tree = struct.unpack(b'<b', ser_read(f, 1))[0]
        return cls(hash, index, tree)

    def stream_serialize(self, f):
        assert len(self.hash) == 32
        f.write(self.hash)
        f.write(struct.pack(b'<I', self.index))
        f.write(struct.pack(b'<b', self.tree))

class TxIn(Serializable):
    """A Decred transaction input."""
    __slots__ = ['prev_out', 'sequence', 'value', 'block_height', 'block_index', 'sig_script']

    def __init__(self, prev_out=OutPoint(), sequence=0, value=0, block_height=0, block_index=0, sig_script=b''):
        # Non-witness.
        object.__setattr__(self, 'prev_out', prev_out)
        object.__setattr__(self, 'sequence', sequence)
        # Witness.
        object.__setattr__(self, 'value', value)
        object.__setattr__(self, 'block_height', block_height)
        object.__setattr__(self, 'block_index', block_index)
        object.__setattr__(self, 'sig_script', sig_script)

    def __repr__(self):
        return 'TxIn(prev_out=%s, sequence=0x%x, value=%d, block_height=%d, block_index=%d, sig_script=x("%s"))' % (repr(self.prev_out),
                self.sequence, self.value, self.block_height, self.block_index, b2x(self.sig_script))

    @classmethod
    def from_txin(cls, txin):
        return cls(OutPoint.from_outpoint(txin.prev_out), txin.sequence, txin.value, txin.block_height, txin.block_index, txin.sig_script)

    @classmethod
    def stream_deserialize(cls, f):
        prev_out = OutPoint.stream_deserialize(f)
        sequence = struct.unpack(b'<I', ser_read(f, 4))[0]

        value = struct.unpack(b'<q', ser_read(f, 8))[0]
        block_height = struct.unpack(b'<I', ser_read(f, 4))[0]
        block_index = struct.unpack(b'<I', ser_read(f, 4))[0]
        sig_script = BytesSerializer.stream_deserialize(f)
        return cls(prev_out, sequence, value, block_height, block_index, sig_script)

    def deserialize_prefix(self, f):
        prev_out = OutPoint.stream_deserialize(f)
        sequence = struct.unpack(b'<I', ser_read(f, 4))[0]

        self.prev_out = prev_out
        self.sequence = sequence

    def deserialize_witness(self, f):
        value = struct.unpack(b'<q', ser_read(f, 8))[0]
        block_height = struct.unpack(b'<I', ser_read(f, 4))[0]
        block_index = struct.unpack(b'<I', ser_read(f, 4))[0]
        sig_script = BytesSerializer.stream_deserialize(f)

        self.value = value
        self.block_height = block_height
        self.block_index = block_index
        self.sig_script = sig_script

    def deserialize_witness_signing(self, f):
        sig_script = BytesSerializer.stream_deserialize(f)
        self.sig_script = sig_script

    def deserialize_witness_value_signing(self, f):
        value = struct.unpack(b'<q', ser_read(f, 8))[0]
        sig_script = BytesSerializer.stream_deserialize(f)

        self.value = value
        self.sig_script = sig_script

    def stream_serialize(self, f):
        OutPoint.stream_serialize(self.prev_out, f)
        f.write(struct.pack(b'<I', self.sequence))

        f.write(struct.pack(b'<q', self.value))
        f.write(struct.pack(b'<I', self.block_height))
        f.write(struct.pack(b'<I', self.block_index))
        BytesSerializer.stream_serialize(self.sig_script, f)

    def serialize_prefix(self, f):
        OutPoint.stream_serialize(self.prev_out, f)
        f.write(struct.pack(b'<I', self.sequence))

    def serialize_witness(self, f):
        f.write(struct.pack(b'<q', self.value))
        f.write(struct.pack(b'<I', self.block_height))
        f.write(struct.pack(b'<I', self.block_index))
        BytesSerializer.stream_serialize(self.sig_script, f)

    def serialize_witness_signing(self, f):
        BytesSerializer.stream_serialize(self.sig_script, f)

    def serialize_witness_value_signing(self, f):
        f.write(struct.pack(b'<q', self.value))
        BytesSerializer.stream_serialize(self.sig_script, f)

class TxOut(Serializable):
    """A Decred transaction output."""
    __slots__ = ['value', 'version', 'pk_script']

    def __init__(self, value=0, version=0, pk_script=b'\x00'):
        object.__setattr__(self, 'value', value)
        object.__setattr__(self, 'version', version)
        object.__setattr__(self, 'pk_script', pk_script)

    def __repr__(self):
        return 'TxOut(value=%d, version=%d, pk_script=x("%s"))' % (self.value, self.version, b2x(self.pk_script))

    @classmethod
    def from_txout(cls, txout):
        return cls(txout.value, txout.version, txout.pk_script)

    @classmethod
    def stream_deserialize(cls, f):
        value = struct.unpack(b'<q', ser_read(f, 8))[0]
        version = struct.unpack(b'<H', ser_read(f, 2))[0]
        pk_script = BytesSerializer.stream_deserialize(f)
        return cls(value, version, pk_script)

    def stream_serialize(self, f):
        f.write(struct.pack(b'<q', self.value))
        f.write(struct.pack(b'<H', self.version))
        BytesSerializer.stream_serialize(self.pk_script, f)

class Transaction(Serializable):
    """A decred transaction."""
    __slots__ = ['version', 'txins', 'txouts', 'locktime', 'expiry']

    def __init__(self, version=0, txins=(), txouts=(), locktime=0, expiry=0):
        object.__setattr__(self, 'version', version)
        object.__setattr__(self, 'txins', list(TxIn.from_txin(txin) for txin in txins))
        object.__setattr__(self, 'txouts', list(TxOut.from_txout(txout) for txout in txouts))
        object.__setattr__(self, 'locktime', locktime)
        object.__setattr__(self, 'expiry', expiry)

    def __repr__(self):
        return 'Transaction(version=%d, txins=%r, txouts=%r, locktime=%d, expiry=%d)' % (self.version,
                self.txins, self.txouts, self.locktime, self.expiry)

    @classmethod
    def from_tx(cls, tx):
        return cls(tx.version, tx.txins, tx.txouts, tx.locktime, tx.expiry)

    @classmethod
    def stream_deserialize(cls, f):
        self = cls()
        self.version = struct.unpack(b'<i', ser_read(f, 4))[0]
        _, ser_type = tx_version_to_vars(self.version)

        if ser_type == TX_SERIALIZE_NO_WITNESS:
            self.deserialize_prefix(f)
        elif ser_type == TX_SERIALIZE_ONLY_WITNESS:
            self.deserialize_witness(f, False)
        elif ser_type == TX_SERIALIZE_WITNESS_SIGNING:
            self.deserialize_witness_signing(f)
        elif ser_type == TX_SERIALIZE_WITNESS_VALUE_SIGNING:
            self.deserialize_witness_value_signing(f)
        elif ser_type == TX_SERIALIZE_FULL:
            self.deserialize_prefix(f)
            self.deserialize_witness(f, True)
        else:
            raise Exception('Unsupported transaction type.')

        return self

    def deserialize_prefix(self, f):
        """Deserialize the transaction prefix."""
        txin_count = VarIntSerializer.stream_deserialize(f)
        txins = []
        for i in range(txin_count):
            txin = TxIn()
            txin.deserialize_prefix(f)
            txins.append(txin)

        txouts = VectorSerializer.stream_deserialize(TxOut, f)
        locktime = struct.unpack(b'<I', ser_read(f, 4))[0]
        expiry = struct.unpack(b'<I', ser_read(f, 4))[0]

        self.txins = list(txins)
        self.txouts = list(txouts)
        self.locktime = locktime
        self.expiry = expiry

    def deserialize_witness(self, f, txins_present):
        """Deserialize the transaction witnesses.

        If txins_present is True, existing txins will be populated
        with witness data.
        """
        txin_count = VarIntSerializer.stream_deserialize(f)
        if not txins_present:
            txins = []
            for i in range(txin_count):
                txin = TxIn()
                txin.deserialize_witness(f)
                txins.append(txin)
            self.txins = list(txins)
        else:
            for i in range(txin_count):
                txin = self.txins[i]
                txin.deserialize_witness(f)

    def deserialize_witness_signing(self, f):
        """Deserialize a witness for signing."""
        txin_count = VarIntSerializer.stream_deserialize(f)
        txins = []
        for i in range(txin_count):
            txin = TxIn()
            txin.deserialize_witness_signing(f)
            txins.append(txin)
        self.txins = list(txins)

    def deserialize_witness_value_signing(self, f):
        """Deserialize a witness for signing with value."""
        txin_count = VarIntSerializer.stream_deserialize(f)
        txins = []
        for i in range(txin_count):
            txin = TxIn()
            txin.deserialize_witness_value_signing(f)
            txins.append(txin)
        self.txins = list(txins)

    def stream_serialize(self, f):
        f.write(struct.pack(b'<i', self.version))
        _, ser_type = tx_version_to_vars(self.version)

        if ser_type == TX_SERIALIZE_NO_WITNESS:
            self.serialize_prefix(f)
        elif ser_type == TX_SERIALIZE_ONLY_WITNESS:
            self.serialize_witness(f)
        elif ser_type == TX_SERIALIZE_WITNESS_SIGNING:
            self.serialize_witness_signing(f)
        elif ser_type == TX_SERIALIZE_WITNESS_VALUE_SIGNING:
            self.serialize_witness_value_signing(f)
        elif ser_type == TX_SERIALIZE_FULL:
            self.serialize_prefix(f)
            self.serialize_witness(f)
        else:
            raise Exception('Unsupported transaction type.')

    def serialize_prefix(self, f):
        VarIntSerializer.stream_serialize(len(self.txins), f)
        for txin in self.txins:
            txin.serialize_prefix(f)

        VectorSerializer.stream_serialize(TxOut, self.txouts, f)
        f.write(struct.pack(b'<I', self.locktime))
        f.write(struct.pack(b'<I', self.expiry))

    def serialize_witness(self, f):
        VarIntSerializer.stream_serialize(len(self.txins), f)
        for txin in self.txins:
            txin.serialize_witness(f)

    def serialize_witness_signing(self, f):
        VarIntSerializer.stream_serialize(len(self.txins), f)
        for txin in self.txins:
            txin.serialize_witness_signing(f)

    def serialize_witness_value_signing(self, f):
        VarIntSerializer.stream_serialize(len(self.txins), f)
        for txin in self.txins:
            txin.serialize_witness_value_signing(f)

