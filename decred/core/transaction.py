from __future__ import absolute_import
import struct

from bitcoin.core.serialize import (ser_read, ImmutableSerializable, BytesSerializer,
        VectorSerializer)


class OutPoint(ImmutableSerializable):
    """A Decred previous transaction output."""
    __slots__ = ['hash', 'index', 'tree']

    def __init__(self, hash=b'\x00'*32, index=0, tree=0):
        if not len(hash) == 32:
            raise ValueError('Previous hash must be 32 bytes.')
        object.__setattr__(self, 'hash', hash)
        object.__setattr__(self, 'index', index)
        object.__setattr__(self, 'tree', tree)

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

class TxIn(ImmutableSerializable):
    """A Decred transaction input."""
    __slots__ = ['prev_out', 'sequence', 'value', 'block_height',
                 'block_index', 'sig_script']

    def __init__(self, prev_out=OutPoint(), sequence=0, value=0,
                 block_height=0, block_index=0, sig_script=b'\x00'):
        # Non-witness.
        object.__setattr__(self, 'prev_out', prev_out)
        object.__setattr__(self, 'sequence', sequence)
        # Witness.
        object.__setattr__(self, 'value', value)
        object.__setattr__(self, 'block_height', block_height)
        object.__setattr__(self, 'block_index', block_index)
        object.__setattr__(self, 'sig_script', sig_script)

    @classmethod
    def stream_deserialize(cls, f):
        prev_out = OutPoint.stream_deserialize(f)
        sequence = struct.unpack(b'<I', ser_read(f, 4))[0]

        value = struct.unpack(b'<q', ser_read(f, 8))[0]
        block_height = struct.unpack(b'<I', read_read(f, 4))[0]
        block_index = struct.unpack(b'<I', read_read(f, 4))[0]
        sig_script = BytesSerializer.stream_deserialize(f)
        return cls(prev_out, sequence, value, block_height, block_index, sig_script)

    def stream_serialize(self, f):
        OutPoint.stream_serialize(self.prev_out, f)
        f.write(struct.pack(b'<I', self.sequence))

        f.write(struct.pack(b'<q', self.value))
        f.write(struct.pack(b'<I', self.block_height))
        f.write(struct.pack(b'<I', self.block_index))
        BytesSerializer.stream_serialize(self.sig_script, f)

class TxOut(ImmutableSerializable):
    """A Decred transaction output."""
    __slots__ = ['value', 'version', 'pk_script']

    def __init__(self, value=0, version=0, pk_script=b'\x00'):
        object.__setattr__(self, 'value', value)
        object.__setattr__(self, 'version', version)
        object.__setattr__(self, 'pk_script', pk_script)

    @classmethod
    def stream_deserialize(cls, f):
        value = struct.unpack(b'<q', ser_read(f, 8))[0]
        version = struct.unpack(b'<H', ser_read(f, 2))[0]
        pk_script = BytesSerializer.stream_deserialize(f)
        return cls(value, version, pk_script)

    def stream_serialize(self, f)
        f.write(struct.pack(b'<q', self.value))
        f.write(struct.pack(b<'H', self.version))
        BytesSerializer.stream_serialize(self.pk_script, f)

class Transaction(ImmutableSerializable):
    """A decred transaction."""
    __slots__ = ['version', 'txins', 'txouts', 'locktime', 'expiry']

    def __init__(self, version=0, txins=(), txouts=(), locktime=0, expiry=0):
        object.__setattr__(self, 'version', version)
        object.__setattr__(self, 'txins', txins)
        object.__setattr__(self, 'txouts', txouts)
        object.__setattr__(self, 'locktime', locktime)
        object.__setattr__(self, 'expiry', expiry)

    @classmethod
    def stream_deserialize(cls, f):
        version = struct.unpack(b'<i', ser_read(f, 4))[0]
        txins = VectorSerializer.stream_deserialize(TxIn, f)
        txouts = VectorSerializer.stream_deserialize(TxOut, f)
        locktime = struct.unpack(b'<I', ser_read(f, 4))[0]
        expiry = struct.unpack(b'<I', ser_read(f, 4))[0]
        return cls(version, txins, txouts, locktime, expiry)

    def stream_serialize(self, f):
        f.write(struct.pack(b'<i', self.version))
        VectorSerializer.stream_serialize(TxIn, self.txins, f)
        VectorSerializer.stream_serialize(TxOut, self.txouts, f)
        f.write(struct.pack(b'<I', self.locktime))
        f.write(struct.pack(b'<I', self.expiry))
