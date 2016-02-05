from __future__ import absolute_import
import struct

from bitcoin.core import b2x, b2lx
from bitcoin.core.serialize import ser_read, Serializable, VectorSerializer

from .serialize import DecredHash
from .transaction import Transaction

class BlockHeader(Serializable):
    """A Decred block header."""
    __slots__ = ['version', 'prev_block', 'merkle_root', 'stake_root',
                 'vote_bits', 'final_state', 'voters', 'fresh_stake',
                 'revocations', 'pool_size', 'bits', 'sbits', 'height',
                 'size', 'timestamp', 'nonce', 'extra_data']

    def __init__(self, version=1, prev_block=b'\x00'*32, merkle_root=b'\x00'*32,
                 stake_root=b'\x00'*32, vote_bits=0, final_state=b'\x00'*6, voters=0,
                 fresh_stake=0, revocations=0, pool_size=0, bits=0, sbits=0,
                 height=0, size=0, timestamp=0, nonce=0, extra_data=b'\x00'*36):
        if not len(prev_block) == 32:
            raise ValueError('Previous block hash must be 32 bytes.')
        if not len(merkle_root) == 32:
            raise ValueError('Merkle root must be 32 bytes.')
        if not len(stake_root) == 32:
            raise ValueError('Stake root must be 32 bytes.')
        if not len(extra_data) == 36:
            raise ValueError('Extra data must be 32 bytes.')
        args = (version, prev_block, merkle_root, stake_root, vote_bits, final_state,
                voters, fresh_stake, revocations, pool_size, bits, sbits, height,
                size, timestamp, nonce, extra_data,)
        for attr_name, argument in zip(BlockHeader.__slots__, args):
            object.__setattr__(self, attr_name, argument)

    def GetHash(self):
        return DecredHash(self.serialize())

    @classmethod
    def stream_deserialize(cls, f):
        version = struct.unpack(b'<i', ser_read(f, 4))[0]
        prev_block = ser_read(f, 32)
        merkle_root = ser_read(f, 32)
        stake_root = ser_read(f, 32)
        vote_bits = struct.unpack(b'<H', ser_read(f, 2))[0]
        final_state = ser_read(f, 6)
        voters = struct.unpack(b'<H', ser_read(f, 2))[0]
        fresh_stake = struct.unpack(b'<B', ser_read(f, 1))[0]
        revocations = struct.unpack(b'<B', ser_read(f, 1))[0]
        pool_size = struct.unpack(b'<I', ser_read(f, 4))[0]
        bits = struct.unpack(b'<I', ser_read(f, 4))[0]
        sbits = struct.unpack(b'<q', ser_read(f, 8))[0]
        height = struct.unpack(b'<I', ser_read(f, 4))[0]
        size = struct.unpack(b'<I', ser_read(f, 4))[0]
        timestamp = struct.unpack(b'<I', ser_read(f, 4))[0]
        nonce = struct.unpack(b'<I', ser_read(f, 4))[0]
        extra_data = ser_read(f, 36)
        return cls(version, prev_block, merkle_root, stake_root, vote_bits, final_state,
                   voters, fresh_stake, revocations, pool_size, bits, sbits, height,
                   size, timestamp, nonce, extra_data)

    def stream_serialize(self, f):
        f.write(struct.pack(b'<i', self.version))
        assert len(self.prev_block) == 32
        f.write(self.prev_block)
        assert len(self.merkle_root) == 32
        f.write(self.merkle_root)
        assert len(self.stake_root) == 32
        f.write(self.stake_root)
        f.write(struct.pack(b'<H', self.vote_bits))
        assert len(self.final_state) == 6
        f.write(self.final_state)
        f.write(struct.pack(b'<H', self.voters))
        f.write(struct.pack(b'<B', self.fresh_stake))
        f.write(struct.pack(b'<B', self.revocations))
        f.write(struct.pack(b'<I', self.pool_size))
        f.write(struct.pack(b'<I', self.bits))
        f.write(struct.pack(b'<q', self.sbits))
        f.write(struct.pack(b'<I', self.height))
        f.write(struct.pack(b'<I', self.size))
        f.write(struct.pack(b'<I', self.timestamp))
        f.write(struct.pack(b'<I', self.nonce))
        assert len(self.extra_data) == 36
        f.write(self.extra_data)

class Block(BlockHeader):
    """A Decred block."""
    __slots__ = ['txs', 'stxs']


    def __init__(self, version=1, prev_block=b'\x00'*32, merkle_root=b'\x00'*32,
                 stake_root=b'\x00'*32, vote_bits=0, final_state=b'\x00'*6, voters=0,
                 fresh_stake=0, revocations=0, pool_size=0, bits=0, sbits=0,
                 height=0, size=0, timestamp=0, nonce=0, extra_data=b'\x00'*36,
                 txs=(), stxs=()):

        args = (version, prev_block, merkle_root, stake_root, vote_bits, final_state,
                voters, fresh_stake, revocations, pool_size, bits, sbits, height,
                size, timestamp, nonce, extra_data,)
        super(Block, self).__init__(*args)
        self.txs = list(txs)
        self.stxs = list(stxs)

    @classmethod
    def stream_deserialize(cls, f):
        self = super(Block, cls).stream_deserialize(f)
        txs = VectorSerializer.stream_deserialize(Transaction, f)
        stxs = VectorSerializer.stream_deserialize(Transaction, f)

        self.txs = list(txs)
        self.stxs = list(stxs)
        return self

    def stream_serialize(self, f):
        super(Block, self).stream_serialize(f)
        VectorSerializer.stream_serialize(Transaction, self.txs, f)
        VectorSerializer.stream_serialize(Transaction, self.stxs, f)

    def get_header(self):
        """Return the block header as a new object."""
        args = ['version', 'prev_block', 'merkle_root', 'stake_root', 'vote_bits',
                'final_state', 'voters', 'fresh_stake', 'revocations', 'pool_size',
                'bits', 'sbits', 'height', 'size', 'timestamp', 'nonce', 'extra_data']
        kwargs = {}
        for i in args:
            kwargs[i] = getattr(self, i)
        return BlockHeader(**kwargs)

    def GetHash(self):
        return super(Block, self).GetHash()
