import unittest

from bitcoin.core import x, b2x, b2lx

from decred.core.block import BlockHeader

class BlockHeaderTest(unittest.TestCase):
    def test_header_serialization_and_deserialization(self):
        raw_header = x('010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d61900000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a00000000000000000000000000000000ffff001d0000000000000000000000000000000029ab5f49f3e00100000000000000000000000000000000000000000000000000000000000000000000000000')
        header = BlockHeader.deserialize(raw_header)

        self.assertEqual(1, header.version)
        self.assertEqual('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f', b2lx(header.prev_block))
        self.assertEqual('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b', b2lx(header.merkle_root))
        self.assertEqual('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b', b2lx(header.stake_root))
        self.assertEqual(0, header.vote_bits)
        self.assertEqual('000000000000', b2x(header.final_state))
        self.assertEqual(0, header.voters)
        self.assertEqual(0, header.fresh_stake)
        self.assertEqual(0, header.revocations)
        self.assertEqual(0, header.pool_size)
        self.assertEqual(486604799, header.bits)
        self.assertEqual(0, header.sbits)
        self.assertEqual(0, header.height)
        self.assertEqual(0, header.size)
        self.assertEqual(1231006505, header.timestamp)
        self.assertEqual(123123, header.nonce)
        self.assertEqual('000000000000000000000000000000000000000000000000000000000000000000000000', b2x(header.extra_data))

        self.assertEqual(raw_header, header.serialize())
        self.assertEqual('df03ea8cb4a6f201c3e726f2f922a9249b39129bb59fa593ceb172e0f7c14d6e', b2lx(header.GetHash()))
