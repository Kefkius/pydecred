import unittest

from bitcoin.core import x, b2x, b2lx

from decred.core.block import BlockHeader, Block

class BlockHeaderTest(unittest.TestCase):
    # Block from decred unit tests.
    raw_block = x('010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e00000000000000000000000000000000ffff001d0000000000000000010000000100000061bc664901e362990000000000000000000000000000000000000000000000000000000000000000000000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff013333333333333333989843410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac1111111122222222011616161616161616171717171818181807ffffffff0100f20101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff01ffffffff013333333333333333121243410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac1111111122222222011313131313131313141414141515151507ffffffff0100f2')

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

    def test_block_serialization_and_deserialization(self):
        block = Block.deserialize(self.raw_block)

        # Test header.
        self.assertEqual(1, block.version)
        self.assertEqual('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f', b2lx(block.prev_block))
        self.assertEqual('0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098', b2lx(block.merkle_root))
        self.assertEqual('0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098', b2lx(block.stake_root))
        self.assertEqual(0, block.vote_bits)
        self.assertEqual('000000000000', b2x(block.final_state))
        self.assertEqual(0, block.voters)
        self.assertEqual(0, block.fresh_stake)
        self.assertEqual(0, block.revocations)
        self.assertEqual(0, block.pool_size)
        self.assertEqual(486604799, block.bits)
        self.assertEqual(0, block.sbits)
        self.assertEqual(1, block.height)
        self.assertEqual(1, block.size)
        self.assertEqual(1231469665, block.timestamp)
        self.assertEqual(2573394689, block.nonce)
        self.assertEqual('000000000000000000000000000000000000000000000000000000000000000000000000', b2x(block.extra_data))

        # Test transaction.
        self.assertEqual(1, len(block.txs))
        tx = block.txs[0]
        self.assertEqual(1, tx.version)
        self.assertEqual(0x11111111, tx.locktime)
        self.assertEqual(0x22222222, tx.expiry)

        # Test input.
        self.assertEqual(1, len(tx.txins))
        txin = tx.txins[0]
        self.assertEqual(b'\x00' * 32, txin.prev_out.hash)
        self.assertEqual(0xffffffff, txin.prev_out.index)
        self.assertEqual(0, txin.prev_out.tree)
        self.assertEqual(0xffffffff, txin.sequence)
        self.assertEqual(0x1616161616161616, txin.value)
        self.assertEqual(0x17171717, txin.block_height)
        self.assertEqual(0x18181818 , txin.block_index)
        self.assertEqual(x('ffffffff0100f2'), txin.sig_script)

        # Test output.
        self.assertEqual(1, len(tx.txouts))
        txout = tx.txouts[0]
        self.assertEqual(0x3333333333333333, txout.value)
        self.assertEqual(0x9898, txout.version)
        self.assertEqual(x('410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac'), txout.pk_script)

        self.assertEqual(self.raw_block, block.serialize())
        self.assertEqual('152437dada95368c42b19febc1702939fa9c1ccdb6fd7284e5b7a19d8fe6df7a', b2lx(block.GetHash()))

        # Test stake transaction.
        self.assertEqual(1, len(block.stxs))
        stx = block.stxs[0]
        self.assertEqual(1, stx.version)
        self.assertEqual(0x11111111, stx.locktime)
        self.assertEqual(0x22222222, stx.expiry)

        # Test input.
        self.assertEqual(1, len(stx.txins))
        txin = stx.txins[0]
        self.assertEqual(b'\x00' * 32, txin.prev_out.hash)
        self.assertEqual(0xffffffff, txin.prev_out.index)
        self.assertEqual(1, txin.prev_out.tree)
        self.assertEqual(0xffffffff, txin.sequence)
        self.assertEqual(0x1313131313131313, txin.value)
        self.assertEqual(0x14141414, txin.block_height)
        self.assertEqual(0x15151515, txin.block_index)
        self.assertEqual(x('ffffffff0100f2'), txin.sig_script)

        # Test output.
        self.assertEqual(1, len(stx.txouts))
        txout = stx.txouts[0]
        self.assertEqual(0x3333333333333333, txout.value)
        self.assertEqual(0x1212, txout.version)
        self.assertEqual(x('410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac'), txout.pk_script)



    def test_block_get_header(self):
        block = Block.deserialize(self.raw_block)
        header = block.get_header()

        self.assertEqual(1, header.version)
        self.assertEqual('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f', b2lx(header.prev_block))
        self.assertEqual('0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098', b2lx(header.merkle_root))
        self.assertEqual('0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098', b2lx(header.stake_root))
        self.assertEqual(0, header.vote_bits)
        self.assertEqual('000000000000', b2x(header.final_state))
        self.assertEqual(0, header.voters)
        self.assertEqual(0, header.fresh_stake)
        self.assertEqual(0, header.revocations)
        self.assertEqual(0, header.pool_size)
        self.assertEqual(486604799, header.bits)
        self.assertEqual(0, header.sbits)
        self.assertEqual(1, header.height)
        self.assertEqual(1, header.size)
        self.assertEqual(1231469665, header.timestamp)
        self.assertEqual(2573394689, header.nonce)
        self.assertEqual('000000000000000000000000000000000000000000000000000000000000000000000000', b2x(header.extra_data))
