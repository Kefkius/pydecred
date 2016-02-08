import unittest
import struct

from bitcoin.core import x, b2x, b2lx

from decred.core.transaction import *

class TransactionTest(unittest.TestCase):

    def test_transaction_deserialization_and_serialization(self):
        # Transaction from Decred unit test.
        raw_tx = x('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0200f2052a01000000abab434104d64bdfd09eb1c5fe295abdeb1dca4281be988e2da0b6c1c6a59dc226c28624e18175e851c96b973d81b01cc31f047834bc06d6d6edf620d184241a6aed8b63a6ac00e1f50500000000bcbc434104d64bdfd09eb1c5fe295abdeb1dca4281be988e2da0b6c1c6a59dc226c28624e18175e851c96b973d81b01cc31f047834bc06d6d6edf620d184241a6aed8b63a6ac00000000000000000112121212121212121515151534343434070431dc001b0162')
        tx = Transaction.deserialize(raw_tx)

        self.assertEqual(1, tx.version)
        self.assertEqual(0, tx.locktime)
        self.assertEqual(0, tx.expiry)

        # Test input.
        self.assertEqual(1, len(tx.txins))
        txin = tx.txins[0]
        self.assertEqual(1302123111085380114, txin.value)
        self.assertEqual(353703189, txin.block_height)
        self.assertEqual(875836468, txin.block_index)
        self.assertEqual(x('0431dc001b0162'), txin.sig_script)
        self.assertEqual(4294967295, txin.sequence)

        self.assertEqual(2, len(tx.txouts))
        # Test output 0.
        txout = tx.txouts[0]
        self.assertEqual(5000000000, txout.value)
        self.assertEqual(43947, txout.version)
        self.assertEqual(x('4104d64bdfd09eb1c5fe295abdeb1dca4281be988e2da0b6c1c6a59dc226c28624e18175e851c96b973d81b01cc31f047834bc06d6d6edf620d184241a6aed8b63a6ac'), txout.pk_script)
        # Test output 1.
        txout = tx.txouts[1]
        self.assertEqual(100000000, txout.value)
        self.assertEqual(48316, txout.version)
        self.assertEqual(x('4104d64bdfd09eb1c5fe295abdeb1dca4281be988e2da0b6c1c6a59dc226c28624e18175e851c96b973d81b01cc31f047834bc06d6d6edf620d184241a6aed8b63a6ac'), txout.pk_script)

        self.assertEqual(b2x(raw_tx), b2x(tx.serialize()))

    def test_vars_to_tx_version(self):
        def repr_version(int32):
            return b2x(struct.pack(b'<i', int32))

        self.assertEqual('01000000', repr_version(vars_to_tx_version(1, TX_SERIALIZE_FULL)))
        self.assertEqual('01000100', repr_version(vars_to_tx_version(1, TX_SERIALIZE_NO_WITNESS)))
