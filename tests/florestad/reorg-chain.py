"""
Chain reorg test

This test will spawn a florestad and a utreexod, we will use utreexod to mine some blocks.
Then we will invalidate one of those blocks, and mine an alternative chain. This should
make florestad switch to the new chain. We then compare the two node's main chain and
accumulator to make sure they are the same.
"""

import re
import time

from test_framework import FlorestaTestFramework


class ChainReorgTest(FlorestaTestFramework):
    """Test the reorganization of the chain in florestad when using utreexod to mine blocks."""

    expected_chain = "regtest"

    def set_test_params(self):
        self.florestad = self.add_node(variant="florestad")

        self.utreexod = self.add_node(
            variant="utreexod",
            extra_args=[
                "--miningaddr=bcrt1q4gfcga7jfjmm02zpvrh4ttc5k7lmnq2re52z2y",
                "--utreexoproofindex",
                "--prune=0",
            ],
        )

    def run_test(self):
        # Start the nodes
        self.run_node(self.florestad)
        self.run_node(self.utreexod)

        # Mine some blocks with utreexod
        self.log("=== Mining blocks with utreexod")
        self.utreexod.rpc.generate(10)

        self.log("=== Connect floresta to utreexod")
        host = self.florestad.get_host()
        port = self.utreexod.get_port("p2p")
        self.florestad.rpc.addnode(
            f"{host}:{port}", command="onetry", v2transport=False
        )
        time.sleep(5)

        self.log("=== Waiting for floresta to connect to utreexod.rpc...")
        peer_info = self.florestad.rpc.get_peerinfo()
        self.assertMatch(
            peer_info[0]["user_agent"],
            re.compile(r"/btcwire:\d+\.\d+\.\d+/utreexod:\d+\.\d+\.\d+/"),
        )

        self.log("=== Wait for the nodes to sync...")
        time.sleep(20)

        self.log("=== Check that floresta has the same chain as utreexod.rpc...")
        floresta_chain = self.florestad.rpc.get_blockchain_info()
        utreexo_chain = self.utreexod.rpc.get_blockchain_info()
        self.assertEqual(floresta_chain["best_block"], utreexo_chain["bestblockhash"])
        self.assertEqual(floresta_chain["height"], utreexo_chain["blocks"])

        self.log("=== Get a block hash from utreexod to invalidate")
        hash = self.utreexod.rpc.get_blockhash(5)
        self.utreexod.rpc.invalidate_block(hash)

        self.log("=== Mining alternative chain with utreexod.rpc...")
        self.utreexod.rpc.generate(10)

        self.log("=== Wait for the nodes to sync")
        time.sleep(20)

        self.log("=== Check that floresta has switched to the new chain")
        floresta_chain = self.florestad.rpc.get_blockchain_info()
        utreexo_chain = self.utreexod.rpc.get_blockchain_info()
        self.assertEqual(floresta_chain["best_block"], utreexo_chain["bestblockhash"])
        self.assertEqual(floresta_chain["height"], utreexo_chain["blocks"])

        self.log("=== Compare the accumulator roots for each node")
        floresta_roots = self.florestad.rpc.get_roots()
        utreexo_roots = self.utreexod.rpc.get_utreexo_roots(
            utreexo_chain["bestblockhash"]
        )
        self.assertEqual(floresta_roots, utreexo_roots["roots"])

        self.stop()


if __name__ == "__main__":
    ChainReorgTest().main()
