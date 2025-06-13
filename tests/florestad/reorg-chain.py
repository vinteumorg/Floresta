"""
Chain reorg test

This test will spawn a florestad and a utreexod, we will use utreexod to mine some blocks.
Then we will invalidate one of those blocks, and mine an alternative chain. This should
make florestad switch to the new chain. We then compare the two node's main chain and
accumulator to make sure they are the same.
"""

from test_framework import FlorestaRPC, UtreexoRPC, FlorestaTestFramework
from test_framework.rpc.floresta import REGTEST_RPC_SERVER as florestad_rpc
from test_framework.rpc.utreexo import REGTEST_RPC_SERVER as utreexod_rpc

import time


class ChainReorgTest(FlorestaTestFramework):
    index = [-1, -1]
    expected_chain = "regtest"

    def set_test_params(self):
        ChainReorgTest.index[0] = self.add_node(
            variant="florestad", rpcserver=florestad_rpc
        )

        # since utreexod and bitcoind
        # uses the same RPC server, we need to
        # select a different port for utreexod
        utreexod_rpc["ports"]["server"] = 18446
        utreexod_rpc["ports"]["rpc"] = 18447
        ChainReorgTest.index[1] = self.add_node(
            variant="utreexod",
            rpcserver=utreexod_rpc,
            extra_args=[
                "--listen=127.0.0.1:18446",
                "--rpclisten=127.0.0.1:18447",
                "--miningaddr=bcrt1q4gfcga7jfjmm02zpvrh4ttc5k7lmnq2re52z2y",
                "--utreexoproofindex",
                "--prune=0",
            ],
        )

    def run_test(self):
        # Start the nodes
        self.run_node(ChainReorgTest.index[0])
        self.run_node(ChainReorgTest.index[1])

        utreexod: UtreexoRPC = self.get_node(ChainReorgTest.index[1]).rpc

        # Mine some blocks with utreexod
        self.log("Mining blocks with utreexod...")
        utreexod.generate(10)

        # Connect floresta to utreexod
        florestad: FlorestaRPC = self.get_node(ChainReorgTest.index[0]).rpc
        florestad.addnode(
            f"{utreexod_rpc["host"]}:{utreexod_rpc["ports"]["server"]}", "onetry"
        )

        time.sleep(20)

        # Check that floresta has the same chain as utreexod
        floresta_chain = florestad.get_blockchain_info()
        utreexo_chain = utreexod.get_blockchain_info()

        self.assertEqual(floresta_chain["height"], utreexo_chain["blocks"])

        hash = utreexod.get_blockhash(5)
        self.log(f"Block hash at height 5: {hash}")
        utreexod.invalidate_block(hash)

        # Mine an alternative chain with 20 blocks
        self.log("Mining alternative chain with utreexod...")
        utreexod.generate(20)

        # Wait for the nodes to sync
        time.sleep(10)

        # Check that floresta has switched to the new chain
        floresta_chain = florestad.get_blockchain_info()
        utreexo_chain = utreexod.get_blockchain_info()
        self.assertEqual(floresta_chain["height"], utreexo_chain["blocks"])

        # Compare the accumulator roots for each node
        floresta_roots = florestad.get_roots()
        utreexo_roots = utreexod.get_utreexo_roots(utreexo_chain["bestblockhash"])
        self.assertEqual(floresta_roots, utreexo_roots["roots"])

        self.stop()


if __name__ == "__main__":
    ChainReorgTest().main()
