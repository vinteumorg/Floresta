"""
getblock.py

This functional test cli utility to interact with a Floresta node with `getbloc`
compliant with Bitcoin-Core.

It starts three nodes, one miner (utreexod) and two sync nodes (florestad and bitcoind).
The miner is also a bridge node.

The miner will mine 101 blocks, and the sync nodes will update their states. Once updated,
the sync nodes  will call for `getblock` rpc command.
"""

import re
import time
from test_framework import FlorestaTestFramework


DATA_DIR = FlorestaTestFramework.get_integration_test_dir()
BLOCKS = 101
SERIALIZED_DATA = "".join(
    [
        "010000000000000000000000000000000000000000000000000000000000000000000000",
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494d",
        "ffff7f200200000001010000000100000000000000000000000000000000000000000000",
        "00000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f",
        "4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f",
        "6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104",
        "678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f",
        "4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000",
    ]
)


class GetBlockTest(FlorestaTestFramework):
    """
    Test florestad's `getblock` by running three nodes in
    a "semi-triangle" network structure, where florestad and bitcoind
    nodes are connected to utreexod, but not connected between them.
    Then assert that the same get_blockheader between florestad and core
    are equal.
    """

    def set_test_params(self):
        """
        Setup a florestad/bitcoind peers and a utreexod mining node
        """
        name = self.__class__.__name__.lower()
        self.v2transport = False
        self.data_dirs = GetBlockTest.create_data_dirs(DATA_DIR, name, 3)
        self.florestad = self.add_node(
            variant="florestad", extra_args=[f"--data-dir={self.data_dirs[0]}"]
        )

        self.utreexod = self.add_node(
            variant="utreexod",
            extra_args=[
                f"--datadir={self.data_dirs[1]}",
                "--miningaddr=bcrt1q4gfcga7jfjmm02zpvrh4ttc5k7lmnq2re52z2y",
                "--prune=0",
            ],
        )

        self.bitcoind = self.add_node(
            variant="bitcoind", extra_args=[f"-datadir={self.data_dirs[2]}"]
        )

    def run_test(self):
        """
        Run a florestad/bitcoind/utreexod nodes. Then mine some blocks
        with utreexod. After that, connect the nodes and wait for them to sync.
        Finally, test the `getblockheader` rpc command checking if it's
        different from genesis one and equals to utreexod one.
        """
        self.run_node(self.florestad)
        self.run_node(self.utreexod)
        self.run_node(self.bitcoind)

        self.log("=== Mining  with utreexod")
        self.utreexod.rpc.generate(BLOCKS)
        time.sleep(5)

        self.log("=== Connect floresta to utreexod")
        host = self.utreexod.get_host()
        port = self.utreexod.get_port("p2p")
        self.florestad.rpc.addnode(
            f"{host}:{port}", command="onetry", v2transport=False
        )

        self.log("=== Waiting for floresta to connect to utreexod...")
        time.sleep(5)
        peer_info = self.florestad.rpc.get_peerinfo()
        self.assertMatch(
            peer_info[0]["user_agent"],
            re.compile(r"/btcwire:\d+\.\d+\.\d+/utreexod:\d+\.\d+\.\d+/"),
        )

        self.log("=== Connect bitcoind to utreexod")
        host = self.utreexod.get_host()
        port = self.utreexod.get_port("p2p")
        self.bitcoind.rpc.addnode(f"{host}:{port}", command="onetry", v2transport=False)

        self.log("=== Waiting for bitcoind to connect to utreexod...")
        time.sleep(5)
        peer_info = self.bitcoind.rpc.get_peerinfo()
        self.assertMatch(
            peer_info[0]["subver"],
            re.compile(r"/btcwire:\d+\.\d+\.\d+/utreexod:\d+\.\d+\.\d+/"),
        )

        for height in range(BLOCKS):
            self.log(
                f"=== Check floresta have the same blockheader as core for height {height}..."
            )
            floresta_hash = self.florestad.rpc.get_blockhash(height)
            bitcoin_hash = self.bitcoind.rpc.get_blockhash(height)
            self.assertEqual(floresta_hash, bitcoin_hash)

            floresta_header = self.florestad.rpc.get_block(floresta_hash, 0)
            bitcoin_header = self.bitcoind.rpc.get_block(bitcoin_hash, 0)
            self.assertEqual(floresta_header, bitcoin_header)

            floresta_verbose_header = self.florestad.rpc.get_block(floresta_hash, 1)
            bitcoin_verbose_header = self.bitcoind.rpc.get_block(bitcoin_hash, 1)

            # Not test in regtest network the "difficulty" field since
            # rust-bitcoin apply correctly while core have a bug in this field
            for key in (
                "hash",
                "confirmations",
                "height",
                "version",
                "versionHex",
                "merkleroot",
                "time",
                "mediantime",
                "nonce",
                "bits",
                "target",
                "chainwork",
                "nTx",
            ):
                self.assertEqual(
                    floresta_verbose_header[key], bitcoin_verbose_header[key]
                )

            # These assertions will run only in some
            # general conditions like the height
            if height != 0:
                self.assertEqual(
                    floresta_verbose_header["previousblockhash"],
                    bitcoin_verbose_header["previousblockhash"],
                )

                if height > 1:
                    self.assertAlmostEqual(
                        floresta_verbose_header["difficulty"],
                        bitcoin_verbose_header["difficulty"],
                    )

            self.assertEqual(
                floresta_verbose_header["nextblockhash"],
                bitcoin_verbose_header["nextblockhash"],
            )

        # stop the node
        self.stop()


if __name__ == "__main__":
    GetBlockTest().main()
