"""
floresta_cli_getblockheader.py

This functional test cli utility to interact with a Floresta node with `getblockheader`
"""

import re
import time
from test_framework import FlorestaTestFramework

DATA_DIR = FlorestaTestFramework.get_integration_test_dir()


class GetBlockheaderTest(FlorestaTestFramework):
    """
    Test florestad's `getbestblockheader` by running three nodes in
    a "semi-triangle" network structure, where florestad and bitcoind
    nodes are connected to utreexod, but not connected between them.
    Then assert that the same get_blockheader in three nodes, before mining
    and after mining.
    """

    def set_test_params(self):
        """
        Setup a florestad/bitcoind peers and a utreexod mining node
        """
        name = self.__class__.__name__.lower()
        self.v2transport = False
        self.data_dirs = GetBlockheaderTest.create_data_dirs(DATA_DIR, name, 3)
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

        self.log("=== Mining blocks with utreexod")
        self.utreexod.rpc.generate(10)
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

        self.log("=== Wait for the nodes to sync...")
        time.sleep(5)

        for height in range(10):
            self.log(
                f"=== Check floresta have the same blockheader as core for height {height}..."
            )
            floresta_hash = self.florestad.rpc.get_blockhash(height)
            bitcoin_hash = self.bitcoind.rpc.get_blockhash(height)
            self.assertEqual(floresta_hash, bitcoin_hash)

            floresta_header = self.florestad.rpc.get_blockheader(floresta_hash, False)
            bitcoin_header = self.bitcoind.rpc.get_blockheader(bitcoin_hash, False)
            self.assertEqual(floresta_header, bitcoin_header)

            floresta_verbose_header = self.florestad.rpc.get_blockheader(
                floresta_hash, True
            )
            bitcoin_verbose_header = self.bitcoind.rpc.get_blockheader(
                bitcoin_hash, True
            )

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

                if height != 10:
                    self.assertEqual(
                        floresta_verbose_header["nextblockhash"],
                        bitcoin_verbose_header["nextblockhash"],
                    )
        # stop the node
        self.stop()


if __name__ == "__main__":
    GetBlockheaderTest().main()
