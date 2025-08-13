"""
getblockheader.py

This functional test cli utility to interact with a Floresta node with `getblockheader`
"""

import re
import time
from test_framework import FlorestaTestFramework

DATA_DIR = FlorestaTestFramework.get_integration_test_dir()


class GetBlockheaderTest(FlorestaTestFramework):
    """
    Compare the `getblockheader` command output with a known block header with
    the values from utreexod and bitcoind.
    """

    version = 1
    blockhash = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    prev_blockhash = "0000000000000000000000000000000000000000000000000000000000000000"
    merkle_root = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    time = 1296688602
    bits = 545259519
    nonce = 2

    def set_test_params(self):
        """
        Setup three nodes for the test: florestad, utreexod (miner),
        and bitcoind.
        """
        name = self.__class__.__name__.lower()
        self.v2transport = False
        self.data_dirs = GetBlockheaderTest.create_data_dirs(DATA_DIR, name, 3)

        self.florestad = self.add_node(variant="florestad")

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
        Run JSONRPC and get the block headers of heights 0 to 1O.
        """
        self.log("=== Starting nodes...")
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

        self.log("=== Get the tip block")
        block_count = self.florestad.rpc.get_block_count()

        for i in range(0, block_count + 1):
            self.log(f"=== Get blockhash for height {i}...")
            hash = self.florestad.rpc.get_blockhash(i)

            self.log(f"=== Check the correct blockheader for height {i}...")
            header_floresta = self.florestad.rpc.get_blockheader(hash)
            header_utreexod = self.utreexod.rpc.get_blockheader(hash)
            header_bitcoind = self.bitcoind.rpc.get_blockheader(hash)

            for field in (
                "version",
                "prev_blockhash",
                "merkle_root",
                "time",
                "bits",
                "nonce",
            ):
                self.log(f"=== Get file {field} for hash {hash}...")
                self.assertEqual(header_floresta[field], header_utreexod[field])
                self.assertEqual(header_floresta[field], header_bitcoind[field])

        # stop the node
        self.stop()


if __name__ == "__main__":
    GetBlockheaderTest().main()
