"""
floresta_cli_getpeerinfo.py

This functional test cli utility to interact with a Floresta node with `getpeerinfo`
"""

import re
import time
from test_framework import FlorestaTestFramework
from test_framework.rpc.floresta import REGTEST_RPC_SERVER

DATA_DIR = FlorestaTestFramework.get_integration_test_dir()


class GetPeerInfoTest(FlorestaTestFramework):
    """
    Test `getpeerinfo` between three implementations.
    """

    def set_test_params(self):
        """
        Setup a single node
        """
        name = self.__class__.__name__.lower()
        self.v2transport = False
        self.data_dirs = GetPeerInfoTest.create_data_dirs(DATA_DIR, name, 3)
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
        Run JSONRPC server and get some data about blockchain with only regtest genesis block
        """
        self.run_node(self.florestad)
        self.run_node(self.utreexod)
        self.run_node(self.bitcoind)

        self.log("=== Nodes aren't connected, zero peers on list")
        result = self.florestad.rpc.get_peerinfo()
        self.assertIsSome(result)
        self.assertEqual(len(result), 0)

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
        floresta_peerinfo = self.florestad.rpc.get_peerinfo()
        self.assertHasAny(
            floresta_peerinfo,
            re.compile(r"/btcwire:\d+\.\d+\.\d+/utreexod:\d+\.\d+\.\d+/"),
        )

        self.log("=== Connect bitcoind to utreexod")
        self.bitcoind.rpc.addnode(f"{host}:{port}", command="onetry", v2transport=False)

        self.log("=== Waiting for bitcoind to connect to utreexod...")
        time.sleep(5)
        bitcoind_peerinfo = self.bitcoind.rpc.get_peerinfo()
        self.assertHasAny(
            bitcoind_peerinfo,
            re.compile(r"/btcwire:\d+\.\d+\.\d+/utreexod:\d+\.\d+\.\d+/"),
        )

        self.log("=== Check that floresta has the same peerinfo as bitcoind...")
        self.assertEqual(floresta_peerinfo[0]["kind"], "manual")
        self.assertEqual(bitcoind_peerinfo[0]["connection_type"], "manual")

        # stop the node
        self.stop()


if __name__ == "__main__":
    GetPeerInfoTest().main()
