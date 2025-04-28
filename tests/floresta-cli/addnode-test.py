"""
floresta_cli_addnode.py

This functional test cli utility to interact with a Floresta node with `addnode`
"""

import os
import tempfile

from test_framework import FlorestaTestFramework
from test_framework.rpc.floresta import REGTEST_RPC_SERVER


class GetAddnodeIDBErrorTest(FlorestaTestFramework):
    """
    Test `addnode` rpc call, by creating two nodes (in its IDB state), where
    the first one should connect with the second one by calling `addnode ip[:port]`.

    Maybe its worth to add custom electrum servers and custom data-dirs for each florestad process
    """

    nodes = [-1, -1]
    data_dirs = [
        os.path.normpath(
            os.path.join(
                FlorestaTestFramework.get_integration_test_dir(),
                "data",
                "florestacli-addnode-test",
                "node-0",
            )
        ),
        os.path.normpath(
            os.path.join(
                FlorestaTestFramework.get_integration_test_dir(),
                "data",
                "floresta-cli-addnode-test",
                "node-1",
            )
        ),
    ]

    # The port 50002 do not have any TLS meaning here,
    # it's just another port for another node
    electrum_addrs = ["0.0.0.0:50001", "0.0.0.0:50002"]
    rpc_addrs = ["0.0.0.0:18442", "0.0.0.0:18443"]
    node_ibd_error = "Node is in initial block download, wait until it's finished"

    def set_test_params(self):
        """
        Setup the two node florestad process with different data-dirs, electrum-addresses
        and rpc-addresses in the same regtest network
        """
        GetAddnodeIDBErrorTest.nodes[0] = self.add_node(
            extra_args=[
                f"--data-dir={GetAddnodeIDBErrorTest.data_dirs[0]}",
                f"--electrum-address={GetAddnodeIDBErrorTest.electrum_addrs[0]}",
                f"--rpc-address={GetAddnodeIDBErrorTest.rpc_addrs[0]}",
            ],
            rpcserver=REGTEST_RPC_SERVER,
            ssl=False,
        )

        GetAddnodeIDBErrorTest.nodes[1] = self.add_node(
            extra_args=[
                f"--data-dir={GetAddnodeIDBErrorTest.data_dirs[1]}",
                f"--electrum-address={GetAddnodeIDBErrorTest.electrum_addrs[1]}",
                f"--rpc-address={GetAddnodeIDBErrorTest.rpc_addrs[1]}",
            ],
            rpcserver={
                "host": "127.0.0.1",
                "ports": {"rpc": 18443, "server": 50002},
                "jsonrpc": "2.0",
                "timeout": 10000,
            },
            ssl=False,
        )

    def run_test(self):
        """
        Run JSONRPC server on first, wait to connect, then call `addnode ip[:port]`
        """
        # Start node
        self.run_node(GetAddnodeIDBErrorTest.nodes[0])
        node_0 = self.get_node(GetAddnodeIDBErrorTest.nodes[0])

        # start a second node
        self.run_node(GetAddnodeIDBErrorTest.nodes[1])
        node_1 = self.get_node(GetAddnodeIDBErrorTest.nodes[1])

        # Test assertions
        result_0 = node_0.rpc.addnode(node="0.0.0.0:18443")
        self.assertTrue(result_0)

        result_1 = node_1.rpc.addnode(node="0.0.0.0:18442")
        self.assertTrue(result_1)

        # stop both nodes
        self.stop()


if __name__ == "__main__":
    GetAddnodeIDBErrorTest().main()
