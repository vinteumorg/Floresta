"""
floresta_cli_addnode.py

This functional test cli utility to interact with a Floresta node with `addnode`
"""

import os
import tempfile
from test_framework.test_framework import FlorestaTestFramework
from test_framework.floresta_rpc import REGTEST_RPC_SERVER, JSONRPCError

# Setup a little node with another port
ANOTHER_REGTEST_RPC_SERVER = {
    "host": "127.0.0.1",
    "port": 18443,
    "user": "anotheruser",
    "password": "anotherpassword",
}


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
                tempfile.gettempdir(),
                "floresta-func-tests",
                "florestacli-addnode-test",
                "node-0",
            )
        ),
        os.path.normpath(
            os.path.join(
                tempfile.gettempdir(),
                "floresta-func-tests",
                "floresta-cli-addnode-test",
                "node-1",
            )
        ),
    ]
    electrum_addrs = ["0.0.0.0:50001", "0.0.0.0:50002"]
    rpc_addrs = ["0.0.0.0:18442", "0.0.0.0:18443"]
    node_ibd_error = "Node is in initial block download, wait until it's finished"

    def set_test_params(self):
        """
        Setup the two node florestad process with different data-dirs, electrum-addresses
        and rpc-addresses in the same regtest network
        """
        GetAddnodeIDBErrorTest.nodes[0] = self.add_node_settings(
            chain="regtest",
            extra_args=[
                f"--data-dir={GetAddnodeIDBErrorTest.data_dirs[0]}",
                f"--electrum-address={GetAddnodeIDBErrorTest.electrum_addrs[0]}",
                f"--rpc-address={GetAddnodeIDBErrorTest.rpc_addrs[0]}",
            ],
            rpcserver=REGTEST_RPC_SERVER,
        )

        GetAddnodeIDBErrorTest.nodes[1] = self.add_node_settings(
            chain="regtest",
            extra_args=[
                f"--data-dir={GetAddnodeIDBErrorTest.data_dirs[1]}",
                f"--electrum-address={GetAddnodeIDBErrorTest.electrum_addrs[1]}",
                f"--rpc-address={GetAddnodeIDBErrorTest.rpc_addrs[1]}",
            ],
            rpcserver=ANOTHER_REGTEST_RPC_SERVER,
        )

    def run_test(self):
        """
        Run JSONRPC server on first, wait to connect, then call `addnode ip[:port]`
        """
        # Start node
        self.run_node(GetAddnodeIDBErrorTest.nodes[0])
        self.wait_for_rpc_connection(GetAddnodeIDBErrorTest.nodes[0])

        # start a second node
        self.run_node(GetAddnodeIDBErrorTest.nodes[1])
        self.wait_for_rpc_connection(GetAddnodeIDBErrorTest.nodes[1])

        # Test assertions
        try:
            node = self.get_node(GetAddnodeIDBErrorTest.nodes[0])
            success = node.get_addnode(node="0.0.0.0:18443")
            assert success
        except JSONRPCError as exc:
            assert exc.code == -32603
            assert exc.message == GetAddnodeIDBErrorTest.node_ibd_error
            assert exc.data is None
        finally:
            # stop nodes
            self.stop_node(GetAddnodeIDBErrorTest.nodes[1])
            self.stop_node(GetAddnodeIDBErrorTest.nodes[0])


if __name__ == "__main__":
    GetAddnodeIDBErrorTest().main()
