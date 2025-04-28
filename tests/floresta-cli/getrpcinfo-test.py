"""
floresta_cli_getrpcinfo.py

This functional test cli utility to interact with a Floresta node with `getrpcinfo`
"""

import os
import tempfile

from test_framework import FlorestaTestFramework
from test_framework.rpc.floresta import REGTEST_RPC_SERVER


class GetRpcInfoTest(FlorestaTestFramework):
    """
    Test `getrpcinfo` rpc call, by creating a node
    """

    nodes = [-1]
    data_dir = os.path.normpath(
        os.path.join(
            FlorestaTestFramework.get_integration_test_dir(),
            "data",
            "florestacli-getrpcinfo-test",
            "node-0",
        )
    )

    def set_test_params(self):
        """
        Setup the two node florestad process with different data-dirs, electrum-addresses
        and rpc-addresses in the same regtest network
        """
        GetRpcInfoTest.nodes[0] = self.add_node(
            extra_args=[
                f"--data-dir={GetRpcInfoTest.data_dir}",
            ],
            rpcserver=REGTEST_RPC_SERVER,
        )

    def run_test(self):
        """
        Run JSONRPC server on first, wait to connect, then call `addnode ip[:port]`
        """
        # Start node
        self.run_node(GetRpcInfoTest.nodes[0])

        # Test assertions
        node = self.get_node(GetRpcInfoTest.nodes[0])

        result = node.rpc.get_rpcinfo()
        self.assertIn("active_commands", result)
        self.assertIn("logpath", result)
        self.assertEqual(len(result["active_commands"]), 1)
        self.assertIn("duration", result["active_commands"][0])
        self.assertIn("method", result["active_commands"][0])
        self.assertEqual(result["active_commands"][0]["duration"], 0)
        self.assertEqual(result["active_commands"][0]["method"], "getrpcinfo")
        self.assertEqual(
            result["logpath"],
            os.path.normpath(
                os.path.join(GetRpcInfoTest.data_dir, "regtest", "output.log")
            ),
        )

        # stop node
        self.stop_node(GetRpcInfoTest.nodes[0])


if __name__ == "__main__":
    GetRpcInfoTest().main()
