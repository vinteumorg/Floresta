"""
floresta_cli_getrpcinfo.py

This functional test cli utility to interact with a Floresta node with `getrpcinfo`
"""

import os
import tempfile
from test_framework.test_framework import FlorestaTestFramework
from test_framework.floresta_rpc import REGTEST_RPC_SERVER


class GetRpcInfoTest(FlorestaTestFramework):
    """
    Test `getrpcinfo` rpc call, by creating a node
    """

    nodes = [-1]
    data_dir = os.path.normpath(
        os.path.join(
            tempfile.gettempdir(),
            "floresta-func-tests",
            "florestacli-getrpcinfo-test",
            "node-0",
        )
    )

    def set_test_params(self):
        """
        Setup the two node florestad process with different data-dirs, electrum-addresses
        and rpc-addresses in the same regtest network
        """
        GetRpcInfoTest.nodes[0] = self.add_node_settings(
            chain="regtest",
            extra_args=[
                f"--data-dir={GetRpcInfoTest.data_dir}",
            ],
            rpcserver=REGTEST_RPC_SERVER,
        )

    def test_rpcinfo_result(self, node):
        """
        Test if the 'getrpcinfo' result was built correctly
        """
        result = node.get_rpcinfo()
        assert "active_commands" in result
        assert "logpath" in result
        assert len(result["active_commands"]) == 1
        assert "duration" in result["active_commands"][0]
        assert "method" in result["active_commands"][0]
        assert result["active_commands"][0]["duration"] == 0
        assert result["active_commands"][0]["method"] == "getrpcinfo"
        assert result["logpath"] == os.path.normpath(
            os.path.join(GetRpcInfoTest.data_dir, "regtest", "output.log")
        )

    def run_test(self):
        """
        Run JSONRPC server on first, wait to connect, then call `addnode ip[:port]`
        """
        # Start node
        self.run_node(GetRpcInfoTest.nodes[0])
        self.wait_for_rpc_connection(GetRpcInfoTest.nodes[0])

        # Test assertions
        node = self.get_node(GetRpcInfoTest.nodes[0])
        self.test_rpcinfo_result(node)

        # Stop node
        self.stop_node(GetRpcInfoTest.nodes[0])


if __name__ == "__main__":
    GetRpcInfoTest().main()
