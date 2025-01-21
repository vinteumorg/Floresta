"""
floresta_cli_getmemoryinfo.py

This functional test cli utility to interact with a Floresta node with `getmemoryinfo`
"""

import os
import re
import sys
import tempfile
from test_framework.test_framework import FlorestaTestFramework
from test_framework.floresta_rpc import REGTEST_RPC_SERVER


class GetMemoryInfoTest(FlorestaTestFramework):
    """
    Test `getmemoryinfo` rpc call, by creating a node and get
    some memory stats with `stats` and `mallocinfo` modes
    """

    nodes = [-1]

    # pylint: disable=duplicate-code
    data_dir = os.path.normpath(
        os.path.join(
            tempfile.gettempdir(),
            "floresta-func-tests",
            "florestacli-getmemoryinfo-test",
            "node-0",
        )
    )

    def set_test_params(self):
        """
        Setup the two node florestad process with different data-dirs, electrum-addresses
        and rpc-addresses in the same regtest network
        """
        GetMemoryInfoTest.nodes[0] = self.add_node_settings(
            chain="regtest",
            extra_args=[
                f"--data-dir={GetMemoryInfoTest.data_dir}",
            ],
            rpcserver=REGTEST_RPC_SERVER,
        )

    def test_mode_stats_ibd(self, node):
        """
        Test `getmemoryinfo stats` when node is in IBD.
        It should return a dictionary with key(str)/value(int).
        """
        if sys.platform == "linux":
            result = node.get_memoryinfo("stats")
            assert "locked" in result
            assert "chunks_free" in result["locked"]
            assert "chunks_used" in result["locked"]
            assert "free" in result["locked"]
            assert "locked" in result["locked"]
            assert "total" in result["locked"]
            assert "used" in result["locked"]
            assert result["locked"]["chunks_free"] >= 0
            assert result["locked"]["chunks_used"] >= 0
            assert result["locked"]["free"] >= 0
            assert result["locked"]["locked"] >= 0
            assert result["locked"]["total"] >= 0
            assert result["locked"]["used"] >= 0
        else:
            print(
                f"Skiping test: 'getmemoryinfo stats' not implemented for '{sys.platform}'"
            )

    def test_mode_mallocinfo_ibd(self, node):
        """
        Test `getmemoryinfo mallocinfo` when node is in IBD
        It should return a malloc xml string.
        """
        if sys.platform == "linux":
            pattern = (
                r'<malloc version="[^"]+">'
                r'<heap nr="\d+">'
                r"<allocated>\d+</allocated>"
                r"<free>\d+</free>"
                r"<total>\d+</total>"
                r"<locked>\d+</locked>"
                r'<chunks nr="\d+">'
                r"<used>\d+</used>"
                r"<free>\d+</free>"
                r"</chunks>"
                r"</heap>"
                r"</malloc>"
            )
            result = node.get_memoryinfo("mallocinfo")
            assert re.fullmatch(pattern, result)
        else:
            print(
                f"Skiping test: 'getmemoryinfo malloc' not implemented for '{sys.platform}'"
            )

    def run_test(self):
        """
        Run JSONRPC server on first, wait to connect, then call `addnode ip[:port]`
        """
        # Start node
        self.run_node(GetMemoryInfoTest.nodes[0])
        self.wait_for_rpc_connection(GetMemoryInfoTest.nodes[0])

        # Test assertions
        node = self.get_node(GetMemoryInfoTest.nodes[0])
        self.test_mode_stats_ibd(node)
        self.test_mode_mallocinfo_ibd(node)

        # Stop node
        self.stop_node(GetMemoryInfoTest.nodes[0])


if __name__ == "__main__":
    GetMemoryInfoTest().main()
