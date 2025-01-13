"""
floresta_cli_uptime.py

This functional test cli utility to interact with a Floresta node with `uptime`
"""

import os
import time
import tempfile
from test_framework.test_framework import FlorestaTestFramework
from test_framework.floresta_rpc import REGTEST_RPC_SERVER


class UptimeTest(FlorestaTestFramework):
    """
    Test `uptime` rpc call, by creating a node, wait for
    some time (10 seconds) and assert that this wait time is
    equal to how long florestad has been running
    """

    nodes = [-1]

    # pylint: disable=duplicate-code
    data_dir = os.path.normpath(
        os.path.join(
            tempfile.gettempdir(),
            "floresta-func-tests",
            "florestacli-uptime-test",
            "node-0",
        )
    )

    def set_test_params(self):
        """
        Setup the two node florestad process with different data-dirs, electrum-addresses
        and rpc-addresses in the same regtest network
        """
        UptimeTest.nodes[0] = self.add_node_settings(
            chain="regtest",
            extra_args=[
                f"--data-dir={UptimeTest.data_dir}",
            ],
            rpcserver=REGTEST_RPC_SERVER,
        )

    def run_test(self):
        """
        Run JSONRPC server on first, wait to connect, then call `addnode ip[:port]`
        """
        # Start node
        self.run_node(UptimeTest.nodes[0])
        self.wait_for_rpc_connection(UptimeTest.nodes[0])

        # wait for some seconds before get the uptime
        # and get the current time
        before = time.time()
        time.sleep(5)

        # Test assertions
        node = self.get_node(UptimeTest.nodes[0])
        uptime = node.uptime()

        # calculate the elapsed time
        after = time.time()
        elapsed = int(after - before)

        assert uptime == elapsed

        # Stop node
        self.stop_node(UptimeTest.nodes[0])


if __name__ == "__main__":
    UptimeTest().main()
