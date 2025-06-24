"""
floresta_cli_uptime.py

This functional test cli utility to interact with a Floresta node with `uptime`
"""

import time
from test_framework import FlorestaTestFramework
from test_framework.rpc.floresta import REGTEST_RPC_SERVER as florestad_conf
from test_framework.rpc.bitcoin import REGTEST_RPC_SERVER as bitcoind_conf

DATA_DIR = FlorestaTestFramework.get_integration_test_dir()


class UptimeTest(FlorestaTestFramework):
    """
    Test `uptime` rpc call, by creating a node, wait for
    some time (10 seconds) and assert that this wait time is
    equal to how long florestad has been running
    """

    nodes = [-1, -1]

    def set_test_params(self):
        """
        Setup the two node florestad process with different data-dirs, electrum-addresses
        and rpc-addresses in the same regtest network
        """
        data_dirs = UptimeTest.create_data_dirs(
            DATA_DIR, self.__class__.__name__.lower(), nodes=2
        )

        UptimeTest.nodes[0] = self.add_node(
            variant="florestad",
            extra_args=[
                f"--data-dir={data_dirs[0]}",
            ],
            rpcserver=florestad_conf,
        )

        UptimeTest.nodes[1] = self.add_node(
            variant="bitcoind",
            extra_args=[
                f"-datadir={data_dirs[1]}",
            ],
            rpcserver=bitcoind_conf,
        )

    def test_node_uptime(self, index: int, test_time: int, margin: int):
        """
        Test the uptime of a node, given an index
        by checking if the uptime matches the elapsed
        time after starting the node with a grace period
        for startup and function call times
        """
        self.run_node(UptimeTest.nodes[index])
        node = self.get_node(UptimeTest.nodes[index])
        before = time.time()
        time.sleep(test_time)
        result = node.rpc.uptime()
        after = time.time()
        elapsed = int(after - before)

        self.assertTrue(result >= elapsed and result <= elapsed + margin)
        return result

    def run_test(self):
        """
        Run JSONRPC server on first, wait to connect, then call `addnode ip[:port]`
        """
        for i in range(len(UptimeTest.nodes)):
            self.test_node_uptime(index=i, test_time=5, margin=5)

        self.stop()


if __name__ == "__main__":
    UptimeTest().main()
