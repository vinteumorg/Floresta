"""
restart.py

A simple test that restart a Floresta node and a related data directory.

The directories used between each power-on/power-off must not be corrupted.
"""

import time
import os
import filecmp
import tempfile
from test_framework.test_framework import FlorestaTestFramework
from test_framework.floresta_rpc import REGTEST_RPC_SERVER


class TestRestart(FlorestaTestFramework):
    """
    Test the restart of a node, calling a first node (0) the recall it as (1);
    We need to check if given data_dirs arent corrupted between restarts
    """

    indexes = [-1, -1]
    data_dirs = [
        os.path.normpath(
            os.path.join(
                tempfile.gettempdir(), "floresta-func-tests", "restart", "node-0"
            )
        ),
        os.path.normpath(
            os.path.join(
                tempfile.gettempdir(), "floresta-func-tests", "restart", "node-1"
            )
        ),
    ]

    def set_test_params(self):
        """
        Here we define setup for test
        """
        TestRestart.indexes[0] = self.add_node_settings(
            chain="regtest",
            extra_args=[f"--data-dir={TestRestart.data_dirs[0]}"],
            rpcserver=REGTEST_RPC_SERVER,
        )
        TestRestart.indexes[1] = self.add_node_settings(
            chain="regtest",
            extra_args=[f"--data-dir={TestRestart.data_dirs[1]}"],
            rpcserver=REGTEST_RPC_SERVER,
        )

    def run_test(self):
        """
        Tests if we don't corrupt our data dir between restarts. This would have caught,
        the error fixed in #9
        """
        # start first node, wait and then kill
        self.run_node(TestRestart.indexes[0])
        time.sleep(5.0)
        self.stop_node(TestRestart.indexes[0])

        # start second node, wait and then kill
        self.run_node(TestRestart.indexes[1])
        time.sleep(5.0)
        self.stop_node(TestRestart.indexes[1])

        # check for any corruption
        assert filecmp.dircmp(TestRestart.data_dirs[0], TestRestart.data_dirs[1])


if __name__ == "__main__":
    TestRestart().main()
