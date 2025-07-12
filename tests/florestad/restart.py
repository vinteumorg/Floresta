"""
restart.py

A simple test that restart a Floresta node and a related data directory.

The directories used between each power-on/power-off must not be corrupted.
"""

import filecmp
import os
import tempfile

from test_framework import FlorestaTestFramework
from test_framework.rpc.floresta import REGTEST_RPC_SERVER


class TestRestart(FlorestaTestFramework):
    """
    Test the restart of a node, calling a first node (0) the recall it as (1);
    We need to check if given data_dirs arent corrupted between restarts
    """

    indexes = [-1, -1]
    data_dirs = [
        os.path.normpath(
            os.path.join(
                FlorestaTestFramework.get_integration_test_dir(),
                "data",
                "restart",
                "node-0",
            )
        ),
        os.path.normpath(
            os.path.join(
                FlorestaTestFramework.get_integration_test_dir(),
                "data",
                "restart",
                "node-1",
            )
        ),
    ]

    def set_test_params(self):
        """
        Here we define setup for test
        """
        TestRestart.indexes[0] = self.add_node(
            extra_args=[f"--data-dir={TestRestart.data_dirs[0]}"],
            rpcserver=REGTEST_RPC_SERVER,
        )
        TestRestart.indexes[1] = self.add_node(
            extra_args=[f"--data-dir={TestRestart.data_dirs[1]}"],
            rpcserver=REGTEST_RPC_SERVER,
        )

    def run_test(self):
        """
        Tests if we don't corrupt our data dir between restarts.
        This would have caught, the error fixed in #9
        """
        # start first node then stop
        self.run_node(TestRestart.indexes[0])

        # wait for some time before restarting
        # this simulate a shutdown followed by a power-on.
        # In a real world scenario, we need to wait for
        # the node to be fully started before stopping it
        # this is done by waiting for the RPC port (the run_node
        # method does this for us, but let's wait a bit more)
        node = self.get_node(TestRestart.indexes[0])
        node.rpc.wait_for_connections(opened=True)
        self.stop_node(TestRestart.indexes[0])

        # start second node then stop
        self.run_node(TestRestart.indexes[1])
        node = self.get_node(TestRestart.indexes[1])
        node.rpc.wait_for_connections(opened=True)
        self.stop_node(TestRestart.indexes[1])

        # check for any corruption
        # if any files are different, we will get a list of them
        result = filecmp.dircmp(TestRestart.data_dirs[0], TestRestart.data_dirs[1])
        self.assertEqual(len(result.diff_files), 0)


if __name__ == "__main__":
    TestRestart().main()
