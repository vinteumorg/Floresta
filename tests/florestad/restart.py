"""
restart.py

A simple test that restart a Floresta node and a related data directory.

The directories used between each power-on/power-off must not be corrupted.
"""

import filecmp

from test_framework import FlorestaTestFramework, NodeType


class TestRestart(FlorestaTestFramework):
    """
    Test the restart of a node, calling a first node (0) the recall it as (1);
    We need to check if given data_dirs arent corrupted between restarts
    """

    def set_test_params(self):
        """
        Here we define setup for test
        """

        self.florestas = [
            self.add_node_default_args(
                variant=NodeType.FLORESTAD,
            ),
            self.add_node_default_args(
                variant=NodeType.FLORESTAD,
            ),
        ]

    def run_test(self):
        """
        Tests if we don't corrupt our data dir between restarts.
        This would have caught, the error fixed in #9
        """
        # start first node then stop
        # wait for some time before restarting
        # this simulate a shutdown followed by a power-on.
        # In a real world scenario, we need to wait for
        # the node to be fully started before stopping it
        # this is done by waiting for the RPC port (the run_node
        # method does this for us, but let's wait a bit more)
        self.run_node(self.florestas[0])
        self.florestas[0].rpc.wait_for_connection(opened=True)
        self.florestas[0].stop()

        # start second node then stop
        self.run_node(self.florestas[1])
        self.florestas[1].rpc.wait_for_connection(opened=True)
        self.florestas[1].stop()

        # check for any corruption
        # if any files are different, we will get a list of them
        result = filecmp.dircmp(
            self.florestas[0].daemon.data_dir, self.florestas[1].daemon.data_dir
        )
        self.assertEqual(len(result.diff_files), 0)


if __name__ == "__main__":
    TestRestart().main()
