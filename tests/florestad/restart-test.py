"""
restart.py

A simple test that restart a Floresta node and a related data directory.

The directories used between each power-on/power-off must not be corrupted.
"""

import filecmp

from test_framework import FlorestaTestFramework

DATA_DIR = FlorestaTestFramework.get_integration_test_dir()


class TestRestart(FlorestaTestFramework):
    """
    Test the restart of a node, calling a first node (0) the recall it as (1);
    We need to check if given data_dirs arent corrupted between restarts
    """

    def set_test_params(self):
        """
        Here we define setup for test
        """

        self.data_dirs = TestRestart.create_data_dirs(
            DATA_DIR, self.__class__.__name__.lower(), 2
        )

        self.florestas = [
            self.add_node(
                variant="florestad",
                extra_args=[f"--data-dir={datadir}"],
            )
            for datadir in self.data_dirs
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
        self.florestas[0].rpc.wait_for_connections(opened=True)
        self.florestas[0].stop()

        # start second node then stop
        self.run_node(self.florestas[1])
        self.florestas[1].rpc.wait_for_connections(opened=True)
        self.florestas[1].stop()

        # check for any corruption
        # if any files are different, we will get a list of them
        result = filecmp.dircmp(self.data_dirs[0], self.data_dirs[1])
        self.assertEqual(len(result.diff_files), 0)


if __name__ == "__main__":
    TestRestart().main()
