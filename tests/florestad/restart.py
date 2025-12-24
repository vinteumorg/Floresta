"""
restart.py

A simple test that restarts a Floresta node and ensures that the node can
successfully restart using the same data directory.

The test verifies that the node can stop and restart without encountering
issues, such as data corruption or failure to initialize.
"""

from test_framework import FlorestaTestFramework

DATA_DIR = FlorestaTestFramework.get_integration_test_dir()


class TestRestart(FlorestaTestFramework):
    """
    Test the restart of a Floresta node using the same data directory.
    Ensures that the node can stop and restart without issues.
    """

    def set_test_params(self):
        """
        Here we define setup for test
        """

        self.data_dir = TestRestart.create_data_dirs(
            DATA_DIR, self.__class__.__name__.lower(), 1
        )[0]

        self.floresta = self.add_node(
            variant="florestad",
            extra_args=[f"--data-dir={self.data_dir}"],
        )

    def run_test(self):
        """
        Tests the node's ability to restart without initialization issues.
        This would have caught, the error fixed in #9
        """

        self.run_node(self.floresta)
        self.floresta.stop()

        self.run_node(self.floresta)


if __name__ == "__main__":
    TestRestart().main()
