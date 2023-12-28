"""
    This is an example of how tests should look lke, see the class bellow for more info
"""
import time
import os

from test_framework.test_framework import TestFramework
from test_framework.electrum_client import ElectrumClient
from test_framework.mock_rpc import MockUtreexod


class ExampleTest(TestFramework):
    """ Tests should be a child class from TestFramework """

    # All tests should override the run_test method
    def run_test(self):
        # This creates a dummy rpc listening on port 8080
        self.run_rpc()
        # Wait until the rpc is ready
        # Start a new node (this crate's binary)
        node1 = self.run_node("./data/test1", "regtest")
        # Wait the node to start
        self.wait_for_rpc_connection()
        # Create an instance of the Electrum Client, a small implementation of the electrum
        # protocol, to test our own electrum implementation
        electrum = ElectrumClient("localhost", 50001)
        print(electrum.get_version())


if __name__ == '__main__':
    ExampleTest().main()
