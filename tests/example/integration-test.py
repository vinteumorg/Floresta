"""
integration-test.py

This is an example of how a tests with integrated electrum should look like,
see `tests/test_framework/test_framework.py` for more info.
"""

from test_framework import FlorestaTestFramework
from test_framework.rpc.floresta import REGTEST_RPC_SERVER as FLORESTA_RPC_SERVER
from test_framework.rpc.utreexo import REGTEST_RPC_SERVER as UTREEXO_RPC_SERVER


class IntegrationTest(FlorestaTestFramework):
    """
    Tests should be a child class from FlorestaTestFramework

    In each test class definition, `set_test_params` and `run_test`, say what
    the test do and the expected result in the docstrings
    """

    index = [-1, -1]
    expected_chain = "regtest"

    def set_test_params(self):
        """
        Here we define setup for test adding a node definition
        """
        IntegrationTest.index[0] = self.add_node(
            variant="florestad", rpcserver=FLORESTA_RPC_SERVER
        )
        IntegrationTest.index[1] = self.add_node(
            variant="utreexod", rpcserver=UTREEXO_RPC_SERVER
        )

    # All tests should override the run_test method
    def run_test(self):
        """
        Here we define the test itself:

        - creates two dummy rpc listening on its default port,
          one for florestad and another for utreexod
        - perform some requests to FlorestaRPC node
        - perform some requests to UtreexoRPC node
        - assert the responses from both nodes
        - compare if both have similar values
        - if any assertion fails, all nodes will be stopped
        - if no error occurs, all nodes will be stopped at the end
        """
        # Start a new node (this crate's binary)
        # This method start a defined daemon,
        # in this case, `florestad`, and wait for
        # all ports opened by it, including the
        # RPC port to be available
        self.run_node(IntegrationTest.index[0])

        # Start a new node (this go's binary)
        # This method start a defined daemon,
        # in this case, `utreexod`, and wait for
        # all ports opened by it, including the
        # RPC port to be available
        self.run_node(IntegrationTest.index[1])

        # get both nodes
        floresta_node = self.get_node(IntegrationTest.index[0])
        utreexo_node = self.get_node(IntegrationTest.index[1])

        # Perform for some defined requests to FlorestaRPC
        # that should be the same for UtreexoRPC
        floresta_response = floresta_node.rpc.get_blockchain_info()
        utreexo_response = utreexo_node.rpc.get_blockchain_info()

        self.assertEqual(floresta_response["chain"], IntegrationTest.expected_chain)
        self.assertEqual(utreexo_response["chain"], IntegrationTest.expected_chain)
        # stop all nodes
        self.stop()


if __name__ == "__main__":
    IntegrationTest().main()
