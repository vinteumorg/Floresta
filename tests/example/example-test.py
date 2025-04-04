"""
example_test.py

This is an example of how tests should look like, see the class bellow for more info.

Every test should define, at least, two special methods:

- `set_test_params`: change default values for number of node, topology, etc.
- `run_test`: the test itself

Any attempt to define a test without these methods will raise a TypeError.

Other methods are available to do more things. Some of them make sense only in `set_test_params`
and others make sense only in `run_tests`.

- `add_node_settings`: register a node settings to create a node after. A node will be a spawned
                       `cargo run --features json-rpc --bin florestad -- --network <chain>` process.
                       In summary, its a `FlorestaRPC` instance.

                       The chain can be one of ["regtest", "signet", "testnet"].
                       You can pass some extra arguments with `extra_args` and it will be appended
                       to the process command. The `rpcserver` is a dictionary defining a "host",
                       "port", "username" and "password". The "data_dir" is optional and can be
                       used to create a temporary directory to store files. It will return an
                       integer pointing an index of a list of nodes.

- `get_node_settings`: get a registered node settings

- `run_node`: run a node for a registered node settings at some index,
              configured with `add_node_settings`.

- `get_node`: get a resgistered running node.

- `wait_for_rpc_connection`: given a node index, wait for it to be available.

- `run_rpc`: our RPC is a MockUtreexod running on a thread.

- `stop_node`: given a running node at index, stop it.
               If any directory was created, it will be removed.

- `stop`: stop all registered nodes.

After the definition of test within a class, you should call `MyTest().main()` at the end of file.
"""

import json
from test_framework.electrum_client import ElectrumClient
from test_framework.floresta_rpc import REGTEST_RPC_SERVER
from test_framework.test_framework import FlorestaTestFramework


class ExampleTest(FlorestaTestFramework):
    """
    Tests should be a child class from FlorestaTestFramework

    In each test class definition, `set_test_params` and `run_test`, say what
    the test do and the expected result in the docstrings
    """

    index = [-1]
    expected_version = ["Floresta 0.3.0", "1.4"]
    expected_height = 0
    expected_block = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    expected_difficulty = 1
    expected_leaf_count = 0

    def set_test_params(self):
        """
        Here we define setup for test adding a node definition
        """
        ExampleTest.index[0] = self.add_node_settings(
            chain="regtest", extra_args=[], rpcserver=REGTEST_RPC_SERVER
        )

    # All tests should override the run_test method
    def run_test(self):
        """
        Here we define the test itself:

        - creates a dummy rpc listening on port 8080
        - wait until the rpc is ready and start a new node (this crate's binary)
        - wait the node to start
        - perform some requests to FlorestaRPC node
        - Create an instance of the Electrum Client, a small implementation of the electrum
          protocol, to test our own electrum implementation
        """
        # Start a new node (this crate's binary)
        self.run_node(ExampleTest.index[0])

        # Wait the node to start
        self.wait_for_rpc_connection(ExampleTest.index[0])

        # Perform for some defined requests to FlorestaRPC
        node = self.get_node(ExampleTest.index[0])
        inf_response = node.get_blockchain_info()

        # Create an instance of the Electrum Client, a small implementation of the electrum
        # protocol, to test our own electrum implementation
        electrum = ElectrumClient("localhost", 50001)
        rpc_response = json.loads(electrum.get_version())

        # Make assertions with our framework. Avoid usage of
        # native `assert` clauses. For more information, see
        # https://github.com/vinteumorg/Floresta/issues/426
        self.assertEqual(rpc_response["result"][0], ExampleTest.expected_version[0])
        self.assertEqual(rpc_response["result"][1], ExampleTest.expected_version[1])
        self.assertEqual(inf_response["height"], ExampleTest.expected_height)
        self.assertEqual(inf_response["best_block"], ExampleTest.expected_block)
        self.assertEqual(inf_response["difficulty"], ExampleTest.expected_difficulty)
        self.assertEqual(inf_response["leaf_count"], ExampleTest.expected_leaf_count)

        # At the end, you should stop all nodes with the `stop`
        # method. Alternatively, you can use `stop_node(int) where int`
        # is the node index
        self.stop()


if __name__ == "__main__":
    ExampleTest().main()
