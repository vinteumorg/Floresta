"""
floresta_cli_getblockhash.py

This functional test cli utility to interact with a Floresta node with `getblockhash`
"""

from test_framework import FlorestaTestFramework


class GetBlockhashTest(FlorestaTestFramework):
    """
    Test `getblock` with a fresh node and expected initial 0 height block
    """

    best_block = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"

    def set_test_params(self):
        """
        Setup a single node
        """
        self.florestad = self.add_node(variant="florestad")

    def run_test(self):
        """
        Run JSONRP and get the hash of height 0
        """
        # Start node
        self.run_node(self.florestad)

        # Test assertions
        response = self.florestad.rpc.get_blockhash(0)
        self.assertEqual(response, GetBlockhashTest.best_block)

        # stop the node
        self.stop()


if __name__ == "__main__":
    GetBlockhashTest().main()
