"""
floresta_cli_getblock.py

This functional test cli utility to interact with a Floresta node with `getblock`
"""

import time

from test_framework import FlorestaTestFramework
from test_framework.rpc.floresta import REGTEST_RPC_SERVER

DATA_DIR = FlorestaTestFramework.get_integration_test_dir()


class GetBlockTest(FlorestaTestFramework):

    def set_test_params(self):

        self.v2transport = True
        self.data_dirs = GetBlockTest.create_data_dirs(DATA_DIR, "get_block", 2)

        self.florestad = self.add_node(
            variant="florestad",
            extra_args=[f"--data-dir={self.data_dirs[0]}"],
        )

        self.bitcoind = self.add_node(
            variant="bitcoind",
            extra_args=[f"-datadir={self.data_dirs[1]}", "-v2transport=1"],
        )

    def compare_block(self):
        block_hash = self.bitcoind.rpc.get_bestblockhash()
        floresta_block = self.florestad.rpc.get_block(block_hash, 0)
        bitcoind_block = self.bitcoind.rpc.get_block(block_hash, 0)
        self.assertEqual(floresta_block, bitcoind_block)

        floresta_block = self.florestad.rpc.get_block(block_hash, 1)
        bitcoind_block = self.bitcoind.rpc.get_block(block_hash, 1)

        for key, bval in bitcoind_block.items():
            fval = floresta_block[key]
            if key == "difficulty":
                # Allow small differences in floating point representation
                self.assertEqualFloat(fval, bval)
            else:
                self.assertEqual(fval, bval)

    def run_test(self):
        self.run_node(self.florestad)
        self.run_node(self.bitcoind)

        bitcoind_port = self.bitcoind.get_port("p2p")
        self.florestad.rpc.addnode(
            node=f"127.0.0.1:{bitcoind_port}",
            command="add",
            v2transport=self.v2transport,
        )

        self.compare_block()

        self.bitcoind.rpc.generate_block(2017)
        time.sleep(1)
        self.bitcoind.rpc.generate_block(6)

        timeout_secs = 10
        start = time.time()
        while (
            self.florestad.rpc.get_block_count() != self.bitcoind.rpc.get_block_count()
        ):
            if time.time() - start > timeout_secs:
                self.stop()
                floresta_count = self.florestad.rpc.get_block_count()
                bitcoind_count = self.bitcoind.rpc.get_block_count()
                raise RuntimeError(
                    f"Timeout waiting for florestad to reach {bitcoind_count} blocks,"
                    f" but got {floresta_count} (>{timeout_secs}s)"
                )
            time.sleep(0.5)

        self.compare_block()

        self.stop()


if __name__ == "__main__":
    GetBlockTest().main()
