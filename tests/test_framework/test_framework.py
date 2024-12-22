"""
test_framework.py

Adapted from
https://github.com/bitcoin/bitcoin/blob/master/test/functional/test_framework/test_framework.py

BitcoinCore functional tests define a metaclass that checks if some important methods are defined
or not defined.

Floresta functional tests will follow this since it is a good practice for a framework.

The difference is that our node will run withing a `cargo run` subprocess, defined at
`add_node_settings`.
"""

import os
import subprocess
import shutil
from threading import Thread
from test_framework.mock_rpc import MockUtreexod
from test_framework.floresta_rpc import FlorestaRPC


class FlorestaTestMetaClass(type):
    """
    Metaclass for FlorestaTestFramework.

    Ensures that any attempt to register a subclass of `FlorestaTestFramework`
    adheres to a standard whereby the subclass override `set_test_params` and
    `run_test but DOES NOT override either `__init__` or `main`.

    If any of those standards are violated, a ``TypeError`` is raised.
    """

    def __new__(mcs, clsname, bases, dct):
        if not clsname == "FlorestaTestFramework":
            if not ("run_test" in dct and "set_test_params" in dct):
                raise TypeError(
                    "FlorestaTestFramework subclasses must override 'run_test'"
                    "and 'set_test_params'"
                )

            if "__init__" in dct or "main" in dct:
                raise TypeError(
                    "FlorestaTestFramework subclasses may not override "
                    "'__init__' or 'main'"
                )

        return super().__new__(mcs, clsname, bases, dct)


class FlorestaTestFramework(metaclass=FlorestaTestMetaClass):
    """
    Base class for a floresta test script.

    Individual floresta test scripts should subclass this class and override the:

    - set_test_params(); and
    - run_test() methods.
    """

    def __init__(self):
        """
        Sets test framework defaults.

        Do not override this method. Instead, override the set_test_params() method
        """
        self._tests = []
        self._nodes = []
        self._rpc = None

    def main(self):
        """
        Main function.

        This should not be overridden by the subclass test scripts.
        """
        self.set_test_params()
        self.run_test()
        self.stop()

    # Should be overrided by individual tests
    def set_test_params(self):
        """
        Tests must override this method to change default values for number of nodes, topology, etc
        """
        raise NotImplementedError

    def run_test(self):
        """
        Tests must override this method to run nodes, etc.
        """
        raise NotImplementedError

    # Framework
    def add_node_settings(
        self, chain: str, extra_args: list[str], rpcserver: dict, data_dir: str = ""
    ) -> int:
        """
        Add a node settings to be run.

        Use this on set_test_params method many times you want
        """
        self._tests.append(
            {
                "chain": chain,
                "extra_args": extra_args,
                "config": [
                    "cargo",
                    "run",
                    "--features",
                    "json-rpc",
                    "--bin",
                    "florestad",
                    "--",
                    "--network",
                    chain,
                    "--no-ssl",
                ],
                "rpcserver": rpcserver,
                "data_dir": data_dir,
            }
        )

        return len(self._tests) - 1

    def get_node_settings(self, index: int) -> dict:
        """
        Given an index, return a node configuration
        """
        return self._tests[index]

    def run_node(self, index: int):
        """
        Run a node given an index on self._tests.

        If the node not exists raise a IndexError. At the time
        the tests will only run nodes configured to run on regtest.
        """
        node = self._tests[index]

        if node["chain"] == "regtest":
            # pylint: disable=consider-using-with
            process_node = subprocess.Popen(node["config"])
            json_rpc = FlorestaRPC(
                process=process_node,
                extra_args=node["extra_args"],
                rpcserver=node["rpcserver"],
            )
            self._nodes.append(json_rpc)

        else:
            chain = node["chain"]
            raise RuntimeError(f"Uninmplemented test_framework for chain '{chain}'")

    def get_node(self, index: int) -> FlorestaRPC:
        """
        Given an index, return a node configuration
        """
        return self._nodes[index]

    def wait_for_rpc_connection(self, index: int):
        """
        Wait for rpc in a given node index
        """
        node = self._nodes[index]
        node.wait_for_rpc_connection()

    def run_rpc(self):
        """
        Run RPC as a thread
        """
        self._rpc = Thread(target=MockUtreexod().run)
        self._rpc.daemon = True
        self._rpc.start()

    def stop_node(self, index: int):
        """
        Stop a node given an index
        """
        node = self._nodes[index]
        node.kill()
        node.wait_to_stop()
        settings = self._tests[index]
        data_dir = settings["data_dir"]
        if data_dir != "" and os.path.exists(data_dir):
            shutil.rmtree(data_dir)

    def stop(self):
        """
        Stop all nodes
        """
        for i in range(len(self._nodes)):
            self.stop_node(i)
