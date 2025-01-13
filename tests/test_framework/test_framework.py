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
import tempfile
import subprocess
from test_framework.floresta_rpc import FlorestaRPC

VALID_FLORESTAD_EXTRA_ARGS = [
    "-c",
    "--config-file",
    "-d",
    "--debug",
    "--log-to-file",
    "--data-dir",
    "--cfilters",
    "-p",
    "--proxy",
    "--wallet-xpub",
    "--wallet-descriptor",
    "--assume-valid",
    "-z",
    "--zmq-address",
    "--connect",
    "--rpc-address",
    "--electrum-address",
    "--filters-start-height",
    "--assume-utreexo",
    "--pid-file",
]


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

    @staticmethod
    def get_integration_test_dir():
        """
        Get path for florestad used in integration tests, generally on
        /tmp/floresta-integration-tests.<some git commit>
        """
        with subprocess.Popen(
            ["git", "rev-parse", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as cmd:

            # get the git rev-parse
            stdout, stderr = cmd.communicate()

            # check for any error
            if isinstance(stderr, str) and stderr != "":
                raise RuntimeError(stderr)

            gitrev = stdout.rstrip()
            return os.path.normpath(
                os.path.join(
                    tempfile.gettempdir(),
                    f"floresta-integration-tests.{gitrev}",
                    "florestad",
                    "debug",
                )
            )

    @staticmethod
    def get_target_release_dir():
        """ "
        Get path for built florestad, generally on
        ./target/release/florestad
        """
        dirname = os.path.dirname(__file__)
        return os.path.normpath(os.path.join(dirname, "..", "..", "target", "release"))

    # Framework
    def add_node_settings(
        self, chain: str, extra_args: list[str], rpcserver: dict
    ) -> int:
        """
        Add a node settings to be run. Use this on set_test_params method many times you want.

        extra_args should be a list of string in the --key=value strings
        (see florestad --help for a list of available commands)
        """
        # PR #331 introduced a preparatory environment at
        # /tmp/floresta-integration-tests.$(git rev-parse HEAD).
        tmpdir = FlorestaTestFramework.get_integration_test_dir()
        targetdir = FlorestaTestFramework.get_target_release_dir()

        # So, check for it first before define the florestad path.
        if os.path.exists(tmpdir):
            florestad = os.path.normpath(os.path.join(tmpdir, "florestad"))

        # If not exists, define the one at ./target/release.
        elif os.path.exists(targetdir):
            florestad = os.path.normpath(os.path.join(targetdir, "florestad"))

        # In case any test florestad is found, raise an exception
        else:
            raise RuntimeError(
                f"Not found 'florestad' in '{tmpdir}' or '{targetdir}'. "
                "Run 'tests/prepare.sh' or 'cargo build --release'."
            )

        print(f"Using {florestad}")
        setting = {
            "chain": chain,
            "config": [
                florestad,
                "--network",
                chain,
                "--no-ssl",
            ],
            "rpcserver": rpcserver,
        }

        # If any extra-arg is needed
        # (see ./target/release/florestad --help)
        # append it after --no-ssl arg
        # Not all possible arguments are valid for tests
        # (for example, --version, --help, --ssl ones...)
        if extra_args is not None and len(extra_args) >= 1:
            for extra in extra_args:
                option = extra.split("=")[0] if "=" in extra else extra.split(" ")[0]
                if option in VALID_FLORESTAD_EXTRA_ARGS:
                    setting["config"].append(extra)
                else:
                    raise ValueError(f"Invalid extra_arg '{extra}'")

        self._tests.append(setting)
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
            # add text=True to treat all outputs as texts (jsons or python stack traces)
            process_node = subprocess.Popen(node["config"], text=True)
            json_rpc = FlorestaRPC(process=process_node, rpcserver=node["rpcserver"])
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

    def stop_node(self, index: int):
        """
        Stop a node given an index
        """
        node = self._nodes[index]
        node.kill()
        node.wait_to_stop()

    def stop(self):
        """
        Stop all nodes
        """
        for i in range(len(self._nodes)):
            self.stop_node(i)
