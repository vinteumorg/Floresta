"""
test_framework.py

Adapted from
https://github.com/bitcoin/bitcoin/blob/master/test/functional/test_framework/test_framework.py

BitcoinCore functional tests define a metaclass that checks if some important
methods are defined or not defined. Floresta functional tests will follow this
since it is a good practice for a framework. The difference is that our node
will run withing a `cargo run` subprocess, defined at `add_node_settings`.
"""

import os
import re
import subprocess
from typing import Any, List, Pattern

from test_framework.crypto.pkcs8 import (
    create_pkcs8_private_key,
    create_pkcs8_self_signed_certificate,
)
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
    "--ssl-electrum-address",
    "--ssl-cert-path",
    "--ssl-key-path",
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


# pylint: disable=too-many-public-methods
class FlorestaTestFramework(metaclass=FlorestaTestMetaClass):
    """
    Base class for a floresta test script. Individual floresta
    test scripts should:

    - subclass FlorestaTestFramework;
    - not override the __init__() method;
    - not override the main() method;
    - implement set_test_params();
    - implement run_test();

    The `set_test_params` method is called before the test starts
    and aims to configure nodes, florestad params, what should be
    considered as expected result, and what you think should be defined.
    It is a good practice to set the number of nodes and their
    configuration in this method with `self.add_node_settings`.

    The `run_test` method is the test itself, where a (or more) node(s)
    are started, and the test is executed. This is where you start a node
    with `run_node` and wait for it to be ready with `wait_for_rpc_connection`.
    It is also where you should do the assertions (`self.assertIsNone`,
    `self.assertIsSome`, `self.assertEqual`, `self.assertIn`,
    `self.assertMatch`, `self.assertTrue`, `self.assertRaises`)
    as well stop nodes when done (`self.stop_node` for stop one node
    or `self.stop` to stop all nodes).

    In both mthods, you can use `self.log` to log messages.

    At the end of file, you should execute `MyTest().main()` method.

    For more details, see the tests/example/example-test.py and/or
    tests/test_framework/test_framework.py.
    """

    class _AssertRaisesContext:
        """
        Context manager for testing that an exception is raised.

        This keeps the assertRaises functionality neatly contained within our test framework
        """

        def __init__(self, test_framework, expected_exception):
            """Initialize the context manager with the expected exception type."""
            self.test_framework = test_framework
            self.expected_exception = expected_exception
            self.exception = None

        def __enter__(self):
            """Enter the context manager."""
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            """Exit the context manager and check if the expected exception was raised."""
            if exc_type is None:
                self.test_framework.stop_all_nodes()
                trace = traceback.format_exc()
                message = f"{self.expected_exception} was not raised"
                raise AssertionError(f"{message}: {trace}")

            if not issubclass(exc_type, self.expected_exception):
                trace = traceback.format_exc()
                message = f"Expected {self.expected_exception} but got {exc_type}"
                raise AssertionError(f"{message}: {trace}")

            self.exception = exc_value
            return True

    def __init__(self):
        """
        Sets test framework defaults.

        Do not override this method. Instead, override the set_test_params() method
        """
        self._tests = []
        self._nodes = []

    def log(self, msg: str):
        """Log a message with the class caller"""
        print(f"[{self.__class__.__name__} INFO] {msg}")

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
        Get path for florestad used in integration tests, generally set on
        $FLORESTA_TEMP_DIR/binaries
        """
        if os.getenv("FLORESTA_TEMP_DIR") is None:
            raise RuntimeError(
                "FLORESTA_TEMP_DIR not set. "
                + " Please set it to the path of the integration test directory."
            )
        return os.path.normpath(
            os.path.join(os.getenv("FLORESTA_TEMP_DIR"), "binaries")
        )

    def create_ssl_keys(self) -> tuple[str, str]:
        """
        Create a PKCS#8 formatted private key and a self-signed certificate.
        These keys are intended to be used with florestad's --ssl-key-path and --ssl-cert-path
        options.
        """
        # If we're in CI, we need to use the
        # path to the integration test dir
        # tempfile will be used to get the proper
        # temp dir for the OS
        ssl_rel_path = os.path.join(
            FlorestaTestFramework.get_integration_test_dir(), "..", "..", "ssl"
        )
        ssl_path = os.path.normpath(os.path.abspath(ssl_rel_path))

        # Create the folder if not exists
        os.makedirs(ssl_path, exist_ok=True)

        # Create certificates
        pk_path, private_key = create_pkcs8_private_key(ssl_path)
        self.log(f"Created PKCS#8 key at {pk_path}")

        cert_path = create_pkcs8_self_signed_certificate(
            ssl_path, private_key, common_name="florestad", validity_days=365
        )
        self.log(f"Created self-signed certificate at {cert_path}")

        return (pk_path, cert_path)

    # Framework
    def add_node_settings(
        self, chain: str, extra_args: list[str], rpcserver: dict, ssl: bool = False
    ) -> int:
        """
        Add a node settings to be run. Use this on set_test_params method
        many times you want. Extra_args should be a list of string in the
        --key=value strings (see florestad --help for a list of available
        commands)
        """
        # PR #331 introduced a preparatory environment at
        # /tmp/floresta-integration-tests.$(git rev-parse HEAD).
        # So, check for it first before define the florestad path.
        if os.getenv("FLORESTA_TEMP_DIR") is not None:
            targetdir = FlorestaTestFramework.get_integration_test_dir()

        else:
            raise RuntimeError(
                "FLORESTA_TEMP_DIR not set. "
                + " Please set it to the path of the integration test directory."
            )

        florestad = os.path.join(targetdir, "florestad")

        # In case any florestad is found, raise an exception
        if not os.path.exists(florestad):
            raise RuntimeError(f"Not found any 'florestad' in '{targetdir}'")

        setting = {
            "chain": chain,
            "config": [florestad, "--network", chain],
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

        # If ssl isnt enabled, add --no-ssl
        # if ssl is enabled, user can add:
        #   --ssl-cert-path
        #   --ssl-key-path
        # Either way, we need to create PKCS#8 key and certificate
        if not ssl:
            setting["config"].append("--no-ssl")
        else:
            (key, cert) = self.create_ssl_keys()
            setting["config"].append("--ssl-key-path")
            setting["config"].append(key)
            setting["config"].append("--ssl-cert-path")
            setting["config"].append(cert)

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
            # add text=True to treat all outputs as texts
            # (jsons or python stack traces)
            cmd = " ".join(node["config"])
            self.log(f"Running '{cmd}'")
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

    # pylint: disable=invalid-name
    def assertTrue(self, condition: bool):
        """
        Assert if the condition is True, otherwise
        all nodes will be stopped and an AssertionError will
        be raised
        """
        if not condition:
            self.stop()
            raise AssertionError(f"Actual: {condition}\nExpected: True")

    # pylint: disable=invalid-name
    def assertIsNone(self, thing: Any):
        """
        Assert if the condition is None, otherwise
        all nodes will be stopped and an AssertionError will
        be raised
        """
        if thing is not None:
            self.stop()
            raise AssertionError(f"Actual: {thing}\nExpected: None")

    # pylint: disable=invalid-name
    def assertIsSome(self, thing: Any):
        """
        Assert if the condition is not None, otherwise
        all nodes will be stopped and an AssertionError will
        be raised
        """
        if thing is None:
            self.stop()
            raise AssertionError(f"Actual: {thing}\nExpected: not None")

    # pylint: disable=invalid-name
    def assertEqual(self, condition: Any, expected: Any):
        """
        Assert if the condition is True, otherwise
        all nodes will be stopped and an AssertionError will
        be raised
        """

        if not condition == expected:
            self.stop()
            raise AssertionError(f"Actual: {condition}\nExpected: {expected}")

    # pylint: disable=invalid-name
    def assertIn(self, element: Any, listany: List[Any]):
        """
        Assert if the element is in listany , otherwise
        all nodes will be stopped and an AssertionError will
        be raised
        """

        if element not in listany:
            self.stop()
            raise AssertionError(
                f"Actual: {element} not in {listany}\nExpected: {element} in {listany}"
            )

    # pylint: disable=invalid-name
    def assertMatch(self, actual: Any, pattern: Pattern):
        """
        Assert if the element fully matches a pattern, otherwise
        all nodes will be stopped and an AssertionError will
        be raised
        """

        if not re.fullmatch(pattern, actual):
            self.stop()
            raise AssertionError(
                f"Actual: {actual} !~ {pattern} \nExpected: {actual} ~ {set}"
            )

    def assertRaises(self, expected_exception):
        """Assert that the expected exception is raised."""
        return self._AssertRaisesContext(self, expected_exception)
