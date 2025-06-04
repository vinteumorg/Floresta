"""
tests/test_framework/__init__.py

Adapted from
https://github.com/bitcoin/bitcoin/blob/master/test/functional/test_framework/test_framework.py

BitcoinCore functional tests define a metaclass that checks if some important
methods are defined or not defined. Floresta functional tests will follow this
since it is a good practice for a framework. The difference is that our node
will run withing a `cargo run` subprocess, defined at `add_node_settings`.
"""

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Pattern

from test_framework.crypto.pkcs8 import (
    create_pkcs8_private_key,
    create_pkcs8_self_signed_certificate,
)
from test_framework.daemon.bitcoin import BitcoinDaemon
from test_framework.daemon.floresta import FlorestaDaemon
from test_framework.daemon.utreexo import UtreexoDaemon
from test_framework.rpc.bitcoin import BitcoinRPC
from test_framework.rpc.floresta import FlorestaRPC
from test_framework.rpc.utreexo import UtreexoRPC


class Node:
    """
    A node object to be used in the test framework.
    It contains the daemon, rpc and rpc_config objects.
    """

    def __init__(self, daemon, rpc, rpc_config, variant):
        self.daemon = daemon
        self.rpc = rpc
        self.rpc_config = rpc_config
        self.variant = variant

    def start(self):
        """
        Start the node.
        """
        if self.daemon.is_running:
            raise RuntimeError(f"Node '{self.variant}' is already running.")
        self.daemon.start()
        self.rpc.wait_for_connections(opened=True)

    def stop(self):
        """
        Stop the node.
        """
        if self.daemon.is_running:
            response = self.rpc.stop()
            self.rpc.wait_for_connections(opened=False)
            self.daemon.process.wait()
            return response
        return None


class FlorestaTestMetaClass(type):
    """
    Metaclass for FlorestaTestFramework.

    Ensures that any attempt to register a subclass of `FlorestaTestFramework`
    adheres to a standard whereby the subclass override `set_test_params` and
    `run_test but DOES NOT override either `__init__` or `main`.

    If any of those standards are violated, a `TypeError` is raised.
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
    and aims to configure the node variant, its daemon parameters
    or whatever you think should be defined. It is a good practice
    to set the number of nodes and their configuration in this method
    with `self.add_node`.

    The `run_test` method is the test itself, where one (or more) node(s)
    are started with the `self.run_node` method. This method will return
    a index integer for a `Node` object stored in a `self.nodes` property,
    each node containing the initialized `daemon` process, a `rpc` and
    `rpc_config` objects. The `rpc` object can be a `FlorestaRPC` or
    `UtreexoRPC` object, depending on the node variant defined.

    When a node start, it will wait for ALL node's socket ports to be opened.
    Inversely, the method `self.stop_node` will wait for ALL node's ports to
    be closed (you could also use `self.stop` to stop all nodes). Internally,
    it uses `node.rpc.wait_for_connections(opened=True)` to wait for all ports
    to be opened, or `node.rpc.wait_for_connections(opened=False)` to wait for
    all ports to be closed. You could use them if you want more control.

    Also, the `self.run_test` method is where you should call for assertions
    like `self.assertIsNone`, `self.assertIsSome`, `self.assertEqual`,
    `self.assertIn`, `self.assertMatch`, `self.assertTrue` and
    `self.assertRaises`. If the assertion passes, the test will continue.
    If it fails, the test will stop all nodes and raise an `AssertionError`.

    The `self.assertRaises` method is a special case. It should be used in a
    context manager, i.e., the `with self.assertRaises(<SomeException>)`
    clause. The context will expect for some exception to be raised and,
    if it raises, the script will continue. If it does not raise, it will stop
    all nodes and raise an `AssertionError`.

    In both methods, you can use `self.log` to log messages.

    At the end of file, you should execute `MyTest().main()` method.

    For more details, see the tests/example/*-test.py file to see how
    the Floresta team thought the test framework should be used and
    test/test_framework/{crypto,daemon,rpc,electrum}/*.py to see
    how the test framework was structured.
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
        self._nodes = []

    # pylint: disable=R0801
    def log(self, msg: str):
        """Log a message with the class caller"""

        now = (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .strftime("%Y-%m-%d %H:%M:%S")
        )
        print(f"[{self.__class__.__name__} {now}] {msg}")

    def main(self):
        """
        Main function.

        This should not be overridden by the subclass test scripts.
        """
        self.set_test_params()
        self.run_test()

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
        return os.getenv("FLORESTA_TEMP_DIR")

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
            FlorestaTestFramework.get_integration_test_dir(), "data", "ssl"
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

    def is_option_set(self, extra_args: list[str], option: str) -> bool:
        """
        Check if an option is set in extra_args
        """
        for arg in extra_args:
            if arg.startswith(option):
                return True
        return False

    # pylint: disable=dangerous-default-value
    def add_node(
        self,
        rpcserver: Dict[str, str | Dict[str, str | int] | int],
        extra_args: List[str] = [],
        variant: str = "florestad",
        ssl: bool = False,
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
        tempdir = FlorestaTestFramework.get_integration_test_dir()
        targetdir = os.path.normpath(os.path.join(tempdir, "binaries"))

        # Daemon can be a variant of Floresta or Utreexo
        daemon = None
        testname = self.__class__.__name__.lower()

        if variant == "florestad":
            daemon = FlorestaDaemon()
            daemon.create(target=targetdir)
            daemon.add_daemon_settings(extra_args)

            # Add a default data-dir if not set
            if not self.is_option_set(extra_args, "--data-dir"):
                daemon.add_daemon_settings([f"--data-dir={tempdir}/data/{testname}"])

            # configure (or not) the ssl keys
            if not ssl:
                daemon.add_daemon_settings(["--no-ssl"])
            else:
                (key, cert) = self.create_ssl_keys()
                daemon.add_daemon_settings(
                    [f"--ssl-key-path={key}", f"--ssl-cert-path={cert}"]
                )

        elif variant == "utreexod":
            daemon = UtreexoDaemon()
            daemon.create(target=targetdir)
            daemon.add_daemon_settings(extra_args)

            # Add a default datadir if not set
            if not self.is_option_set(extra_args, "--datadir"):
                daemon.add_daemon_settings([f"--datadir={tempdir}/data/{testname}"])

            # configure (or not) the ssl keys
            if not ssl:
                daemon.add_daemon_settings(["--notls"])
            else:
                (key, cert) = self.create_ssl_keys()
                daemon.add_daemon_settings([f"--rpckey={key}", f"--rpccert={cert}"])

        elif variant == "bitcoind":
            daemon = BitcoinDaemon()
            daemon.create(target=targetdir)
            daemon.add_daemon_settings(extra_args)

            # Add a default datadir if not set
            if not self.is_option_set(extra_args, "-datadir"):
                daemon.add_daemon_settings([f"-datadir={tempdir}/data/{testname}"])

                # we need to create the datadir
                datadir = os.path.join(tempdir, "data", testname)
                if not os.path.exists(datadir):
                    os.makedirs(os.path.join(tempdir, "data", testname), exist_ok=True)

        else:
            raise ValueError(f"'{variant}' not supported")

        node = Node(daemon, rpc=None, rpc_config=rpcserver, variant=variant)
        self._nodes.append(node)
        return len(self._nodes) - 1

    def get_node(self, index: int) -> Node:
        """
        Given an index, return a node configuration.
        If the node not exists, raise a IndexError exception.
        """
        if index < 0 or index >= len(self._nodes):
            raise IndexError(
                f"Node {index} not found. Please run it with add_node_settings"
            )
        return self._nodes[index]

    def run_node(self, index: int, timeout: int = 10):
        """
        Run a node given an index on self._tests.

        If the node not exists raise a IndexError. At the time
        the tests will only run nodes configured to run on regtest.
        """
        node = self.get_node(index)
        node.daemon.start()

        if node.variant == "florestad":
            node.rpc = FlorestaRPC(node.daemon.process, node.rpc_config)

        if node.variant == "utreexod":
            node.rpc = UtreexoRPC(node.daemon.process, node.rpc_config)

        if node.variant == "bitcoind":
            node.rpc = BitcoinRPC(node.daemon.process, node.rpc_config)

        node.rpc.wait_for_connections(opened=True, timeout=timeout)
        self.log(f"Node {index} ({node.variant}) started")

    def stop_node(self, index: int):
        """
        Stop a node given an index on self._tests.
        """
        node = self.get_node(index)
        return node.stop()

    def stop(self):
        """
        Stop all nodes.
        """
        for i in range(len(self._nodes)):
            self.stop_node(i)

    # pylint: disable=invalid-name
    def assertTrue(self, condition: bool):
        """
        Assert if the condition is True, otherwise
        all nodes will be stopped and an AssertionError will
        be raised.
        """
        if not condition:
            self.stop()
            raise AssertionError(f"Actual: {condition}\nExpected: True")

    def assertFalse(self, condition: bool):
        """
        Assert if the condition is False, otherwise
        all nodes will be stopped and an AssertionError will
        be raised.
        """
        if condition:
            self.stop()
            raise AssertionError(f"Actual: {condition}\nExpected: False")

    # pylint: disable=invalid-name
    def assertIsNone(self, thing: Any):
        """
        Assert if the condition is None, otherwise
        all nodes will be stopped and an AssertionError will
        be raised.
        """
        if thing is not None:
            self.stop()
            raise AssertionError(f"Actual: {thing}\nExpected: None")

    # pylint: disable=invalid-name
    def assertIsSome(self, thing: Any):
        """
        Assert if the condition is not None, otherwise
        all nodes will be stopped and an AssertionError will
        be raised.
        """
        if thing is None:
            self.stop()
            raise AssertionError(f"Actual: {thing}\nExpected: not None")

    # pylint: disable=invalid-name
    def assertEqual(self, condition: Any, expected: Any):
        """
        Assert if the condition is True, otherwise
        all nodes will be stopped and an AssertionError will
        be raised.
        """

        if not condition == expected:
            self.stop()
            raise AssertionError(f"Actual: {condition}\nExpected: {expected}")

    # pylint: disable=invalid-name
    def assertIn(self, element: Any, listany: List[Any]):
        """
        Assert if the element is in listany , otherwise
        all nodes will be stopped and an AssertionError will
        be raised.
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
