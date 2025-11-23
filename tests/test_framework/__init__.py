"""Test framework for Floresta integration tests.

This module provides a test framework for running integration tests with
Bitcoin daemons (bitcoind, florestad, utreexod).
"""

import os
import re
import sys
import copy
import random
import socket
import shutil
import signal
import contextlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Pattern

from test_framework.crypto.pkcs8 import (
    create_pkcs8_private_key,
    create_pkcs8_self_signed_certificate,
)

from test_framework.daemon.bitcoin import BitcoinDaemon
from test_framework.daemon.floresta import FlorestaDaemon
from test_framework.daemon.utreexo import UtreexoDaemon
from test_framework.rpc.bitcoin import (
    BitcoinRPC,
    REGTEST_RPC_SERVER as bitcoind_rpc_server,
)
from test_framework.rpc.floresta import (
    FlorestaRPC,
    REGTEST_RPC_SERVER as florestad_rpc_server,
)
from test_framework.rpc.utreexo import (
    UtreexoRPC,
    REGTEST_RPC_SERVER as utreexod_rpc_server,
)


class Node:
    """Represents a node in the test network (bitcoind, florestad, or utreexod)."""

    def __init__(self, daemon, rpc, rpc_config, variant):
        """Initialize a node.

        Args:
            daemon: Daemon process instance
            rpc: RPC client instance
            rpc_config: RPC configuration dictionary
            variant: Node type ('bitcoind', 'florestad', or 'utreexod')
        """
        self.daemon = daemon
        self.rpc = rpc
        self.rpc_config = rpc_config
        self.variant = variant

    def start(self):
        """Start the node daemon and wait for RPC connections."""
        if self.daemon.is_running:
            raise RuntimeError(f"Node '{self.variant}' is already running.")
        self.daemon.start()
        self.rpc.wait_for_connections(opened=True)

    def stop(self):
        """Stop the node daemon and wait for shutdown."""
        if self.daemon.is_running:
            response = self.rpc.stop()
            self.rpc.wait_for_connections(opened=False)
            self.daemon.process.wait()
            return response
        return None

    def get_host(self) -> str:
        """Get the host address for this node."""
        return self.rpc_config["host"]

    def get_ports(self) -> int:
        """Get all ports configuration for this node."""
        return self.rpc_config["ports"]

    def get_port(self, port_type: str) -> int:
        """Get a specific port for this node.

        Args:
            port_type: Type of port to retrieve (e.g., 'rpc', 'p2p')

        Returns:
            Port number

        Raises:
            ValueError: If port type not found
        """
        if port_type not in self.rpc_config["ports"]:
            raise ValueError(
                f"Port type '{port_type}' not found in node ports: "
                f"{self.rpc_config['ports']}"
            )
        return self.rpc_config["ports"][port_type]

    def send_kill_signal(self, sigcode="SIGTERM"):
        """Send a kill signal to the node process.

        Args:
            sigcode: Signal code to send (default: SIGTERM)
        """
        with contextlib.suppress(ProcessLookupError):
            pid = self.daemon.process.pid
            os.kill(pid, getattr(signal, sigcode, signal.SIGTERM))


class FlorestaTestMetaClass(type):
    """Metaclass for enforcing test framework contract."""

    def __new__(mcs, clsname, bases, dct):
        """Create a new test class and validate required methods."""
        if not clsname == "FlorestaTestFramework":
            if not ("run_test" in dct and "set_test_params" in dct):
                raise TypeError(
                    "FlorestaTestFramework subclasses must override "
                    "'run_test' and 'set_test_params'"
                )
            if "__init__" in dct or "main" in dct:
                raise TypeError(
                    "FlorestaTestFramework subclasses may not override "
                    "'__init__' or 'main'"
                )
        return super().__new__(mcs, clsname, bases, dct)


# pylint: disable=too-many-public-methods
class FlorestaTestFramework(metaclass=FlorestaTestMetaClass):
    """Base class for Floresta integration tests."""

    class _AssertRaisesContext:
        """Context manager for assertRaises."""

        def __init__(self, test_framework, expected_exception):
            """Initialize the context manager.

            Args:
                test_framework: Parent test framework instance
                expected_exception: Exception type expected to be raised
            """
            self.test_framework = test_framework
            self.expected_exception = expected_exception
            self.exception = None

        def __enter__(self):
            """Enter the context."""
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            """Exit the context and validate exception was raised."""
            if exc_type is None:
                self.test_framework.stop_all_nodes()
                raise AssertionError(f"{self.expected_exception} was not raised")
            if not issubclass(exc_type, self.expected_exception):
                raise AssertionError(
                    f"Expected {self.expected_exception} but got {exc_type}"
                )
            self.exception = exc_value
            return True

    def __init__(self):
        """Initialize the test framework."""
        self._nodes = []

    def log(self, msg: str):
        """Log a message with timestamp and test name.

        Args:
            msg: Message to log
        """
        now = datetime.now(timezone.utc).replace(microsecond=0)
        print(f"[{self.__class__.__name__} {now:%Y-%m-%d %H:%M:%S}] {msg}")

    def main(self):
        """Run the test and handle cleanup on failure."""
        try:
            self.cleanup()
            self.set_test_params()
            self.run_test()
        except Exception as err:
            processes = []
            for node in self._nodes:
                processes.append(str(node.daemon.process.pid))
                if getattr(node, "rpc", None):
                    node.rpc.stop()
                    node.rpc.wait_for_connections(opened=False)
                else:
                    try:
                        node.send_kill_signal("SIGTERM")
                    except Exception:  # pylint: disable=broad-exception-caught
                        node.send_kill_signal("SIGKILL")
            raise RuntimeError(
                f"Process with pids {', '.join(processes)} failed to start: {err}"
            ) from err

    def set_test_params(self):
        """Set test parameters. Must be overridden by subclasses."""
        raise NotImplementedError

    def run_test(self):
        """Run the test. Must be overridden by subclasses."""
        raise NotImplementedError

    @staticmethod
    def get_integration_test_dir():
        """Get the integration test directory from environment.

        Returns:
            Path to integration test directory

        Raises:
            RuntimeError: If FLORESTA_TEMP_DIR not set
        """
        if os.getenv("FLORESTA_TEMP_DIR") is None:
            raise RuntimeError("FLORESTA_TEMP_DIR not set")
        return os.getenv("FLORESTA_TEMP_DIR")

    @staticmethod
    def create_data_dirs(data_dir: str, base_name: str, nodes: int) -> list[str]:
        """Create data directories for multiple nodes.

        Args:
            data_dir: Base data directory
            base_name: Base name for node directories
            nodes: Number of nodes to create directories for

        Returns:
            List of created directory paths
        """
        paths = []
        for i in range(nodes):
            p = os.path.join(data_dir, "data", base_name, f"node-{i}")
            os.makedirs(p, exist_ok=True)
            paths.append(p)
        return paths

    @staticmethod
    def get_available_random_port(start: int, end: int = 65535):
        """Get a random available port in the specified range.

        Args:
            start: Starting port number
            end: Ending port number (default: 65535)

        Returns:
            Available port number
        """
        while True:
            port = random.randint(start, end)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(("127.0.0.1", port)) != 0:
                    return port

    def get_test_log_path(self) -> str:
        """Get the path for the test log file.

        Returns:
            Path to log file
        """
        tempdir = str(self.get_integration_test_dir())
        filename = os.path.basename(sys.modules[self.__class__.__module__].__file__)
        filename = filename.replace(".py", "")
        return os.path.join(tempdir, "logs", f"{filename}.log")

    def create_tls_key_cert(self) -> tuple[str, str]:
        """Create TLS key and certificate for secure connections.

        Returns:
            Tuple of (key_path, cert_path)
        """
        tls_rel_path = os.path.join(self.get_integration_test_dir(), "data", "tls")
        tls_path = os.path.normpath(os.path.abspath(tls_rel_path))
        os.makedirs(tls_path, exist_ok=True)

        pk_path, private_key = create_pkcs8_private_key(tls_path)
        self.log(f"Created PKCS#8 key at {pk_path}")

        cert_path = create_pkcs8_self_signed_certificate(
            tls_path, private_key, common_name="florestad", validity_days=365
        )
        self.log(f"Created self-signed certificate at {cert_path}")
        return (pk_path, cert_path)

    def is_option_set(self, extra_args: list[str], option: str) -> bool:
        """Check if an option is set in the extra arguments.

        Args:
            extra_args: List of command-line arguments
            option: Option to check for

        Returns:
            True if option is set, False otherwise
        """
        return any(arg.startswith(option) for arg in extra_args)

    def extract_port_from_args(self, extra_args: list[str], option: str) -> int:
        """Extract port number from command-line arguments.

        Args:
            extra_args: List of command-line arguments
            option: Option name to extract port from

        Returns:
            Port number or None if not found
        """
        for arg in extra_args:
            if arg.startswith(f"{option}="):
                address = arg.split("=", 1)[1]
                if ":" in address:
                    return int(address.split(":")[-1])
        return None

    def should_enable_electrum_for_utreexod(self, extra_args: list[str]) -> bool:
        """Determine if electrum should be enabled for utreexod.

        Args:
            extra_args: List of command-line arguments

        Returns:
            True if electrum should be enabled, False otherwise
        """
        electrum_disabled_options = [
            "--noelectrum",
            "--disable-electrum",
            "--electrum=false",
            "--electrum=0",
        ]
        if any(
            arg.startswith(opt)
            for arg in extra_args
            for opt in electrum_disabled_options
        ):
            return False

        electrum_listener_options = ["--electrumlisteners", "--tlselectrumlisteners"]
        return any(
            arg.startswith(opt)
            for arg in extra_args
            for opt in electrum_listener_options
        )

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def create_data_dir_for_daemon(
        self,
        data_dir_arg: str,
        default_args: list[str],
        extra_args: list[str],
        tempdir: str,
        testname: str,
    ):
        """Create data directory for a daemon.

        Args:
            data_dir_arg: Command-line argument name for data directory
            default_args: List to append default arguments to
            extra_args: Extra command-line arguments
            tempdir: Temporary directory path
            testname: Test name for directory naming
        """
        if not self.is_option_set(extra_args, data_dir_arg):
            datadir = os.path.join(tempdir, "data", testname)
            default_args.append(f"{data_dir_arg}={datadir}")
        else:
            datadir = next(
                arg.split("=", 1)[1]
                for arg in extra_args
                if arg.startswith(f"{data_dir_arg}=")
            )

        os.makedirs(datadir, exist_ok=True)

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def setup_florestad_daemon(
        self,
        targetdir: str,
        tempdir: str,
        testname: str,
        extra_args: List[str],
        tls: bool,
        port_index: int,
    ):
        """Set up a florestad daemon instance.

        Args:
            targetdir: Target directory for daemon binary
            tempdir: Temporary directory for test data
            testname: Test name for directory naming
            extra_args: Extra command-line arguments
            tls: Whether to enable TLS
            port_index: Index for port offset calculation

        Returns:
            Tuple of (daemon, ports_dict)
        """
        daemon = FlorestaDaemon()
        daemon.create(target=targetdir)
        default_args, ports = [], {}

        self.create_data_dir_for_daemon(
            "--data-dir", default_args, extra_args, tempdir, testname
        )

        if not self.is_option_set(extra_args, "--rpc-address"):
            ports["rpc"] = 18443 + port_index
            default_args.append(f"--rpc-address=127.0.0.1:{ports['rpc']}")
        else:
            ports["rpc"] = self.extract_port_from_args(extra_args, "--rpc-address")

        if not self.is_option_set(extra_args, "--electrum-address"):
            ports["electrum-server"] = 20001 + port_index
            default_args.append(
                f"--electrum-address=127.0.0.1:{ports['electrum-server']}"
            )
        else:
            ports["electrum-server"] = self.extract_port_from_args(
                extra_args, "--electrum-address"
            )

        if tls:
            key, cert = self.create_tls_key_cert()
            default_args.extend(
                [
                    "--enable-electrum-tls",
                    f"--tls-key-path={key}",
                    f"--tls-cert-path={cert}",
                ]
            )

            if not self.is_option_set(extra_args, "--electrum-address-tls"):
                ports["electrum-server-tls"] = 21001 + port_index
                default_args.append(
                    f"--electrum-address-tls=127.0.0.1:{ports['electrum-server-tls']}"
                )
            else:
                ports["electrum-server-tls"] = self.extract_port_from_args(
                    extra_args, "--electrum-address-tls"
                )

        daemon.add_daemon_settings(default_args + extra_args)
        return daemon, ports

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def setup_utreexod_daemon(
        self,
        targetdir: str,
        tempdir: str,
        testname: str,
        extra_args: List[str],
        tls: bool,
        _port_index: int,
    ):
        """Set up a utreexod daemon instance.

        Args:
            targetdir: Target directory for daemon binary
            tempdir: Temporary directory for test data
            testname: Test name for directory naming
            extra_args: Extra command-line arguments
            tls: Whether to enable TLS
            port_index: Index for port offset calculation (unused but kept for signature)

        Returns:
            Tuple of (daemon, ports_dict)
        """
        daemon = UtreexoDaemon()
        daemon.create(target=targetdir)
        default_args, ports = [], {}

        self.create_data_dir_for_daemon(
            "--datadir", default_args, extra_args, tempdir, testname
        )

        if not self.is_option_set(extra_args, "--listen"):
            ports["p2p"] = self.get_available_random_port(18000, 20000)
            default_args.append(f"--listen=127.0.0.1:{ports['p2p']}")
        else:
            ports["p2p"] = self.extract_port_from_args(extra_args, "--listen")

        if not self.is_option_set(extra_args, "--rpclisten"):
            ports["rpc"] = self.get_available_random_port(20001, 22000)
            default_args.append(f"--rpclisten=127.0.0.1:{ports['rpc']}")
        else:
            ports["rpc"] = self.extract_port_from_args(extra_args, "--rpclisten")

        electrum_enabled = self.should_enable_electrum_for_utreexod(extra_args)

        if electrum_enabled and self.is_option_set(extra_args, "--electrumlisteners"):
            ports["electrum-server"] = self.extract_port_from_args(
                extra_args, "--electrumlisteners"
            )

        if tls:
            key, cert = self.create_tls_key_cert()
            default_args.extend([f"--rpckey={key}", f"--rpccert={cert}"])

            if electrum_enabled and self.is_option_set(
                extra_args, "--tlselectrumlisteners"
            ):
                ports["electrum-server-tls"] = self.extract_port_from_args(
                    extra_args, "--tlselectrumlisteners"
                )
        else:
            default_args.append("--notls")

        daemon.add_daemon_settings(default_args + extra_args)
        return daemon, ports

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def setup_bitcoind_daemon(
        self,
        targetdir: str,
        tempdir: str,
        testname: str,
        extra_args: List[str],
        port_index: int,
    ):
        """Set up a bitcoind daemon instance.

        Args:
            targetdir: Target directory for daemon binary
            tempdir: Temporary directory for test data
            testname: Test name for directory naming
            extra_args: Extra command-line arguments
            port_index: Index for port offset calculation

        Returns:
            Tuple of (daemon, ports_dict)
        """
        daemon = BitcoinDaemon()
        daemon.create(target=targetdir)
        default_args, ports = [], {}

        self.create_data_dir_for_daemon(
            "-datadir", default_args, extra_args, tempdir, testname
        )

        if not self.is_option_set(extra_args, "-bind"):
            ports["p2p"] = 18445 + port_index
            default_args.append(f"-bind=127.0.0.1:{ports['p2p']}")
        else:
            ports["p2p"] = self.extract_port_from_args(extra_args, "-bind")

        if not self.is_option_set(extra_args, "-rpcbind"):
            ports["rpc"] = 20443 + port_index
            default_args.extend(
                ["-rpcallowip=127.0.0.1", f"-rpcbind=127.0.0.1:{ports['rpc']}"]
            )
        else:
            ports["rpc"] = self.extract_port_from_args(extra_args, "-rpcbind")

        daemon.add_daemon_settings(default_args + extra_args)
        return daemon, ports

    def add_node(
        self,
        extra_args: List[str] = None,
        variant: str = "florestad",
        tls: bool = False,
    ) -> Node:
        """Add a node to the test network.

        Args:
            extra_args: Extra command-line arguments (default: empty list)
            variant: Node type ('florestad', 'utreexod', or 'bitcoind')
            tls: Whether to enable TLS

        Returns:
            Created Node instance

        Raises:
            ValueError: If variant is unsupported
        """
        if extra_args is None:
            extra_args = []
        port_index = len(self._nodes)
        tempdir = str(self.get_integration_test_dir())
        targetdir = os.path.join(tempdir, "binaries")
        testname = self.__class__.__name__.lower()

        if variant == "florestad":
            daemon, ports = self.setup_florestad_daemon(
                targetdir, tempdir, testname, extra_args, tls, port_index
            )
            rpcserver = copy.deepcopy(florestad_rpc_server)
        elif variant == "utreexod":
            daemon, ports = self.setup_utreexod_daemon(
                targetdir, tempdir, testname, extra_args, tls, port_index
            )
            rpcserver = copy.deepcopy(utreexod_rpc_server)
        elif variant == "bitcoind":
            daemon, ports = self.setup_bitcoind_daemon(
                targetdir, tempdir, testname, extra_args, port_index
            )
            rpcserver = copy.deepcopy(bitcoind_rpc_server)
        else:
            raise ValueError(f"Unsupported variant: {variant}")

        rpcserver["ports"] = ports
        node = Node(daemon, None, rpcserver, variant)
        self._nodes.append(node)
        return node

    def get_node(self, index: int) -> Node:
        """Get a node by index.

        Args:
            index: Node index

        Returns:
            Node instance

        Raises:
            IndexError: If index is out of bounds
        """
        if index < 0 or index >= len(self._nodes):
            raise IndexError(f"Node {index} not found")
        return self._nodes[index]

    def run_node(self, node: Node, timeout: int = 180):
        """Start a node and initialize its RPC connection.

        Args:
            node: Node to run
            timeout: Connection timeout in seconds (default: 180)
        """
        node.daemon.start()

        if node.variant == "florestad":
            node.rpc = FlorestaRPC(node.daemon.process, node.rpc_config)
        elif node.variant == "utreexod":
            node.rpc = UtreexoRPC(node.daemon.process, node.rpc_config)
        elif node.variant == "bitcoind":
            node.rpc = BitcoinRPC(node.daemon.process, node.rpc_config)

        node.rpc.wait_for_connections(opened=True, timeout=timeout)
        self.log(f"Node '{node.variant}' started on ports: {node.rpc_config['ports']}")

    def stop_node(self, index: int):
        """Stop a node by index.

        Args:
            index: Node index to stop

        Returns:
            Stop response from node
        """
        return self.get_node(index).stop()

    def stop(self):
        """Stop all nodes."""
        for node in self._nodes:
            node.stop()

    def stop_all_nodes(self):
        """Stop all nodes (alias for stop method)."""
        self.stop()

    # pylint: disable=invalid-name
    def assertTrue(self, condition: bool):
        """Assert that condition is True.

        Args:
            condition: Condition to check

        Raises:
            AssertionError: If condition is False
        """
        if not condition:
            self.stop()
            raise AssertionError(f"Expected: True, Got: {condition}")

    # pylint: disable=invalid-name
    def assertFalse(self, condition: bool):
        """Assert that condition is False.

        Args:
            condition: Condition to check

        Raises:
            AssertionError: If condition is True
        """
        if condition:
            self.stop()
            raise AssertionError(f"Expected: False, Got: {condition}")

    # pylint: disable=invalid-name
    def assertIsNone(self, thing: Any):
        """Assert that thing is None.

        Args:
            thing: Object to check

        Raises:
            AssertionError: If thing is not None
        """
        if thing is not None:
            self.stop()
            raise AssertionError(f"Expected: None, Got: {thing}")

    # pylint: disable=invalid-name
    def assertIsSome(self, thing: Any):
        """Assert that thing is not None.

        Args:
            thing: Object to check

        Raises:
            AssertionError: If thing is None
        """
        if thing is None:
            self.stop()
            raise AssertionError("Expected: not None")

    # pylint: disable=invalid-name
    def assertEqual(self, condition: Any, expected: Any):
        """Assert that condition equals expected.

        Args:
            condition: Actual value
            expected: Expected value

        Raises:
            AssertionError: If values are not equal
        """
        if condition != expected:
            self.stop()
            raise AssertionError(f"Expected: {expected}, Got: {condition}")

    # pylint: disable=invalid-name
    def assertNotEqual(self, condition: Any, expected: Any):
        """Assert that condition does not equal expected.

        Args:
            condition: Actual value
            expected: Value that should not match

        Raises:
            AssertionError: If values are equal
        """
        if condition == expected:
            self.stop()
            raise AssertionError(f"Expected: not {expected}, Got: {condition}")

    # pylint: disable=invalid-name
    def assertIn(self, element: Any, container: List[Any]):
        """Assert that element is in container.

        Args:
            element: Element to find
            container: Container to search in

        Raises:
            AssertionError: If element not in container
        """
        if element not in container:
            self.stop()
            raise AssertionError(f"Expected {element} in {container}")

    # pylint: disable=invalid-name
    def assertMatch(self, actual: Any, pattern: Pattern):
        """Assert that actual matches pattern.

        Args:
            actual: String to match
            pattern: Regex pattern to match against

        Raises:
            AssertionError: If pattern doesn't match
        """
        if not re.fullmatch(pattern, actual):
            self.stop()
            raise AssertionError(f"Pattern {pattern} not matched in {actual}")

    # pylint: disable=invalid-name
    def assertRaises(self, expected_exception):
        """Context manager for asserting an exception is raised.

        Args:
            expected_exception: Exception type expected to be raised

        Returns:
            Context manager instance
        """
        return self._AssertRaisesContext(self, expected_exception)

    def cleanup(self, clean_logs=False):
        """Clean up log files and data folder before running tests.

        Args:
            clean_logs: If True, remove old logs. If False, preserve them. (default: False)
        """

        tempdir = str(self.get_integration_test_dir())

        # Clean log files only if requested
        if clean_logs:
            log_path = self.get_test_log_path()
            log_dir = os.path.dirname(log_path)

            if os.path.exists(log_dir):
                for log_file in os.listdir(log_dir):
                    if log_file.endswith(".log"):
                        log_file_path = os.path.join(log_dir, log_file)
                        os.remove(log_file_path)
                        self.log(f"Cleaned log file: {log_file_path}")

        # Always clean data folder
        data_dir = os.path.join(tempdir, "data")
        if os.path.exists(data_dir):
            shutil.rmtree(data_dir)
            self.log(f"Cleaned data directory: {data_dir}")
            # Recreate the data directory
            os.makedirs(data_dir, exist_ok=True)
