"""Node management utilities for integration tests.

This module provides classes for managing daemon nodes (Bitcoin, Floresta, Utreexo)
in integration test environments, including node creation, configuration, and lifecycle management.
"""

# I disable the following because i literally will delete this file too later its a middle way to the __init__.py from test framework for the pytest
# pylint: disable=all


import contextlib
import copy
import os
from utilities import (
    create_tls_key_cert,
    is_option_set,
    extract_port_from_args,
    get_integration_test_dir,
    should_enable_electrum_for_utreexod,
)
import random
import signal
import socket
from datetime import datetime, timezone
from typing import Dict, List, Optional
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
    """Represents a daemon node with its RPC interface and configuration.

    Attributes:
        daemon: The daemon process wrapper.
        rpc: The RPC client interface.
        rpc_config: Dictionary containing RPC configuration including host and ports.
        variant: String identifier for the node type ('florestad', 'utreexod', 'bitcoind').
    """

    def __init__(self, daemon, rpc, rpc_config, variant):
        """Initialize a Node instance.

        Args:
            daemon: Daemon process wrapper object.
            rpc: RPC client object for communication.
            rpc_config: Dictionary with RPC configuration.
            variant: String identifying the node type.
        """
        self.daemon = daemon
        self.rpc = rpc
        self.rpc_config = rpc_config
        self.variant = variant

    def start(self):
        """Start the daemon node and wait for RPC connections."""
        if self.daemon.is_running:
            raise RuntimeError(f"Node '{self.variant}' is already running.")
        self.daemon.start()
        self.rpc.wait_for_connections(opened=True)

    def stop(self):
        """Stop the daemon node gracefully.

        Returns:
            Response from the stop RPC call, or None if daemon wasn't running.
        """
        if self.daemon.is_running:
            response = self.rpc.stop()
            self.rpc.wait_for_connections(opened=False)
            self.daemon.process.wait()
            return response
        return None

    def get_host(self) -> str:
        """Get the RPC host address.

        Returns:
            Host address as a string.
        """
        return self.rpc_config["host"]

    def get_ports(self) -> Dict[str, int]:
        """Get all configured ports for this node.

        Returns:
            Dictionary mapping port type names to port numbers.
        """
        return self.rpc_config["ports"]

    def get_port(self, port_type: str) -> int:
        """Get a specific port number by type.

        Args:
            port_type: The type of port to retrieve (e.g., 'rpc', 'p2p').

        Returns:
            The port number.

        Raises:
            ValueError: If the port type is not found in configuration.
        """
        if port_type not in self.rpc_config["ports"]:
            raise ValueError(
                f"Port type '{port_type}' not found in node ports: {self.rpc_config['ports']}"
            )
        return self.rpc_config["ports"][port_type]

    def force_kill(self, sigcode="SIGTERM"):
        """Forcefully terminate the daemon process,
        This should only be used as a last resort when graceful
        shutdown via RPC has failed.
        Args:
            sigcode: Signal name as string (default: 'SIGTERM').
        """
        with contextlib.suppress(ProcessLookupError):
            pid = self.daemon.process.pid
            os.kill(pid, getattr(signal, sigcode, signal.SIGTERM))


class NodeManager:
    """Manages the creation and lifecycle of test daemon nodes.

    This class handles node creation, configuration, startup, and cleanup
    for integration testing environments.
    """

    def __init__(self):
        """Initialize the NodeManager."""
        self._nodes = []
        self._temp_dir = get_integration_test_dir()
        self._port_counter = 0

    def log(self, msg: str):
        """Log a message with timestamp.

        Args:
            msg: Message to log.
        """
        now = datetime.now(timezone.utc).replace(microsecond=0)
        print(f"[NodeManager {now:%Y-%m-%d %H:%M:%S}] {msg}")

    @staticmethod
    def get_available_random_port(start: int, end: int = 65535):
        """Find an available port in the specified range.

        Args:
            start: Starting port number.
            end: Ending port number (default: 65535).

        Returns:
            An available port number.
        """
        while True:
            port = random.randint(start, end)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                if sock.connect_ex(("127.0.0.1", port)) != 0:
                    return port

    def create_data_dir_for_daemon(
        self,
        data_dir_arg: str,
        default_args: list[str],
        extra_args: list[str],
        testname: str,
        variant: str,  # Add this to create meaningful names
    ):
        if not is_option_set(extra_args, data_dir_arg):
            tempdir = get_integration_test_dir()  # Call directly instead of passing
            datadir = os.path.join(tempdir, "data", f"{testname}-{variant}")
            default_args.append(f"{data_dir_arg}={datadir}")
        else:
            datadir = next(
                arg.split("=", 1)[1]
                for arg in extra_args
                if arg.startswith(f"{data_dir_arg}=")
            )

        os.makedirs(datadir, exist_ok=True)

    def setup_florestad_daemon(
        self,
        targetdir: str,
        tempdir: str,
        testname: str,
        extra_args: List[str],
        tls: bool,
        port_index: int,
    ):
        """Set up a Floresta daemon with configuration.

        Args:
            targetdir: Directory containing daemon binaries.
            tempdir: Temporary directory for test data.
            testname: Name of the test.
            extra_args: Additional command-line arguments.
            tls: Whether to enable TLS.
            port_index: Index for port number calculation.

        Returns:
            Tuple of (daemon, ports_dict).
        """
        daemon = FlorestaDaemon()
        daemon.create(target=targetdir)
        default_args, ports = [], {}

        self.create_data_dir_for_daemon(
            "--data-dir", default_args, extra_args, tempdir, testname
        )

        if not is_option_set(extra_args, "--rpc-address"):
            ports["rpc"] = 18443 + port_index
            default_args.append(f"--rpc-address=127.0.0.1:{ports['rpc']}")
        else:
            ports["rpc"] = extract_port_from_args(extra_args, "--rpc-address")

        if not is_option_set(extra_args, "--electrum-address"):
            ports["electrum-server"] = 20001 + port_index
            default_args.append(
                f"--electrum-address=127.0.0.1:{ports['electrum-server']}"
            )
        else:
            ports["electrum-server"] = extract_port_from_args(
                extra_args, "--electrum-address"
            )

        if tls:
            key, cert = create_tls_key_cert(self)
            default_args.extend(
                [
                    "--enable-electrum-tls",
                    f"--tls-key-path={key}",
                    f"--tls-cert-path={cert}",
                ]
            )

            if not is_option_set(extra_args, "--electrum-address-tls"):
                ports["electrum-server-tls"] = 21001 + port_index
                default_args.append(
                    f"--electrum-address-tls=127.0.0.1:{ports['electrum-server-tls']}"
                )
            else:
                ports["electrum-server-tls"] = extract_port_from_args(
                    extra_args, "--electrum-address-tls"
                )

        daemon.add_daemon_settings(default_args + extra_args)
        return daemon, ports

    def setup_utreexod_daemon(
        self,
        targetdir: str,
        tempdir: str,
        testname: str,
        extra_args: List[str],
        tls: bool,
        _port_index: int,
    ):
        """Set up a Utreexo daemon with configuration.

        Args:
            targetdir: Directory containing daemon binaries.
            tempdir: Temporary directory for test data.
            testname: Name of the test.
            extra_args: Additional command-line arguments.
            tls: Whether to enable TLS.
            port_index: Unused, kept for interface consistency.

        Returns:
            Tuple of (daemon, ports_dict).
        """
        daemon = UtreexoDaemon()
        daemon.create(target=targetdir)
        default_args, ports = [], {}
        """
        Create and configure the data directory for a daemon.

        Allows you to choose meaningful names for the data directory, such as 'getblockchaininfo-bitcoin' or 'ping-floresta', making it easier to identify the purpose of each test by its directory name.

        Args:
            data_dir_arg: Argument name for the data directory option.
            default_args: List of default arguments for the daemon.
            extra_args: List of extra arguments provided by the user.
            testname: Name of the test, can be used for meaningful directory names.
            variant: Daemon variant (e.g., 'bitcoin', 'floresta'), also useful for descriptive names.
        """
        self.create_data_dir_for_daemon(
            "--datadir", default_args, extra_args, tempdir, testname
        )

        if not is_option_set(extra_args, "--listen"):
            ports["p2p"] = self.get_available_random_port(18000, 20000)
            default_args.append(f"--listen=127.0.0.1:{ports['p2p']}")
        else:
            ports["p2p"] = extract_port_from_args(extra_args, "--listen")

        if not is_option_set(extra_args, "--rpclisten"):
            ports["rpc"] = self.get_available_random_port(20001, 22000)
            default_args.append(f"--rpclisten=127.0.0.1:{ports['rpc']}")
        else:
            ports["rpc"] = extract_port_from_args(extra_args, "--rpclisten")

        electrum_enabled = should_enable_electrum_for_utreexod(extra_args)

        if electrum_enabled and is_option_set(extra_args, "--electrumlisteners"):
            ports["electrum-server"] = extract_port_from_args(
                extra_args, "--electrumlisteners"
            )

        if tls:
            key, cert = create_tls_key_cert(self)
            default_args.extend([f"--rpckey={key}", f"--rpccert={cert}"])

            if electrum_enabled and is_option_set(extra_args, "--tlselectrumlisteners"):
                ports["electrum-server-tls"] = extract_port_from_args(
                    extra_args, "--tlselectrumlisteners"
                )
        else:
            default_args.append("--notls")

        daemon.add_daemon_settings(default_args + extra_args)
        return daemon, ports

    def setup_bitcoind_daemon(
        self,
        targetdir: str,
        tempdir: str,
        testname: str,
        extra_args: List[str],
        port_index: int,
    ):
        """Set up a Bitcoin Core daemon with configuration.

        Args:
            targetdir: Directory containing daemon binaries.
            tempdir: Temporary directory for test data.
            testname: Name of the test.
            extra_args: Additional command-line arguments.
            port_index: Index for port number calculation.

        Returns:
            Tuple of (daemon, ports_dict).
        """
        daemon = BitcoinDaemon()
        daemon.create(target=targetdir)
        default_args, ports = [], {}

        self.create_data_dir_for_daemon(
            "-datadir", default_args, extra_args, tempdir, testname
        )

        if not is_option_set(extra_args, "-bind"):
            ports["p2p"] = 18445 + port_index
            default_args.append(f"-bind=127.0.0.1:{ports['p2p']}")
        else:
            ports["p2p"] = extract_port_from_args(extra_args, "-bind")

        if not is_option_set(extra_args, "-rpcbind"):
            ports["rpc"] = 20443 + port_index
            default_args.extend(
                ["-rpcallowip=127.0.0.1", f"-rpcbind=127.0.0.1:{ports['rpc']}"]
            )
        else:
            ports["rpc"] = extract_port_from_args(extra_args, "-rpcbind")

        daemon.add_daemon_settings(default_args + extra_args)
        return daemon, ports

    def create_node(
        self,
        extra_args: Optional[List[str]] = None,
        variant: str = "florestad",
        tls: bool = False,
        testname: str = "pytest",
    ) -> Node:
        """Create a new daemon node.

        Args:
            extra_args: Additional command-line arguments (default: None).
            variant: Type of node to create: 'florestad', 'utreexod', or 'bitcoind'.
            tls: Whether to enable TLS (default: False).
            testname: Name of the test (default: 'pytest').

        Returns:
            Configured Node instance.

        Raises:
            ValueError: If an unsupported variant is specified.
        """
        if extra_args is None:
            extra_args = []

        port_index = self._port_counter
        self._port_counter += 1

        tempdir = self._temp_dir
        targetdir = os.path.join(tempdir, "binaries")

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

    def start_node(self, node: Node, timeout: int = 180):
        """Start a daemon node and initialize its RPC interface.

        Args:
            node: The Node instance to start.
            timeout: Connection timeout in seconds (default: 180).
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

    def stop_all_nodes(self):
        """Stop all managed nodes gracefully, with force kill as fallback."""
        for node in self._nodes:
            try:
                node.stop()
            except Exception as exc:
                self.log(f"Error stopping node {node.variant}: {exc}")
                # Try force kill
                try:
                    node.force_kill("SIGKILL")
                except Exception:
                    pass
        self._nodes.clear()

    def cleanup(self):
        """Clean up all resources and reset the manager state."""
        self.stop_all_nodes()
        self._port_counter = 0
