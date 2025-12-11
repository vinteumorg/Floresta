"""
Pytest configuration and fixtures for node testing.

This module provides fixtures for creating and managing test nodes
(florestad, bitcoind, utreexod) in various configurations.
"""

import os
import sys
from typing import Dict
import pytest

# defaults to import...
EXPECTED_HEIGHT = 0
EXPECTED_BLOCK = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
EXPECTED_DIFFICULTY_INT = 1
EXPECTED_DIFFICULTY_FLOAT = 4.656542373906925e-10
EXPECTED_LEAF_COUNT = 0
EXPECTED_CHAIN = "regtest"

# pylint: disable=redefined-outer-name  # Pytest fixtures pattern

sys.path.insert(0, os.path.dirname(__file__))
# pylint: disable=wrong-import-position,import-error
from node_manager import NodeManager, Node


# Fixture scopes:
# - "function": New instance for each test function (default)
# - "class": New instance for each test class
# - "module": New instance for each test file
# - "session": One instance for entire test session


@pytest.fixture(scope="function")
def node_manager():
    """Provides a NodeManager instance that automatically cleans up after each test"""
    manager = NodeManager()
    yield manager
    # Cleanup happens automatically after yield
    manager.cleanup()


@pytest.fixture
def florestad_node(node_manager) -> Node:
    """Single florestad node, started and ready for testing"""
    node = node_manager.create_node(variant="florestad", testname="pytest_florestad")
    node_manager.start_node(node)
    return node


@pytest.fixture
def bitcoind_node(node_manager) -> Node:
    """Single bitcoind node, started and ready for testing"""
    node = node_manager.create_node(variant="bitcoind", testname="pytest_bitcoind")
    node_manager.start_node(node)
    return node


@pytest.fixture
def utreexod_node(node_manager) -> Node:
    """Single utreexod node, started and ready for testing"""
    node = node_manager.create_node(variant="utreexod", testname="pytest_utreexod")
    node_manager.start_node(node)
    return node


@pytest.fixture
def florestad_with_tls(node_manager) -> Node:
    """Florestad node with TLS enabled"""
    node = node_manager.create_node(
        variant="florestad", tls=True, testname="pytest_florestad_tls"
    )
    node_manager.start_node(node)
    return node


@pytest.fixture
def multi_node_setup(node_manager) -> Dict[str, Node]:
    """Multi-node setup with florestad and bitcoind"""
    florestad = node_manager.create_node(
        variant="florestad", testname="pytest_multi_floresta"
    )
    bitcoind = node_manager.create_node(
        variant="bitcoind", testname="pytest_multi_bitcoin"
    )

    node_manager.start_node(florestad)
    node_manager.start_node(bitcoind)

    return {"florestad": florestad, "bitcoind": bitcoind}


@pytest.fixture
def three_node_setup(node_manager) -> Dict[str, Node]:
    """Three-node setup with all variants"""
    florestad = node_manager.create_node(
        variant="florestad", testname="pytest_three_floresta"
    )
    bitcoind = node_manager.create_node(
        variant="bitcoind", testname="pytest_three_bitcoin"
    )
    utreexod = node_manager.create_node(
        variant="utreexod", testname="pytest_three_utreexo"
    )

    node_manager.start_node(florestad)
    node_manager.start_node(bitcoind)
    node_manager.start_node(utreexod)

    return {"florestad": florestad, "bitcoind": bitcoind, "utreexod": utreexod}


# Parametrized fixtures for testing across all node types
@pytest.fixture(params=["florestad", "bitcoind", "utreexod"])
def any_node(request, node_manager) -> Node:
    """Parametrized fixture that runs test with each node type"""
    variant = request.param
    node = node_manager.create_node(variant=variant, testname=f"pytest_any_{variant}")
    node_manager.start_node(node)
    return node


@pytest.fixture(
    params=[
        {"variant": "florestad", "extra_args": []},
        {"variant": "florestad", "extra_args": ["--compact-filters"]},
        {"variant": "bitcoind", "extra_args": []},
    ]
)
def configured_node(request, node_manager) -> Node:
    """Parametrized fixture for testing different node configurations"""
    config = request.param
    node = node_manager.create_node(
        variant=config["variant"],
        extra_args=config["extra_args"],
        testname=f"pytest_configured_{config['variant']}",
    )
    node_manager.start_node(node)
    return node


# Custom node creation fixture for advanced use cases
@pytest.fixture
def node_creator(node_manager):
    """Factory fixture for creating custom nodes within tests"""
    created_nodes = []

    def _create_node(**kwargs):
        testname = kwargs.pop("testname", "pytest_factory")
        node = node_manager.create_node(testname=testname, **kwargs)
        created_nodes.append(node)
        return node

    def _start_node(node, timeout=180):
        node_manager.start_node(node, timeout)
        return node

    _create_node.start = _start_node
    return _create_node


# Environment validation fixture
@pytest.fixture(scope="session", autouse=True)
def validate_environment():
    """Automatically validates test environment before any tests run"""
    temp_dir = os.getenv("FLORESTA_TEMP_DIR")
    if not temp_dir:
        pytest.fail("FLORESTA_TEMP_DIR environment variable not set")

    if not os.path.exists(temp_dir):
        pytest.fail(f"FLORESTA_TEMP_DIR directory does not exist: {temp_dir}")

    # Create necessary subdirectories
    os.makedirs(os.path.join(temp_dir, "logs"), exist_ok=True)
    os.makedirs(os.path.join(temp_dir, "data"), exist_ok=True)


# Test markers - define custom markers for organizing tests
def pytest_configure(config):
    """Configure custom pytest markers"""
    config.addinivalue_line("markers", "slow: marks tests as slow")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "tls: marks tests that use TLS")
    config.addinivalue_line(
        "markers", "multi_node: marks tests that use multiple nodes"
    )
    config.addinivalue_line("markers", "rpc: marks tests focused on RPC calls")
    config.addinivalue_line(
        "markers", "electrum: marks tests for electrum server functionality"
    )


@pytest.fixture(autouse=True)
def skip_if_no_binaries(request):
    """Skip tests if required binaries are not available"""
    temp_dir = os.getenv("FLORESTA_TEMP_DIR")
    if not temp_dir:
        return

    binaries_dir = os.path.join(temp_dir, "binaries")
    if request.node.get_closest_marker("bitcoind"):
        bitcoind_path = os.path.join(binaries_dir, "bitcoind")
        if not os.path.exists(bitcoind_path):
            pytest.skip("bitcoind binary not found")


# Fixtures for specific test scenarios from your current tests
@pytest.fixture
def floresta_addnode_setup(node_manager) -> Dict[str, Node]:
    """Setup for addnode tests (equivalent to your AddnodeTest)"""
    florestad = node_manager.create_node(variant="florestad", testname="pytest_addnode")
    node_manager.start_node(florestad)
    return {"florestad": florestad}


@pytest.fixture
def floresta_electrum_setup(node_manager) -> Dict[str, Node]:
    """Setup for electrum tests"""
    florestad = node_manager.create_node(
        variant="florestad",
        extra_args=["--electrum-address=127.0.0.1:50001"],
        testname="pytest_electrum",
    )
    node_manager.start_node(florestad)
    return {"florestad": florestad}
