"""
Pytest configuration and fixtures for node testing.

This module provides fixtures for creating and managing test nodes
(florestad, bitcoind, utreexod) in various configurations.
"""

# pylint: disable=redefined-outer-name

import os
import pytest

from test_framework import FlorestaTestFramework, Node


# defaults to import...
GENESIS_BLOCK_HEIGHT = 0
GENESIS_BLOCK_BLOCK = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
GENESIS_BLOCK_DIFFICULTY_INT = 1
GENESIS_BLOCK_DIFFICULTY_FLOAT = 4.656542373906925e-10
GENESIS_BLOCK_LEAF_COUNT = 0
TEST_CHAIN = "regtest"


@pytest.fixture(scope="session", autouse=True)
def validate_and_check_environment():
    """Validate environment and check for required binaries before running tests."""
    temp_dir = os.getenv("FLORESTA_TEMP_DIR")
    if not temp_dir:
        pytest.fail("FLORESTA_TEMP_DIR environment variable not set")

    if not os.path.exists(temp_dir):
        pytest.fail(f"FLORESTA_TEMP_DIR directory does not exist: {temp_dir}")

    # Create necessary subdirectories
    os.makedirs(os.path.join(temp_dir, "logs"), exist_ok=True)
    os.makedirs(os.path.join(temp_dir, "data"), exist_ok=True)

    # Check for required binaries
    binaries_dir = os.path.join(temp_dir, "binaries")
    binaries = {
        "florestad": os.path.join(binaries_dir, "florestad"),
        "utreexod": os.path.join(binaries_dir, "utreexod"),
        "bitcoind": os.path.join(binaries_dir, "bitcoind"),
    }

    for binary_name, binary_path in binaries.items():
        if not os.path.exists(binary_path):
            pytest.fail(f"{binary_name} binary not found at {binary_path}")


@pytest.fixture(scope="function")
def node_manager():
    """Provides a FlorestaTestFramework instance that automatically cleans up after each test"""
    manager = FlorestaTestFramework()
    yield manager
    # Cleanup happens automatically after yield
    manager.stop()


@pytest.fixture
def florestad_node(node_manager) -> Node:
    """Single `florestad` node with default configurations, started and ready for testing"""
    node = node_manager.add_node(variant="florestad")
    node_manager.run_node(node)
    return node


@pytest.fixture
def bitcoind_node(node_manager) -> Node:
    """Single `bitcoind` node with default configurations, started and ready for testing"""
    node = node_manager.add_node(variant="bitcoind")
    node_manager.run_node(node)
    return node


@pytest.fixture
def utreexod_node(node_manager) -> Node:
    """Single `utreexod` node with default configurations, started and ready for testing"""
    node = node_manager.add_node(variant="utreexod")
    node_manager.run_node(node)
    return node


@pytest.fixture
def add_node_with_tls(node_manager):
    """Creates and starts a node with TLS enabled, based on the specified variant."""

    def _create_node(variant: str) -> Node:
        node = node_manager.add_node(
            variant=variant,
            tls=True,
        )
        node_manager.run_node(node)
        return node

    return _create_node


@pytest.fixture
def add_node_with_extra_args(node_manager):
    """
    Creates and starts a node with extra command-line arguments, based on the
    specified variant.
    """

    def _create_node(variant: str, extra_args: list) -> Node:
        node = node_manager.add_node(
            variant=variant,
            extra_args=extra_args,
        )
        node_manager.run_node(node)
        return node

    return _create_node
