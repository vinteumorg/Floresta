import pytest

from conftest import (
    GENESIS_BLOCK_HEIGHT,
    GENESIS_BLOCK_BLOCK,
    GENESIS_BLOCK_DIFFICULTY_INT,
    GENESIS_BLOCK_LEAF_COUNT,
)


@pytest.mark.example
def test_functional(florestad_node):
    response = florestad_node.rpc.get_blockchain_info()

    assert response["height"] == GENESIS_BLOCK_HEIGHT
    assert response["best_block"] == GENESIS_BLOCK_BLOCK
    assert response["difficulty"] == GENESIS_BLOCK_DIFFICULTY_INT
    assert response["leaf_count"] == GENESIS_BLOCK_LEAF_COUNT
