import pytest

from conftest import TEST_CHAIN, GENESIS_BLOCK_BLOCK, GENESIS_BLOCK_DIFFICULTY_FLOAT


@pytest.mark.example
def test_bitcoind(bitcoind_node):
    response = bitcoind_node.rpc.get_blockchain_info()

    assert response["chain"] == TEST_CHAIN
    assert response["bestblockhash"] == GENESIS_BLOCK_BLOCK
    assert response["difficulty"] == GENESIS_BLOCK_DIFFICULTY_FLOAT
