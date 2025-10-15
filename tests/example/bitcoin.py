import pytest
from node_manager import Node


class TestBitcoind:
    EXPECTED_CHAIN = "regtest"
    EXPECTED_BLOCKHASH = (
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    )
    EXPECTED_DIFFICULTY = 1

    @pytest.mark.bitcoind
    def test_bitcoind_blockchain_info(self, bitcoind_node):
        response = bitcoind_node.rpc.get_blockchain_info()
        assert response["chain"] == self.EXPECTED_CHAIN
        assert response["bestblockhash"] == self.EXPECTED_BLOCKHASH
        assert response["difficulty"] > 0
