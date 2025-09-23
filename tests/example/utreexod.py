import pytest


class TestUtreexod:
    EXPECTED_CHAIN = "regtest"
    EXPECTED_BLOCKHASH = (
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    )
    EXPECTED_DIFFICULTY = 1

    @pytest.mark.utreexod
    def test_utreexod_blockchain_info(self, utreexod_node):
        utreexo_response = utreexod_node.rpc.get_blockchain_info()

        assert utreexo_response["chain"] == self.EXPECTED_CHAIN
        assert utreexo_response["bestblockhash"] == self.EXPECTED_BLOCKHASH
        assert utreexo_response["difficulty"] == self.EXPECTED_DIFFICULTY
