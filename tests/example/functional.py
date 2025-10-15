import pytest


class TestFunctional:
    EXPECTED_HEIGHT = 0
    EXPECTED_BLOCK = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    EXPECTED_DIFFICULTY = 1
    EXPECTED_LEAF_COUNT = 0

    @pytest.mark.integration
    def test_florestad_blockchain_info(self, florestad_node):
        inf_response = florestad_node.rpc.get_blockchain_info()

        assert inf_response["height"] == self.EXPECTED_HEIGHT
        assert inf_response["best_block"] == self.EXPECTED_BLOCK
        assert inf_response["difficulty"] == self.EXPECTED_DIFFICULTY
        assert inf_response["leaf_count"] == self.EXPECTED_LEAF_COUNT
