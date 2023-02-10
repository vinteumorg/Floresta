"""
    Fake utreexod's json_rpc interface for tests that doesn't really require a actual utreexod
"""
from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer
import json


class MockUtreexod:
    def __init__(self):
        self.server = SimpleJSONRPCServer(('localhost', 8080))
        self.server.register_function(self.getblock)
        self.server.register_function(self.stop)
        self.server.register_function(self.getutreexoproof)
        self.server.register_function(self.get_best_block)
        self.server.register_function(self.get_block_hash)

        self.server.serve_forever()

    def get(self, what: str, key: str | int, verbosity=bool | int) -> dict:
        fp = open("tests/data/rpc/{}.json" % key)
        data = json.load(fp)

        if verbosity:
            return data[key]["1"]
        return data[key]["0"]

    def getblock(self, height: int, verbose: int = 0):
        return self.get("blocks", height, verbose)

    def stop(self):
        return self.server.shutdown()

    def get_best_block(self):
        fp = open("tests/data/rpc/blocks.json")
        data = json.load(fp)
        return {"height": len(data), "hash": data[-1]["1"]["hash"]}

    def get_block_hash(self, height: str) -> dict:
        return self.get("blocks", height)["hash"]

    def getutreexoproof(self, height: str):
        return self.get("proofs", height)["hash"]
