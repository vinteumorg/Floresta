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
        self.server.register_function(self.getbestblock)
        self.server.register_function(self.getblockhash)
        self.server.register_function(self.getheaders)

    def run(self):
        print("rpc running")
        self.server.serve_forever()

    def get(self, what: str, key: str | int, verbosity=bool | int) -> dict:
        fp = open(f"tests/data/rpc/{what}.json")
        data = json.load(fp)
        if verbosity == None:
            return data[key]

        if verbosity:
            return data[key]["1"]
        return data[key]["0"]

    def getblock(self, height: int, verbose: int = 0):
        return self.get("blocks", height, verbose)

    def stop(self):
        return self.server.shutdown()

    def getbestblock(self):
        fp = open("tests/data/rpc/block_index.json")
        data = json.load(fp)
        return {"height": len(data) - 1, "hash": data[-1]}

    def getblockhash(self, height: str) -> dict:
        return self.get("block_index", height, None)

    def getheaders(self, locator, verbosity) -> dict:
        fBlocks = open("tests/data/rpc/blocks.json")
        blocks_data = json.load(fBlocks)
        headers = []
        for i in blocks_data:
            headers.append(blocks_data[i]["0"][0:160])
        return headers

    def getutreexoproof(self, height: str, verbosity=None):
        return self.get("proofs", height)
