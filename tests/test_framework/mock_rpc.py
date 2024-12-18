"""
mock_rpc.py

This class mock a Utreexod daemon as a SimpleJSONRPCServer. Instead to perform a real request
to a real Utreexod daemon, it search for a key/value in a JSON file located at `tests/data/rpc`.

Available methods:

| method          | comment                                                  |
|-----------------|----------------------------------------------------------|
| run             | start the SimpleJSONRPCServer                            |
| stop            | stop the SimpleJSONRPCServer                             |
| get             | General method for 'get_block' and 'get_blockhash' below |
| getblock        | mock 'getblock' command                                  |
| getbestblock    | mock 'getbestblock' command                              |
| getblockhash    | mock 'getblockhash' command                              |
| getheaders      | mock 'getheaders' command                                |
| getutreexoproof | mock 'getutreexoproof'                                   |
"""

import os
import json
from jsonrpclib.SimpleJSONRPCServer import SimpleJSONRPCServer

dirname = os.path.dirname(__file__)
DATA_DIR = os.path.normpath(os.path.abspath(os.path.join(dirname, "..", "data", "rpc")))


class MockUtreexod:
    """
    Fake utreexod's json_rpc interface for tests that doesn't really require a actual utreexod
    """

    def __init__(self):
        self.server = SimpleJSONRPCServer(("localhost", 8080))
        self.server.register_function(self.getblock)
        self.server.register_function(self.stop)
        self.server.register_function(self.getutreexoproof)
        self.server.register_function(self.getbestblock)
        self.server.register_function(self.getblockhash)
        self.server.register_function(self.getheaders)

    def run(self):
        """Start the mocked Utreexod server"""
        print("[ MockUtreexod ] [ INFO ]: rpc running")
        self.server.serve_forever()

    def stop(self):
        """Stop the mocked Utreexod server"""
        print("[ MockUtreexod ] [ INFO ]: rpc shutdown...")
        return self.server.shutdown()

    def get(self, what: str, key: str | int, verbosity: None | bool | int) -> dict:
        """
        General method for 'get_block' and 'get_blockhash'

        If `verbosity` isnt provided, it will return an raw data togheter with its parsed data;
        If `verbosity` is `0` or `False`, it will return only the raw data;
        if `verbosity` is `1` or `True`, it will return only the parsed data
        """
        filename = os.path.normpath(os.path.join(DATA_DIR, f"{what}.json"))
        with open(filename, "r", encoding="utf-8") as fp:
            data = json.load(fp)
            if verbosity is None:
                return data[key]

            if verbosity:
                return data[key]["1"]

            return data[key]["0"]

    def getblock(self, height: int, verbose: int = 0):
        """
        Mock 'getblock' request by returning
        the given 'height' at test/data/rpc/blocks.json file
        """
        return self.get("blocks", height, verbose)

    def getbestblock(self):
        """
        Mock 'getbestblock' request by returning
        the given length of blocks and the last element of blocks
        at test/data/rpc/blocks_index.json file
        """
        filename = os.path.normpath(os.path.join(DATA_DIR, "block_index.json"))
        with open(filename, "r", encoding="utf-8") as fp:
            data = json.load(fp)
            return {"height": len(data) - 1, "hash": data[-1]}

    def getblockhash(self, height: str) -> dict:
        """
        Mock 'getblockhash' request by returning
        the given 'height' at test/data/rpc/blocks_index.json file
        """
        return self.get("block_index", height, None)

    def getheaders(self) -> list[dict]:
        """
        Mock 'getheaders' request by returning
        a list of extracted headers (the first 160 characters) of raw data (key "0")
        at test/data/rpc/blocks_index.json file
        """
        filename = os.path.normpath(os.path.join(DATA_DIR, "blocks.json"))
        with open(filename, "r", encoding="utf-8") as f_blocks:
            blocks_data = json.load(f_blocks)
            headers = []
            for i in blocks_data:
                headers.append(blocks_data[i]["0"][0:160])
            return headers

    def getutreexoproof(self, height: str, verbosity=None):
        """
        Mock 'getutxoproofs' request by returning
        the given 'height' of a proof
        at test/data/rpc/proof.json file
        """
        return self.get("proofs", height, verbosity)
