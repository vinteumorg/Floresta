"""
    Spawn a new utreexod process on background and run it on 
    regtest mode for tests. You can use it to generate blocks
    and utreexo proofs for tests.
"""

import subprocess
import time
import os
import shutil
import json
import requests

class UtreexoDaemon:
    def __init__(self, datadir: str, utreexod_path: str, rpc_port: int = 18334, p2p_port: int = 8333):
        self.datadir = datadir
        self.utreexod_path = utreexod_path
        self.rpc_port = rpc_port
        self.p2p_port = p2p_port
        self.utreexod = None
        self.utreexod_log = None

    def perform(self, command: str, args: list[str] = []):
        """
            Perform a RPC command to utreexod and return the result
        """
        url = f"http://localhost:{self.rpc_port}/"
        headers = {'content-type': 'application/json'}
        data = {
            "jsonrpc": "1.0",
            "id": "curltest",
            "method": command,
            "params": args
        }
        username = "utreexo"
        password = "utreexo"
        auth = requests.auth.HTTPBasicAuth(username, password)
        response = requests.post(url, data=json.dumps(data), headers=headers, auth=auth)
        if response.status_code != 200:
            raise Exception(f"RPC error: {response.status_code} {response.reason} {response.text}")
        return response.json()["result"]

    def start(self):
        """
            Start a new utreexod process on background and wait for it to be ready
        """
        if not os.path.isdir(self.datadir):
            os.makedirs(self.datadir)
        self.utreexod_log = open(self.datadir + "utreexod.log", "wt")
        self.utreexod = subprocess.Popen([self.utreexod_path,
                                          "--regtest",
                                          "--datadir",
                                          self.datadir,
                                          "-u",
                                          "utreexo",
                                          "-P",
                                          "utreexo",
                                          "--utreexoproofindex",
                                          "--notls"
        ], stdout=self.utreexod_log, stderr=self.utreexod_log)

        # Wait for utreexod to be ready
        timeout = 10
        while 42:
            try:
                self.perform("getblockchaininfo")
                break
            except:
                time.sleep(10)
                timeout -= 1
                if timeout == 0:
                    raise Exception("utreexod failed to start")



    def generate_blocks(self, blocks: int):
        addr = self.perform("getnewaddress")
        self.perform("generatetoaddress", [blocks, addr])

    def send_to_address(self, address: str, amount: float):
        self.perform("sendtoaddress", [address, amount])

    def get_balance(self):
        return self.perform("getbalance")

    def stop(self):
        self.perform("stop")
        self.utreexod.wait()
        self.utreexod_log.close()
        shutil.rmtree(self.datadir)
        self.utreexod = None
        self.utreexod_log = None

    def __del__(self):
        if self.utreexod:
            self.stop()

if __name__ == "__main__":
    daemon = UtreexoDaemon("./utreexo/", "/home/erik/Documents/utreexod/utreexod")
    daemon.start()
    daemon.generate_blocks(100)
    print(daemon.get_balance())
    daemon.stop()