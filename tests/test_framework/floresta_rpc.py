""" 
    A test framework for testing RPC calls to a floresta node.
"""

import os
import time
import shutil
import tempfile
import logging
import traceback
import json
import requests

class FlorestaRPC:
    """
    A class for making RPC calls to a floresta node.
    """
    def __init__(self, process, extra_args=None, rpchost='127.0.0.1', rpcport=18442, rpcuser='user', rpcpassword='password'):
        """
        Initialize a FlorestaRPC object
        """
        self.extra_args = extra_args
        self.rpchost = rpchost
        self.rpcport = rpcport
        self.rpcuser = rpcuser
        self.rpcpassword = rpcpassword
        self.process = process
        self.rpcconn = None

    def wait_for_rpc_connection(self):
        """
        Wait for the RPC connection to be established.
        """
        timeout = 10
        while True:
            try:
                self.rpcconn = self.perform_request('getblockchaininfo')
                break
            except requests.exceptions.ConnectionError:
                time.sleep(0.1)
                timeout -= 0.1
                if timeout <= 0:
                    raise Exception('Timeout waiting for RPC connection')
                continue

    def kill(self):
        """
        Kill the floresta node process.
        """
        self.process.kill()

    def wait_to_stop(self):
        """
        Wait for the floresta node process to stop.
        """
        self.process.wait()

    def perform_request(self, method, params=None):
        """
        Perform an RPC request to the floresta node.
        """
        url = 'http://%s:%d' % (self.rpchost, self.rpcport)
        headers = {'content-type': 'application/json'}
        payload = {
            'method': method,
            'params': params,
            'jsonrpc': '2.0',
            'id': '0',
        }
        response = requests.post(url, data=json.dumps(payload), headers=headers)
        return response.json()['result']

    def getblockchaininfo(self):
        """
        Get the blockchain info.
        """
        return self.perform_request('getblockchaininfo')

