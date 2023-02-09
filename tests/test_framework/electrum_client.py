"""
    A small Electrum client that should be used to test our Electrum functionality.
    This should be conformant to the ElectrumX specs.
    More here: https://electrumx.readthedocs.io/en/latest/protocol-methods.html#blockchain-relayfee
"""
import socket
import json


class Server:
    def __init__(self, host, port=8080):
        self.conn = s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))

    def _request(self, method, params):
        request = json.dumps(
            {"jsonrpc": "2.0", "id": 0, "method": method, "params": params})
        self.conn.send(str.encode(request + "\n"))
        buff: bytes = ""
        while 42:
            # FIXME: Inefficient reading
            c = self.conn.recv(1)
            if c == b'\n':
                break
            buff += c.decode("utf-8")

        return str.encode(buff)


class ElectrumClient:
    def __init__(self, host, port):
        self.con = Server(host, port)

    def block_header(self, block_hash: str):
        """
            Return the hash of a block, givin it's hash.
        """
        return self.con._request("blockchain.block.header", [block_hash])

    def get_headers(self, start_height: int, stop_height: int):
        """
            Returns all headers in the best known tip.
        """
        return self.con._request("blockchain.block.headers", [start_height, stop_height])

    def estimate_fee(self, target: int):
        """
            Return an estimation of fees to get your transaction confirmed in `target` blocks.
        """
        return self.con._request("blockchain.estimatefee", [target])

    def headers_subscribe(self, script_hash: str):
        """
            Subscribe for receiving new headers as blocks are mined.
        """
        return self.con._request("blockchain.headers.subscribe", [script_hash])

    def relay_fee(self):
        """
            Return the minimum fee a low-priority transaction must pay in order to be
            accepted to the daemon's memory pool.
        """
        return self.con._request("blockchain.relayfee")

    def get_balance(self, script_hash):
        """
            Return the confirmed and unconfirmed balances of a script hash.
        """
        return self.con._request("blockchain.scripthash.get_balance", [script_hash])

    def get_history(self, script_hash: str):
        """
            Return the confirmed and unconfirmed history of a script hash.
        """
        return self.con._request("blockchain.scripthash.get_history", [script_hash])

    def get_mempool(self, script_hash: str):
        """
            Return the unconfirmed transactions of a script hash.
        """
        return self.con._request("blockchain.scripthash.get_mempool", [script_hash])

    def list_unspent(self, script_hash: str):
        """
            Return an ordered list of UTXOs sent to a script hash.
        """
        return self.con._request("blockchain.scripthash.listunspent", [script_hash])

    def subscribe(self, script_hash: str):
        """
            Subscribe to a script hash to receive new transactions as notification.
        """
        return self.con._request("blockchain.scripthash.subscribe", [script_hash])

    def unsubscribe(self, script_hash: str):
        """
            Unsubscribe from a script hash, preventing future notifications if its status changes.
        """
        return self.con._request("blockchain.scripthash.unsubscribe", [script_hash])

    def broadcast(self, tx: str):
        """
            Broadcast a transaction to the network.
        """
        return self.con._request("blockchain.transaction.broadcast", [tx])

    def get_transaction(self, tx_id: str):
        """
            Return a raw transaction.
        """
        return self.con._request("blockchain.transaction.get", [tx_id])

    def get_merkle(self, tx_id: str, height: int):
        """
            Return the merkle branch to a confirmed transaction given its hash and height.
        """
        return self.con._request("blockchain.transaction.get_merkle", [tx_id, height])

    # blockchain.transaction.get_tsc_merkle not really useful

    def tx_id_from_pos(self, height: int, pos: int, merkle=True):
        """
            Return a transaction hash and optionally a merkle proof, given a block height
            and a position in the block.
        """
        return self.con._request("blockchain.transaction.id_from_pos", [height, pos, merkle])

    def get_fee_histogram(self) -> str:
        """
            Return a histogram of the fee rates paid by transactions in the memory pool,
            weighted by transaction size.
        """
        return self.con._request("mempool.get_fee_histogram", [])

    def add_peer(self, features: str) -> str:
        """
            A newly-started server uses this call to get itself into other servers'
            peers lists. It should not be used by wallet clients.
        """
        return self.con._request("server.add_peer", [features])

    def add_peer(self, features: str) -> str:
        """
            Return a banner to be shown in the Electrum console.
        """
        return self.con._request("server.banner", [])

    def get_donation_address(self) -> str:
        """
            Return a server donation address.
        """
        return self.con._request("server.donation_address", [])

    def get_server_features(self) -> str:
        """
            Return a list of features and services supported by the server.
        """
        return self.con._request("server.features", [])

    def peers_subscribe(self) -> str:
        """
            Return a list of peer servers. Despite the name this is not a subscription
            and the server must send no notifications.
        """
        return self.con._request("server.peers.subscribe", [])

    def ping(self) -> str:
        """
            Ping the server to ensure it is responding, and to keep the session alive.
            The server may disconnect clients that have sent no requests for roughly 10
            minutes.
        """
        return self.con._request("server.ping", [])

    def get_version(self) -> str:
        """
            Identify the client to the server and negotiate the protocol version.
            Only the first server.version() message is accepted.
        """
        return self.con._request("server.version", [])
