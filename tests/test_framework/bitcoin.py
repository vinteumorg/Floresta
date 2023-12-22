"""
    General Bitcoin-related tools for our test framework.
"""

import os
import datetime
import hashlib

from datetime import timedelta
from .secp256k1 import GE, FE

class Outpoint:
    """
        A transaction outpoint, a canonical pointer to a specific output of a specific 
        transaction in the chain. Since BIP30, outpoints are unique, so we can use them
        as a unique identifier for a UTXO.
    """
    def __init__(self, txid: str, vout: int):
        self.txid = txid
        self.vout = vout

    def __eq__(self, other):
        return self.txid == other.txid and self.vout == other.vout
    
    def __hash__(self):
        return hash((self.txid, self.vout))

    def __repr__(self):
        return f"{self.txid}:{self.vout}"

    def __str__(self):
        return self.__repr__()

class TxInput:
    """
        A transaction input.
    """
    def __init__(self, outpoint: Outpoint, scriptSig: str, sequence: int):
        self.vout = outpoint
        self.scriptSig = scriptSig
        self.sequence = sequence
    
    def __repr__(self):
        return f"{self.vout} {self.scriptSig} {self.sequence}"
    
    def __str__(self):
        return self.__repr__()
    
    def __eq__(self, other):
        return self.vout == other.vout and self.scriptSig == other.scriptSig and self.sequence == other.sequence
    
    def __hash__(self):
        return hash((self.vout, self.scriptSig, self.sequence))
    
    def to_dict(self):
        return {
            "txid": self.vout.txid,
            "vout": self.vout.vout,
            "scriptSig": self.scriptSig,
            "sequence": self.sequence
        }
    
    @staticmethod
    def from_dict(data: dict):
        return TxInput(
            Outpoint(data["txid"], data["vout"]),
            data["scriptSig"],
            data["sequence"]
        )
    

class TxOutput:
    """
        A transaction output that may or not be unspent. This contains the value and the
        scriptPubKey needed to spend it.
    """
    def __init__(self, value: int, scriptPubKey: bytes):
        if value < 0:
            raise ValueError("Value must be positive")

        if len(scriptPubKey) > 520:
            raise ValueError("ScriptPubKey is too long")

        if not type(value) is int or not type(scriptPubKey) is bytes:
            raise TypeError("Invalid type for TxOutput")

        self.value = value
        self.scriptPubKey = scriptPubKey
    
    def __repr__(self):
        return f"{self.value} {self.scriptPubKey}"
    
    def __str__(self):
        return self.__repr__()
    
    def __eq__(self, other):
        return self.value == other.value and self.scriptPubKey == other.scriptPubKey
    
    def __hash__(self):
        return hash((self.value, self.scriptPubKey))
    
    def to_dict(self):
        return {
            "value": self.value,
            "scriptPubKey": self.scriptPubKey
        }
    
    @staticmethod
    def from_dict(data: dict):
        return TxOutput(
            data["value"],
            data["scriptPubKey"]
        )

class Transaction:
    """
        A transaction, containing a list of inputs and outputs.
    """
    def __init__(self, txid: str, inputs: list[TxInput], outputs: list[TxOutput]):
        self.txid = txid
        self.inputs = inputs
        self.outputs = outputs

    def __repr__(self):
        return f"{self.txid} {self.inputs} {self.outputs}"

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        return self.txid == other.txid and self.inputs == other.inputs and self.outputs == other.outputs

    def __hash__(self):
        return hash((self.txid, self.inputs, self.outputs))

    def to_dict(self):
        return {
            "txid": self.txid,
            "inputs": [i.to_dict() for i in self.inputs],
            "outputs": [o.to_dict() for o in self.outputs]
        }

    @staticmethod
    def from_dict(data: dict):
        return Transaction(
            data["txid"],
            [TxInput.from_dict(i) for i in data["inputs"]],
            [TxOutput.from_dict(o) for o in data["outputs"]]
        )

    def verify(self, utxos: dict[Outpoint, TxOutput]) -> bool:
        """
            Verify that this transaction is valid, given the UTXOs we have.
        """
        # Check that the outputs are valid
        out = 0
        for out in self.outputs:
            if out.value < 0:
                return False
            if out.value > 21000000 * 100000000:
                return False
            if out.value > 0 and len(out.scriptPubKey) < 2:
                return False
            out += out.value

        # Check that the inputs and outputs balance
        in_ = 0
        for inp in self.inputs:
            if inp.vout not in utxos:
                return False
            in_ += utxos[inp.vout].value

        if in_ < out:
            return False

        return True

    def sign(self, privkey: str, utxos: dict[Outpoint, TxOutput]):
        """
            Sign this transaction with the given private key.
        """
        pass

    @staticmethod
    def create_transaction(destinations: list[TxOutput], utxos: dict[TxOutput]) -> "Transaction":
        """
            Create a transaction that spends the given outputs and sends them to the given
            destinations
        """
        inputs = [TxInput(outpoint, "", 0) for outpoint in utxos]
        return Transaction("", inputs, destinations)

    def serialize(self) -> bytes:
        """
            Serialize this transaction to bytes.
        """
        buffer = bytearray()
        buffer.extend([0x01, 0x00, 0x00, 0x00]) # Version
        buffer.extend(len(self.inputs).to_bytes(1)) # Number of inputs
        for inp in self.inputs:
            buffer.extend(bytes.fromhex(inp.vout.txid)[::-1])
            buffer.extend(inp.vout.vout.to_bytes(4, "little"))
            buffer.extend([0x00]) # Script length
            buffer.extend([0xff, 0xff, 0xff, 0xff]) # Sequence
        buffer.extend(len(self.outputs).to_bytes(1)) # Number of outputs
        for out in self.outputs:
            buffer.extend(out.value.to_bytes(8, "little"))
            buffer.extend(len(out.scriptPubKey).to_bytes(1))
            buffer.extend(out.scriptPubKey)
        buffer.extend([0x00, 0x00, 0x00, 0x00]) # Locktime
        return buffer

class BlockHeader:
    """
        A block header, containing the hash of the previous block, the merkle root of the
        transactions, timestamp, target, and nonce.
    """
    def __init__(self, version: int, prev_blockhash: str, merkle_root: str, timestamp: int, target: int, nonce: int):
        self.version = version
        self.prev_blockhash = prev_blockhash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.target = target
        self.nonce = nonce

    def __repr__(self):
        return f"version={self.version} prev_block={self.prev_blockhash} merkle_root={self.merkle_root} time={self.timestamp} bits={self.target} nonce={self.nonce}"

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        return self.hash() == other.hash()

    def __hash__(self):
        return hash((self.prev_blockhash, self.merkle_root, self.timestamp, self.target, self.nonce))

    def to_dict(self):
        return {
            "prev_blockhash": self.prev_blockhash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "target": self.target,
            "nonce": self.nonce
        }

    @staticmethod
    def from_dict(data: dict):
        return BlockHeader(
            data["prev_blockhash"],
            data["merkle_root"],
            data["timestamp"],
            data["target"],
            data["nonce"]
        )

    def serialize(self) -> bytes:
        """
            Serialize this block header to bytes.
        """
        buffer = bytearray()
        buffer.extend(self.version.to_bytes(4, "little"))
        buffer.extend(bytes.fromhex(self.prev_blockhash)[::-1])
        buffer.extend(bytes.fromhex(self.merkle_root)[::-1])
        buffer.extend(self.timestamp.to_bytes(4, "little"))
        buffer.extend(self.target.to_bytes(4, "little"))
        buffer.extend(self.nonce.to_bytes(4, "little"))
        return buffer

    @staticmethod
    def deserialize(data: bytes) -> "BlockHeader":
        """
            Deserialize a block header from bytes.
        """
        version = int.from_bytes(data[:4], "little")
        prev_blockhash = data[4:36][::-1].hex()
        merkle_root = data[36:68][::-1].hex()
        timestamp = int.from_bytes(data[68:72], "little")
        target = int.from_bytes(data[72:76], "little")
        nonce = int.from_bytes(data[76:80], "little")
        return BlockHeader(version, prev_blockhash, merkle_root, timestamp, target, nonce)

    def hash(self) -> str:
        """
            Hash this block header.
        """
        return hashlib.sha256(hashlib.sha256(self.serialize()).digest()).digest()[::-1].hex()

    def verify(self) -> bool:
        """
            Verify that this block header is valid.
        """
        return int(self.hash(), 16) < int(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)

    def mine(self) -> int:
        """
            Mine this block header.
        """
        nonce = 0
        while True:
            self.nonce = nonce
            if self.verify():
                return nonce
            nonce += 1

    def get_difficulty(self) -> float:
        """
            Get the difficulty of this block header.
        """
        return 0xffff * 2**208 / self.target

    def get_timestamp(self) -> datetime:
        """
            Get the timestamp of this block header.
        """
        return datetime.fromtimestamp(self.timestamp)

    def get_time_since(self) -> timedelta:
        """
            Get the time since this block header was mined.
        """
        return datetime.now() - self.get_timestamp()

class Block:
    """
        A block, containing a list of transactions.
    """
    def __init__(self, header: BlockHeader, transactions: list[Transaction]):
        self.header = header
        self.transactions = transactions

    def __repr__(self):
        return f"header={self.header} transactions={self.transactions}"

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        return self.header == other.header and self.transactions == other.transactions

    def __hash__(self):
        return self.header.hash()

    def to_dict(self):
        return {
            "header": self.header.to_dict(),
            "transactions": [tx.to_dict() for tx in self.transactions]
        }

    @staticmethod
    def from_dict(data: dict):
        return Block(
            BlockHeader.from_dict(data["header"]),
            [Transaction.from_dict(tx) for tx in data["transactions"]]
        )

    def serialize(self) -> bytes:
        """
            Serialize this block to bytes.
        """
        buffer = bytearray()
        buffer.extend(self.header.serialize())
        buffer.extend(len(self.transactions).to_bytes(1, "little"))
        for tx in self.transactions:
            buffer.extend(tx.serialize())
        return buffer

    @staticmethod
    def deserialize(data: bytes) -> "Block":
        """
            Deserialize a block from bytes.
        """
        header = BlockHeader.deserialize(data[:80])
        num_transactions = int.from_bytes(data[80:81], "little")
        transactions = []
        offset = 81
        for i in range(num_transactions):
            tx = Transaction.deserialize(data[offset:])
            transactions.append(tx)
            offset += len(tx.serialize())
        return Block(header, transactions)

    def from_transaction_list(previous: bytes, version: int, bits: int, timestamp: int, transactions: list[Transaction]) -> "Block":
        """
            Create a block from a list of transactions.
        """
        return Block(BlockHeader(version, previous, "0"*64, int(time.time()), bits, 0), transactions)

    def get_merkle_root(self) -> str:
        """
            Get the merkle root of this block.
        """
        return merkle_root([tx.hash() for tx in self.transactions])

    def verify(self) -> bool:
        """
            Verify that this block is valid.
        """
        return self.header.verify() and self.get_merkle_root() == self.header.merkle_root
