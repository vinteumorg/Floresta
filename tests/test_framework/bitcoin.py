"""
General Bitcoin-related tools for our test framework.
"""

import struct
import hashlib
from datetime import datetime, timedelta


def dsha256(data: bytes) -> bytes:
    """Double sha256 of some data"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def read_compact_size(data: bytes, offset: int) -> tuple[int, int]:
    """
    CompactSize field is a variable-length byte structure.
    The leading byte indicates the size of the field, and also
    indicates the bytes that contain the number.
    """
    prefix = data[offset]

    if prefix < 0xFC:
        return prefix, offset + 1
    if prefix == 0xFD:
        return struct.unpack_from("<H", data, offset)[0], offset + 3
    if prefix == 0xFE:
        return struct.unpack_from("<I", data, offset)[0], offset + 5
    if prefix == 0xFF:
        return struct.unpack_from("<Q", data, offset)[0], offset + 9
    raise ValueError("Invalid compact size")


def get_merkle_root(data: list[bytes]):
    """Recursivewly calculate the merkle root of a list of bytes"""
    if not data:
        raise ValueError("Cannot calculate the merkle root of an empty list")

    if len(data) == 1:
        return dsha256(data[0])

    # if the number of elements is odd, repeat the last element
    if len(data) % 2 == 1:
        data.append(data[-1])

    # get the double sha of a pair of elements
    next_merkle = [dsha256(data[i] + data[i + 1]) for i in range(0, len(data), 2)]
    return get_merkle_root(next_merkle)


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

    def __init__(self, outpoint: Outpoint, script_sig: str, sequence: int):
        self.vout = outpoint
        self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return f"{self.vout} {self.script_sig} {self.sequence}"

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        return (
            self.vout == other.vout
            and self.script_sig == other.script_sig
            and self.sequence == other.sequence
        )

    def __hash__(self):
        return hash((self.vout, self.script_sig, self.sequence))

    def to_dict(self):
        """Convert this object to dictionary"""
        return {
            "txid": self.vout.txid,
            "vout": self.vout.vout,
            "scriptSig": self.script_sig,
            "sequence": self.sequence,
        }

    @staticmethod
    def from_dict(data: dict):
        """Convert a dictionary to a TxInput object"""
        return TxInput(
            Outpoint(data["txid"], data["vout"]), data["scriptSig"], data["sequence"]
        )


class TxOutput:
    """
    A transaction output that may or not be unspent. This contains the value and the
    script_pub_key needed to spend it.
    """

    def __init__(self, value: int, script_pub_key: bytes):
        if value < 0:
            raise ValueError("Value must be positive")

        if len(script_pub_key) > 520:
            raise ValueError("ScriptPubKey is too long")

        if not isinstance(value, int) or not isinstance(script_pub_key, bytes):
            raise TypeError("Invalid type for TxOutput")

        self.value = value
        self.script_pub_key = script_pub_key

    def __repr__(self):
        return f"{self.value} {self.script_pub_key}"

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        return self.value == other.value and self.script_pub_key == other.script_pub_key

    def __hash__(self):
        return hash((self.value, self.script_pub_key))

    def to_dict(self):
        """Convert this object to a dictionary"""
        return {"value": self.value, "script_pub_key": self.script_pub_key}

    @staticmethod
    def from_dict(data: dict):
        """Convert a dictionary to a TxOutput object"""
        return TxOutput(data["value"], data["script_pub_key"])


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
        return (
            self.txid == other.txid
            and self.inputs == other.inputs
            and self.outputs == other.outputs
        )

    def __hash__(self):
        return hash((self.txid, self.inputs, self.outputs))

    def to_dict(self):
        """Convert this object to a dictionary"""
        return {
            "txid": self.txid,
            "inputs": [i.to_dict() for i in self.inputs],
            "outputs": [o.to_dict() for o in self.outputs],
        }

    def hash(self) -> str:
        """
        Hash this block header.
        """
        return dsha256(self.serialize())[::-1].hex()

    @staticmethod
    def from_dict(data: dict):
        """Convert a dictionary to a Transaction object"""
        return Transaction(
            data["txid"],
            [TxInput.from_dict(i) for i in data["inputs"]],
            [TxOutput.from_dict(o) for o in data["outputs"]],
        )

    def verify(self, utxos: dict[Outpoint, TxOutput]) -> bool:
        """
        Verify that this transaction is valid, given the UTXOs we have.
        """
        # Check that the outputs are valid
        out_ = 0
        for out in self.outputs:
            if out.value < 0:
                return False
            if out.value > 21000000 * 100000000:
                return False
            if out.value > 0 and len(out.script_pub_key) < 2:
                return False
            out_ += out.value

        # Check that the inputs and outputs balance
        in_ = 0
        for inp in self.inputs:
            if inp.vout not in utxos:
                return False
            in_ += utxos[inp.vout].value

        if in_ < out_:
            return False

        return True

    # pylint: disable=unnecessary-pass
    def sign(self, privkey: str, utxos: dict[Outpoint, TxOutput]):
        """
        Sign this transaction with the given private key.
        """
        pass

    @staticmethod
    def create_transaction(
        destinations: list[TxOutput], utxos: list[Outpoint]
    ) -> "Transaction":
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
        buffer.extend([0x01, 0x00, 0x00, 0x00])  # Version
        buffer.extend(len(self.inputs).to_bytes(1))  # Number of inputs
        for inp in self.inputs:
            buffer.extend(bytes.fromhex(inp.vout.txid)[::-1])
            buffer.extend(inp.vout.vout.to_bytes(4, "little"))
            buffer.extend([0x00])  # Script length
            buffer.extend([0xFF, 0xFF, 0xFF, 0xFF])  # Sequence
        buffer.extend(len(self.outputs).to_bytes(1))  # Number of outputs
        for out in self.outputs:
            buffer.extend(out.value.to_bytes(8, "little"))
            buffer.extend(len(out.script_pub_key).to_bytes(1))
            buffer.extend(out.script_pub_key)
        buffer.extend([0x00, 0x00, 0x00, 0x00])  # Locktime
        return buffer

    # pylint: disable=too-many-locals
    @staticmethod
    def deserialize(data: bytes) -> "Transaction":
        """
        Deserialize a rawtransaction
        """
        # byte position counter
        offset = 0

        # version
        # pylint: disable=unused-variable
        version = int.from_bytes(data[offset : offset + 4], "little")
        offset += 4

        # marker and flag
        marker_and_flag = data[offset : offset + 2]
        is_segwit = marker_and_flag == b"\x00\x01"
        marker_and_flag_offset = None
        witness_start_offset = None
        if is_segwit:
            marker_and_flag_offset = offset
            offset += 2

        # input count
        n_inputs, offset = read_compact_size(data, offset)

        # inputs
        inputs = []
        for _ in range(n_inputs):
            # txid
            prev_txid = data[offset : offset + 32][::-1].hex()
            offset += 32

            # vout
            prev_vout = int.from_bytes(data[offset : offset + 4], "little")
            offset += 4

            # script sig size, script sig
            script_len, offset = read_compact_size(data, offset)
            script_sig = data[offset : offset + script_len]
            full_script_sig = (script_len.to_bytes(1, "little") + script_sig).hex()
            offset += script_len

            # sequence
            sequence = int.from_bytes(data[offset : offset + 4], "little")
            offset += 4

            inputs.append(
                {
                    "txid": prev_txid,
                    "vout": prev_vout,
                    "scriptSig": full_script_sig,
                    "sequence": sequence,
                }
            )

        # output count
        n_outputs, offset = read_compact_size(data, offset)

        # outputs
        outputs = []
        for _ in range(n_outputs):
            # amount
            value = int.from_bytes(data[offset : offset + 8], "little")
            offset += 8

            # script pub key size, script pub key
            script_len, offset = read_compact_size(data, offset)
            script_pub_key = data[offset : offset + script_len]
            full_script_pub_key = (
                script_len.to_bytes(1, "little") + script_pub_key
            ).hex()
            offset += script_len

            outputs.append({"value": value, "scriptPubKey": full_script_pub_key})

        # witness
        witness_start_offset = offset  # save this data before parsing witness structure
        if is_segwit:
            for inp in inputs:
                # stack items
                n_witness, offset = read_compact_size(data, offset)

                # item
                witnesses = []
                for _ in range(n_witness):
                    wit_len, offset = read_compact_size(data, offset)
                    wit_data = data[offset : offset + wit_len].hex()
                    offset += wit_len
                    witnesses.append(wit_data)
                inp["witness"] = witnesses

        # locktime
        # pylint: disable=unused-argument
        locktime = int.from_bytes(data[offset : offset + 4], "little")
        offset += 4

        # get txid excluding the witness data when is a segwit one
        if (
            is_segwit
            and marker_and_flag_offset is not None
            and witness_start_offset is not None
        ):
            # exclude marker_and_flag
            data_txid = (
                data[:marker_and_flag_offset]
                + data[marker_and_flag_offset + 2 : witness_start_offset]
            )
        else:
            data_txid = data[:offset]

        return Transaction("", inputs, outputs)


class BlockHeader:
    """
    A block header, containing the hash of the previous block, the merkle root of the
    transactions, timestamp, target, and nonce.
    """

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def __init__(
        self,
        version: int,
        prev_blockhash: str,
        merkle_root: str,
        timestamp: int,
        target: int,
        nonce: int,
    ):
        self.version = version
        self.prev_blockhash = prev_blockhash
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.target = target
        self.nonce = nonce

    def __repr__(self):
        return " ".join(
            [
                f"version={self.version}",
                f"prev_block={self.prev_blockhash}",
                f"merkle_root={self.merkle_root}",
                f"time={self.timestamp}",
                f"bits={self.target}",
                f"nonce={self.nonce}",
            ]
        )

    def __str__(self):
        return self.__repr__()

    def __eq__(self, other):
        return self.hash() == other.hash()

    def __hash__(self):
        return hash(
            (
                self.prev_blockhash,
                self.merkle_root,
                self.timestamp,
                self.target,
                self.nonce,
            )
        )

    def to_dict(self):
        """Convert this object to a dictionary"""
        return {
            "prev_blockhash": self.prev_blockhash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "target": self.target,
            "nonce": self.nonce,
        }

    @staticmethod
    def from_dict(data: dict):
        """Convert a dictionary to a BlockHeader object"""
        return BlockHeader(
            data["version"],
            data["prev_blockhash"],
            data["merkle_root"],
            data["timestamp"],
            data["target"],
            data["nonce"],
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
        return BlockHeader(
            version, prev_blockhash, merkle_root, timestamp, target, nonce
        )

    def hash(self) -> str:
        """
        Hash this block header.
        """
        return (
            hashlib.sha256(hashlib.sha256(self.serialize()).digest())
            .digest()[::-1]
            .hex()
        )

    def verify(self) -> bool:
        """
        Verify that this block header is valid.
        """
        return int(self.hash(), 16) < int(
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        )

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
        return 0xFFFF * 2**208 / self.target

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
        """Convert this object to a dictionary"""
        return {
            "header": self.header.to_dict(),
            "transactions": [tx.to_dict() for tx in self.transactions],
        }

    @staticmethod
    def from_dict(data: dict):
        """Convert a dictionary to a Block object"""
        return Block(
            BlockHeader.from_dict(data["header"]),
            [Transaction.from_dict(tx) for tx in data["transactions"]],
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
        for _ in range(num_transactions):
            tx = Transaction.deserialize(data[offset:])
            transactions.append(tx)
            offset += len(tx.serialize())
        return Block(header, transactions)

    @staticmethod
    def from_transaction_list(
        previous: bytes,
        version: int,
        bits: int,
        timestamp: int,
        transactions: list[Transaction],
    ) -> "Block":
        """
        Create a block from a list of transactions.
        """
        return Block(
            BlockHeader(version, previous[::-1].hex(), "0" * 64, timestamp, bits, 0),
            transactions,
        )

    def get_merkle_root(self) -> str:
        """
        Get the merkle root of this block.
        """
        merkle = get_merkle_root([bytes.fromhex(tx.hash()) for tx in self.transactions])
        return merkle.hex()

    def verify(self) -> bool:
        """
        Verify that this block is valid.
        """
        return (
            self.header.verify() and self.get_merkle_root() == self.header.merkle_root
        )
