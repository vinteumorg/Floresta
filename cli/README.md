## Command line utility

This is a simple cli utility to interact with your node. To run it, just call
```bash
$ floresta-cli [<options>] <command>
```

Available commands:

 - [getblockchaininfo](#getblockchaininfo)
 - [getblockhash](#getblockhash)
 - [gettxout](#gettxout)
 - [gettxproof](#gettxproof)
 - [getrawtransaction](#getrawtransaction)
 - [rescan](#rescan)
 - [sendrawtransaction](#sendrawtransaction)
 - [getblockheader](#getblockheader)
 - [loaddescriptor](#loaddescriptor)
 - [getroots](#getroots)

### getblockchaininfo

This command takes no params and returns some useful data about the current active network

**Args**: None

**Return**
```json
{
    "best_block": "A hash of the latest block we know about",
    "height": "The position of our current best known block",
    "ibd": "Whether we are on Initial Block Download"
}
```

### getblockhash

Returns the block hash associated with a given height
**Args**
```
height: A numerical identifier for a block
```
**Return**
```
block_hash: A string containing a hex-encoded block hash
```

### gettxout

Returns a cached transaction output. The output itself doesn't have to be ours. But the transaction containing it should be cached by our internal wallet.
**Args**
```
tx_id: A transaction id
vout: A index for the desired output
```
**Returns**
```json
{
    "value": "The amount of satoshis in this output",
    "spk": "The redeem script for this output"
}
```

### getrawtransaction

Returns a cached transaction associated data.

**Args**
```
    tx_id: The id of a transaction currently cached
```
**Returns**
```json
{
    "tx": "A object describing a transaction"
}
```

### rescan

Tells our node to rescan blocks. This will make our node download all blocks all over again, which may be network intensive.
This rpc is useful if you add another address, descriptor or xpub to our wallet, and you know it have historical transactions that are not indexed yet.

**Args**
```
height: The height we should start
```
**Return**
```
success: Whether we successfully started rescanning
```

### sendrawtransaction

Submits a transaction to the network

**Args**
```
tx_hex: A hex-encoded transaction
```
**Return**
```
tx_id: The transaction id if we succeed
```

### getblockheader

Returns the header of a block, giving its hash

**Args**
```
block_hash: The id of a block
```
**Return**:
```json
{
    "block_header": {
        "bits": "A compact representation of the block target",
        "merkle_root": "The root of a tree formed by all transactions in this block",
        "nonce": "The nonce used to mine this block",
        "prev_blockhash": "The hash of this block's ancestor",
        "time": "The time in which this block was created",
        "version": "This block's version"
    }
}
```
### loaddescriptor

Tells our wallet to follow this new descriptor. Optionally, whether we should rescan the blockchain if there's any historical transaction associated with this descriptor.

**Args**
```
descriptor: A output descriptor
```
**Return**
```
status: Whether we succeed loading this descriptor
```
### getroots

Returns the roots of our current forest state

**Args**: None
**Return**
```
roots: A vec of hashes
```
