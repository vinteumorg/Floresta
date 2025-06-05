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
 - [gettransaction](#gettransaction)
 - [rescan](#rescan)
 - [sendrawtransaction](#sendrawtransaction)
 - [getblockheader](#getblockheader)
 - [loaddescriptor](#loaddescriptor)
 - [getroots](#getroots)
 - [stop](#stop)
 - [addnode](#addnode)
 - [ping](#ping)

## getblockchaininfo

This command takes no params and returns some useful data about the current active network

**Args**: None

**Return**

`best_block`: The best block we have headers for

`chain`: The name of the current active network(eg: bitcoin, testnet, regtest)

`difficulty`: Current network difficulty

`height`: The height of the best block we have headers for

`ibd`: Whether we are currently in initial block download

`latest_block_time`: The time in which the latest block was mined

`latest_work`: The work of the latest block (e.g the amount of hashes needed to mine it, on average)

`leaf_count`: The amount of leaves in our current forest state

`progress`: The percentage of blocks we have validated so far

`root_count`: The amount of roots in our current forest state

`root_hashes`: The hashes of the roots in our current forest state

`validated`: The amount of blocks we have validated so far

`verification_progress`: The percentage of blocks we have verified so far

## getblockhash

Returns the block hash associated with a given height

**Args**

`height`: A numerical identifier for a block

**Return**

`block_hash`: A string containing a hex-encoded block hash


## gettxout

Returns a cached transaction output. The output itself doesn't have to be ours. But the transaction containing it should be cached by our internal wallet.

**Args**

`tx_id`: A transaction id

`vout`: A index for the desired output

**Returns**

`value`: The amount of satoshis in this output

`spk`: The redeem script for this output

## gettransaction

Returns a transaction data, given its id. The transaction itself doesn't have to be ours. But it should be cached by our internal wallet or in the mempool.

**Args**

`tx_id`: The id of a transaction

**Returns**

`blockhash`: The hash of the block containing this transaction, if it is in a block

`blocktime`: Time when the block containing this transaction was mined, if it is in a block

`confirmations`: The amount of confirmations this transaction has, if it is in a block

`hash`: The hash of this transaction, a.k.a wtxid

`hex`: The hex-encoded transaction

`in_active_chain`: Whether this transaction is in the active chain

`locktime`: The locktime value of this transaction.

`size`: The size of this transaction in bytes.

`time`: The time when this transaction was mined, if it is in a block

`txid`: The id of this transaction. Only for witness transactions, this is `different` from the wtxid

`version`: The version of this transaction

`vin`: A vector of inputs

  `script_sig`: The script signature for this input
  
  `asm`: The disassembled script signature
    
  `hex`: Raw hex-encoded script signature
  
  `sequence`: The nSequence value for this input
  
  `txid`: The id of the transaction containing the output we are spending
  
  `vout`: The index of the output we are spending
  
  `witness`: A vector of witness data

`vout`: A vector of outputs

  `n`: The index of this output
  
  `script_pub_key`: The script pubkey for this output
  
  `address`: The address this output pays to, if it's a standard output
    
  `asm`: The disassembled script pubkey
    
  `hex`: Raw hex-encoded script pubkey
    
  `req_sigs`: The amount of signatures required to spend this output (Deprecated)
    
  `type`: The type of this output (e.g pubkeyhash, scripthash, etc)
    
  `value`: The amount of satoshis in this output

`vsize`: The size of this transaction, in virtual bytes

`weight`: The weight of this transaction

## rescan

Tells our node to rescan blocks. This rpc will only work if the node is not in IBD and it was started with the `--cfilters` flag.
This will rescan for all scripts in our internal wallet within the range of blocks you've downloaded filters for (which can be set
with the `--filters-start-height` flag). If we don't see any error in early stages, the rescan will continue in the background, and
you'll get a `true` as a response. Once the process is finished, you'll see a log message in the node's log saying that the rescan is done.

**Args**: None

**Return**

`success`: Whether we successfully started rescanning

## sendrawtransaction

Submits a transaction to the network. This will broadcast the transaction to our peers, and if it's valid, it will be included in a block.

**Args**

`tx_hex`: A hex-encoded transaction

**Return**

`tx_id`: The transaction id if we succeed

## getblockheader

Returns the header of a block, giving its hash

**Args**

`block_hash`: The id of a block

**Return**:

`bits`: A compact representation of the block target

`merkle_root`: The root of a tree formed by all transactions in this block

`nonce`: The nonce used to mine this block

`prev_blockhash`: The hash of this block's ancestor

`time`: The time in which this block was created

`version`: This block's version

## loaddescriptor

Tells our wallet to follow this new descriptor. This method will also make our wallet rescan the blockchain for transactions that match this descriptor. Due to that, you can only use this method when the node is not in IBD and if it was started with the `--cfilters` flag.

**Args**

`descriptor`: An output descriptor

**Return**

`status`: Whether we succeed loading this descriptor

## getroots

Returns the roots of our current forest state

**Args**: None

**Return**

`roots`: A vec of hashes

## getblock

Returns a full block, given its hash. Notice that this rpc will cause a actual network request to our node, so it may be slow, and if used too often, may cause more network usage. The returns for this rpc are identical to bitcoin core's `getblock` rpc as of version 27.0

**Args**

`block_hash`: The hash of the block you need to get

**Return**

`block_hash`: The hash of a block

`bits`: A compact representation of the block target

`chainwork`: The combined work of all blocks in this blockchain

`confirmations`: The amount of confirmations this block has

`difficulty`: This block's difficulty

`hash`: This block's hash

`height`: This block's height

`mediantime`: The median of the timestamps of the last 11 blocks

`merkleroot`: The root of a tree formed by all transactions in this block

`n_tx`: The amount of transactions in this block

`nextblockhash`": The hash of the next block, if any

`nonce`: The nonce used to mine this block

`previousblockhash`": The hash of this block's ancestor

`size`: The size of this block in bytes

`strippedsize`: The size of this block in bytes, excluding witness data

`time`: The time in which this block was created

`tx`: A txid vector of transactions in this block

`version`: This block's version

`versionHex`: This block's version, in hex

`weight`: The weight of this block

## getpeerinfo

Returns a list of peers connected to our node, and some useful information about them.

**Args**: None

**Returns**

`peers`: A vector of peers connected to our node

  `address`: This peer's network address

  `services`: The services this peer announces as supported

  `user_agent`: A string representing this peer's software

## stop

Gracefully stops the node

**Args**: None

**Return**

`success`: Whether we successfully stopped the node

## addnode

Adds a new node to our list of peers. This will make our node try to connect to this peer.

**Args**

`node`: A network address with the format `ip[:port]`

**Return**

`success`: Whether we successfully added this node to our list of peers

## ping

Sends a ping message to all our peers, to check if they are still alive.

**Args**: None
**Return**: `null`
