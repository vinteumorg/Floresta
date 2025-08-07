# `getblock`

Returns the block related to the given hash with 3 verbose options that give more info about the transactions from the block.

## Argument

* `hash` - (string, required) The hash of the block, a unique identifier for every block and it can be retrieved by double hashing it with sha256.

* `verbosity` - (numeric, optional, default=0) The verbosity level of the returned message.
  0 - Only the serialized block is returned.
  1 - More metadada of related info is returned including txids.
  2 - The transactions are returned together with the block.

## Returns

verbosity = 0:
```json5
"hex"    (string) A string that is serialized, hex-encoded data for block 'hash'
```

verbosity = 1:
```json5
{                                 (json object)
  "hash" : "hex",                 (string) the block hash (same as provided)
  "confirmations" : n,            (numeric) The number of confirmations, or -1 if the block is not on the main chain
  "size" : n,                     (numeric) The block size
  "strippedsize" : n,             (numeric) The block size excluding witness data
  "weight" : n,                   (numeric) The block weight as defined in BIP 141
  "height" : n,                   (numeric) The block height or index
  "version" : n,                  (numeric) The block version
  "versionHex" : "hex",           (string) The block version formatted in hexadecimal
  "merkleroot" : "hex",           (string) The merkle root
  "tx" : [                        (json array) The transaction ids
    "hex",                        (string) The transaction id
    ...
  ],
  "time" : xxx,                   (numeric) The block time expressed in UNIX epoch time
  "mediantime" : xxx,             (numeric) The median block time expressed in UNIX epoch time
  "nonce" : n,                    (numeric) The nonce
  "bits" : "hex",                 (string) nBits: compact representation of the block difficulty target
  "target" : "hex",               (string) The difficulty target
  "difficulty" : n,               (numeric) The difficulty
  "chainwork" : "hex",            (string) Expected number of hashes required to produce the chain up to this block (in hex)
  "nTx" : n,                      (numeric) The number of transactions in the block
  "previousblockhash" : "hex",    (string, optional) The hash of the previous block (if available)
  "nextblockhash" : "hex"         (string, optional) The hash of the next block (if available)
}
```
verbosity = 2:
```json5
{                   (json object)
  ...,              Same output as verbosity = 1
  "tx" : [          (json array)
    {               (json object)
      ...,          The transactions in the format of the getrawtransaction RPC. Different from verbosity = 1 "tx" result
      "fee" : n     (numeric) The transaction fee in BTC, omitted if block undo data is not available
    },
    ...
  ]
}
```

### Error Enum 

This command only have a specific error in the case the client specifies a verbosity level that isnt implemented, e.g. the number is < 0 or > 2. Other possible errors can be raised from non-specific functionalities.

Another common error that may raise is related wheter one makes a request with a given hash that doesnt belong to any block in the active network.

## Usage Examples

```bash
# 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce27f the genesis blockhash
floresta-cli getblock 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce27f 1 

floresta-cli getblock 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce27f # Defaulting the verbose to 0.

floresta-cli getblock 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce27f 2
# These above should sucessfully eval in all bitcoin networks.
```

## Notes

- You can retrieve a block hash from a height using the `getblockhash` command
- Floresta still doesnt support verbose level 3 that was added in latest versions of bitcoin core.
- Floresta doesnt store transactions and this rpc command totally relies on the network to retrieve the block. The alternative of this command that floresta should answer without asking the network is `getblockheader`.