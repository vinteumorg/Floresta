# `getblockheader`

If `verbosity` is 0, returns a string that is serialized, hex-encoded data for block `hash`.

If `verbosity` is 1, returns an Object with information about block `hash`.

If `verbosity` is 2, returns an Object with information about block `hash`` and information about each transaction.


## Usage

### Synopsis

```bash
floresta-cli getblock <hash> [0|1|2]
```

### Examples

```bash
floresta-cli getblock 00000000ba63ae2eeb3d2371708291b90507c3317ef957f6fcba3811cc4fe0cc
floresta-cli getblock 00000000ba63ae2eeb3d2371708291b90507c3317ef957f6fcba3811cc4fe0cc 0
floresta-cli getblock 00000000ba63ae2eeb3d2371708291b90507c3317ef957f6fcba3811cc4fe0cc 1
floresta-cli getblock 00000000ba63ae2eeb3d2371708291b90507c3317ef957f6fcba3811cc4fe0cc 2
```

## Arguments

`hex` - (string, required) The block hash

`verbosity` - (boolean, optional) 0 for hex-encoded data, 1 for a json object, and 2 for json object with transaction data

## Returns

### Ok Response

* `verbosity = 0`: (`serde_json::Value<String>`) -  A serialized hexadecimal string in the format:

```bash
<version><previousblockhash><merkleroot><time><bits><nonce>
```

* `verbosity = 1`: (`serde_json::Value<floresta_rpc::rpc_types::GetBlockResVerbose>`) with the format:

```json5
{
  "hash": "hex",                  // (string) the block hash (same as provided)
  "confirmations" : n,            // (numeric) The number of confirmations, or -1 if the block is not on the main chain
  "height" : n,                   // (numeric) The block height or index
  "version" : n,                  // (numeric) The block version
  "versionHex" : "hex",           // (string) The block version formatted in hexadecimal
  "merkleroot" : "hex",           // (string) The merkle root
  "tx": [
    "hex",                        // (string) The transaction id
    ...
  ],
  "time" : xxx,                   // (numeric) The block time expressed in UNIX epoch time
  "mediantime" : xxx,             // (numeric) The median block time expressed in UNIX epoch time
  "nonce" : n,                    // (numeric) The nonce
  "bits" : "hex",                 // (string) The bits
  "difficulty" : n,               // (numeric) The difficulty
  "chainwork" : "hex",            // (string) Expected number of hashes required to produce the current chain
  "nTx" : n,                      // (numeric) The number of transactions in the block
  "previousblockhash" : "hex",    // (string) The hash of the previous block
  "nextblockhash" : "hex"         // (string) The hash of the next block
}
```

* `verbosity = 2`: (`serde_json::Value<floresta_rpc::rpc_types::GetBlockResRedundantVerbose>`) with the format:

```json5
{             (json object)
  ...,        Same output as verbosity = 1
  "tx" : [    (json array)
    {         (json object)
      ...     The transactions in the format of the getrawtransaction RPC. Different from verbosity = 1 "tx" result
    },
    ...
  ]
}
```

### Error 

Any of the error types on `rpc_types::Error`.

## Notes

Will print the hexadecimal format unless the parameter `verbose` is specified to `true`, else will print a json string.
