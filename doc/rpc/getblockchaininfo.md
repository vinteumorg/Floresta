# `getblockchaininfo`

Returns an object containing various state info regarding blockchain processing.

## Returns

```json5
{                                         (json object)

  "chain" : "str",                        (string) current network name (main, test, testnet4, signet, regtest)

  "blocks" : n,                           (numeric) the height of the most-work fully-validated chain. The genesis block has height 0

  "headers" : n,                          (numeric) the current number of headers we have validated

  "bestblockhash" : "str",                (string) the hash of the currently best block

  "bits" : "hex",                         (string) nBits: compact representation of the block difficulty target

  "target" : "hex",                       (string) The difficulty target

  "difficulty" : n,                       (numeric) the current difficulty

  "time" : xxx,                           (numeric) The block time expressed in UNIX epoch time

  "mediantime" : xxx,                     (numeric) The median block time expressed in UNIX epoch time

  "verificationprogress" : n,             (numeric) estimate of verification progress [0..1]

  "initialblockdownload" : true|false,    (boolean) (debug information) estimate of whether this node is in Initial Block Download mode

  "chainwork" : "hex",                    (string) total amount of work in active chain, in hexadecimal

  "size_on_disk" : n,                     (numeric) the estimated size of the block and undo files on disk

  "pruned" : true|false,                  (boolean) if the blocks are subject to pruning. (always true, Florestad doesnt store transactions).

  "pruneheight" : n,                      (numeric) height of the last block pruned. (Florestad is always pruned so this should be equal to the tip height).

  "automatic_pruning" : true|false,       (boolean) whether automatic pruning is enabled. (always true, Florestad doesnt store transactions).

  "prune_target_size" : n,                (numeric) the target size used by pruning. (Florestad doesnt store transactions so this are equal to size_on_disk).

  "warnings" : [                          (json array) any network and blockchain warnings (run with `-deprecatedrpc=warnings` to return the latest warning as a single string)

    "str",                                (string) warning
    ...
  ]
}
```

### Error

This command can only fail if the rpc server cant comunnicate with the blockchain and the internal node. If this happens, something got really wrong.

## Usage Examples

```bash
floresta-cli getblockchaininfo
```

## Notes

- The camp `signet_challenge` is missing due to `florestad` not supporting signet yet. Soon™.
- Some camps are only present to maintain API compatibility, such as `pruned`, `pruneheight`, `automatic_pruning`, `prune_target_size` and `warnings` doesnt expose any meaningfull information.
