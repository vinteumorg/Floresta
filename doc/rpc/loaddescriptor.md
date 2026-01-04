# `loaddescriptor`

Loads a descriptor into Floresta, derives its address(es), caches the derived addresses, and monitors them for transactions. The descriptor is persisted in the database.

## Usage

### Synopsis

```bash
floresta-cli loaddescriptor <descriptor>
```

### Examples

```bash
floresta-cli loaddescriptor "wpkh(tpubDDtyive2LqLWKzPZ8LZ9Ebi1JDoLcf1cEpn3Mshp6sxVfCupHZJRPQTozp2EpTF76vJcyQBN7VP7CjUntEJxeADnuTMNTYKoSWNae8soVyv/1/*)#0rlhs7rw"

```

## Arguments

`descriptor` (string, required): A descriptor defining the address(es) derivation scheme to be processed.

## Returns

### Ok Response

- bool: Indicates whether the descriptor was successfully loaded.

### Error Enum `CommandError`

* `JsonRpcError::InvalidDescriptor`
* `JsonRpcError::InInitialBlockDownload`
* `JsonRpcError::Wallet`

## Notes

- If the `descriptor` includes keys, they must always be public keys, because it is watch-only wallet. Passing private keys in the descriptor will result in an error.
- After adding new descriptors or addresses to be monitored on the watch-only wallet, it may be necessary to trigger a blockchain rescan (e.g. via the `rescanblockchain` RPC call) to gather older related transactions and proofs.
