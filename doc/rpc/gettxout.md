# `gettxout`

Returns details about an unspent transaction output.

## Arguments

* `txid` - (string, required) The transaction id;
* `command` - (string, required) vout number;
* `include_mempool` - (not implemented).

## Returns

### Ok Response

* `"bestblock"`: (String) The hash of the block at the tip of the chain;
* `"confirmations"`: (Numeric) The number of confirmations;
* `"value"` : (Numeric) The transaction value in BTC;
* `"scriptPubKey"` : (json)
  * `"asm"` : (String) The assembled scriptPubKey
  * `"hex"` : (String) The raw scriptPubKey
  * `"type"` : (String) The type, eg pubkeyhash
  * `"addresses"` : (String) bitcoin addresses
* `"coinbase"` : (Boolean) Coinbase or not.

### Error Enum `CommandError`

* `JsonRpcError::BlockNotFound`;
* `JsonRpcError::InvalidScript`;
* `JsonRpcError::InvalidDescriptor`;
* `JsonRpcError::Encode`

## Usage Examples

* General usage:

```bash
floresta-cli gettxout <txid> <n> (include_mempool)
```

* Examples:

```bash
# gettxout with a txid, vout 0 and include_mempool is false by default
floresta-cli gettxout aa5f3068b53941915d82be382f2b35711305ec7d454a34ca69f8897510db7ab8 0

# gettxout with a txid, vout 0 and include_mempool is false
floresta-cli gettxout aa5f3068b53941915d82be382f2b35711305ec7d454a34ca69f8897510db7ab8 0 false

# gettxout with a txid, vout 0 and include_mempool is true
floresta-cli gettxout aa5f3068b53941915d82be382f2b35711305ec7d454a34ca69f8897510db7ab8 0 true
```

## Notes

This `rpc` isn't fully implemented mostly because we need to implement mempool. For more information see [RPC Saga](https://github.com/orgs/vinteumorg/projects/5):

* It accept the `include_mempool` option, but for now, it do nothing;
