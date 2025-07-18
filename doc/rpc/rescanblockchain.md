# `rescanblockchain`

Sends a request to the node for rescan the blockchain searching for addresses and utxos.

## Arguments

* start_height (numeric, optional, default=0): The initial block height to start the blockchain rescan. When timestamp is set this numeric value will be understood as a block UNIX timestamp.

* stop_height (numeric, optional): The height limit to stop the rescanning. When timestamp is set this numeric value will be understood as a block UNIX timestamp.

* use_timestamp (boolean flag, optional): When present in the command the provided values will be treated as UNIX timestamps.

## Returns

### Ok Response

When the rescan request sucessfully starts you will receive an Ok(true).

### Error Enum

This RPC command can only fail if we can communicate with the headers database, 
if invalid values are inserted, that is, the start of the request being lesser
than the stop value. For the timestamp specific one the previous rule is maintained 
and if any of the values is lesser than 1231006505 which is the timestamp of the genesis block.

Also the request will be aborted if the node still syncing with the blockchain.

## Usage Examples

```bash

# Rescan from height 100 to 200

floresta-cli rescanblockchain 100 200

# Rescan from height 100 to tip

floresta-cli rescanblockchain 100

# Rescan from timestamp 1231006505 (genesis) until 133456789

floresta-cli rescanblockchain -t 1231006505 1752516460

# Rescan from timestamp 0 (alias for genesis) until the tip

floresta-cli rescanblockchain --timestamp 0

 ```

## Notes

- Be sure to not insert invalid values, e.g. the start being greater than the stop.

- This rescan relies on BIP 158 block filters.