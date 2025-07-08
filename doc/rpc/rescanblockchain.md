# `rescanblockchain`

Sends a request to the node for rescan the blockchain searching for addresses and utxos.

## Arguments

* start_height (numeric, optional): The initial height to start rescanning. When timestamp is specified this numeric value will be understood as a block UNIX timestamp.

* stop_height (numeric, optional): The height limit to stop the rescanning. When timestamp is specified this numeric value will be understood as a block UNIX timestamp.

* use_timestamp (boolean flag, optional): When present in the command the inserted values will be treated as unix timestamps.

## Returns

### Ok Response

When the rescan request sucessfully starts you will receive an Ok(true).

### Error Enum [`CommandError`]

This RPC command doesnt have any specific error enum besides the internal calls related to blockchain requests.

## Usage Examples

```bash

# Rescan from height 100 to 200

floresta-cli rescanblockchain 100 200

# Rescan from height 100 to tip

floresta-cli rescanblockchain 100

# Rescan from timestamp 123456789 until 133456789

floresta-cli rescanblockchain -t 123456789 133456789

# Rescan from timestamp 123456789 until the tip

floresta-cli rescanblockchain --timestamp 123456789

 ```

## Notes

- Be sure to not insert invalid values, e.g. the start being greater than the stop.

- This rescan relies on BIP 158 block filters.