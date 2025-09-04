# `rescanblockchain`

Sends a request to the node for rescan the blockchain searching for transactions related to the wallet's cached addresses.

## Usage

### Synopsis

```Bash
floresta-cli rescanblockchain <--t or --timestamp> <start_block> <stop_block> <high|medium|low|exact)>
```

### Examples

```bash

# Rescan from height 100 to 200

floresta-cli rescanblockchain 100 200

# Rescan from height 100 to tip

floresta-cli rescanblockchain 100

# Rescan from timestamp 1231006505 (genesis) until 133456789

floresta-cli rescanblockchain -t 1231006505 1752516460 --confidence high

# Rescan from timestamp 0 (alias for genesis) until the tip

floresta-cli rescanblockchain --timestamp 0 1752516460 -c high

 ```

## Arguments

`start_block` (numeric, optional, default=`0`): The initial block to start the blockchain rescan.

`stop_block` (numeric, optional, default=`0`): The block limit to stop rescanning. (0 disables it)

`use_timestamp` (boolean flag, optional, default=`false`): When present in the command the provided values will be treated as UNIX timestamps. These timestamps do not need to be directly from a block and can be used for finding addresses and UTXOs from meaningful timestamp values.

`confidence` (string, optional, default=`medium`): In cases where `use_timestamp` is set, tells how much confidence the user wants for finding its addresses from this rescan request, a higher confidence will add more lookback seconds to the targeted timestamp and rescanning more blocks.

Under the hood this uses an [Exponential distribution](https://en.wikipedia.org/wiki/Exponential_distribution) [cumulative distribution function (CDF)](https://en.wikipedia.org/wiki/Cumulative_distribution_function) where the parameter $\lambda$ (rate) is $\frac{1}{600}$ (1 block every 600 seconds, 10 minutes).
  The supplied string can be one of:
  
  - `high`: 99% confidence interval.
  - `medium` (default): 95% confidence interval.
  - `low`: 90% confidence interval.
  - `exact`: Doesnt apply any lookback seconds.

## Returns

### Ok Response

When the rescan request successfully starts you will receive an Ok(true).
After the rescan finishes, you'll see a log message telling all the blocks that may have any transactions to your wallet

### Error Enum

This RPC command can only fail if:
   - we can't communicate with the headers database;
   - if invalid values are provided. That is, the start of the request being less than the stop value.

If `timestamp` is true, apart the previous rules, if any of the values is smaller than the genesis block (1231006505 for mainnet) or greater than the tip time, the execution will also fail.

Furthermore, the request will be aborted if the node still syncing with the blockchain.

## Notes

- Be sure to not insert invalid values, e.g. the start being greater than the stop.

- This rescan relies on BIP 158 block filters.

- You dont need to be picky with timestamps but, when using uncertain timestamps you mostly want to set a high confidence which is not necessary for precise timestamps.