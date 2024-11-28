### Compact Filters

Floresta supports compact block filters, which can be used to scan for transactions in a block without downloading the entire block. You can start the node with the `--cfilters` flag to download the filters for the blocks that you're interested in. You can also use the `--filters-start-height` flag to specify the block height that you want to start downloading the filters from. This is useful if you want to download only the filters for a specific range of blocks.

```bash
florestad --cfilters --filters-start-height 800000
```