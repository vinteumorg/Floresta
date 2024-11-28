### Assume Utreexo
If you want to skip the IBD process, you can use the `--assume-utreexo` flag. This flag will start the node at a given height, with the state
provided by this implementation. Therefore, you're trusting that we are giving you the correct state. Everything after that height will be
verified by the node just like any other node.

```bash
florestad --assume-utreexo
```