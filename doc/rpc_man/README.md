# General instructions

This folder will hold all the RPC man pages generated.

They can be generated using the script [gen_manpages.sh](/contrib/dist/gen_manpages.sh) for releases/distributions or if you want to generate them locally you can also use the `just gen-manpages` command. This will generate man pages from files at `doc/rpc/*.md` to `doc/man/*.1.gz`. It uses the `pandoc` dependency, so please install it before running the script.

```bash
just gen-manpages <path_to_file> # if no filepath is given, default is doc/rpc/*.md
# or
chmod +x contrib/dist/gen_manpages.sh
./contrib/dist/gen_manpages.sh
```

To read a man-page just do the following:

```bash
man <path-to-file>
man ./doc/rpc_man/template.1 #usage example
```
