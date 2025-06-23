## Command line utility

This is a simple cli utility to interact with your node. To run it, just call

```bash
floresta-cli help # this will show all the available options
floresta-cli help <command> # this will show the help for the command including the usage and description
floresta-cli [<options>] <command> <args> #general command usage
```

We also have `man pages` that can be generated using the script [gen_manpages.sh](/contrib/dist/gen_manpages.sh) for releases/distributions or if you want to generate them locally you can also use the `just convert-all` command. This will generate man pages from files at `doc/rpc/*.md` to `doc/man/*.1.gz`. It uses the `pandoc` dependency, so please install it before running the script.

```bash
just gen-manpages
# or
chmod +x contrib/dist/gen_manpages.sh
./contrib/dist/gen_manpages.sh
```

To read a man-page just do the following:

```bash
man <path-to-file>
man ./doc/rpc_man/template.1 #usage example
```
