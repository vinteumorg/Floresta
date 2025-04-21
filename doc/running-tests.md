# Tests

This document is a guide for the different testing options available in Floresta. We have an extensive suite of Rust tests, as well as a functional tests Python framework, found in the [tests directory](../tests). For fuzzing tests refer to [this document](fuzzing.md).

## Requirements

The tests in `floresta-cli` depend on the compiled `florestad` binary. Make sure to build the entire project first by running:

```bash
cargo build
```

The functional tests also need some dependencies, we use python for writing them and `uv` to manage its dependencies.

Our tests also needs the `Utreexod` and `florestad` binaries to match some functionalities and we have some helper scripts to avoid conflicts, which happens a lot while developing but can help one that have one of them installed in the system.

See [Setting Functional Tests Binaries](#setting-functional-tests-binaries) for more instructions.

## Testing Options
There's a set of unit and integration Rust tests that you can run with:

```bash
cargo test
```

For the full test suite, including long-running tests, use:

```bash
cargo test --release
```

Next sections will cover the Python functional tests.

### Setting Functional Tests Binaries

We provide two helper scripts to support our functional tests and ensure the correct binaries are used.

* [prepare.sh](https://github.com/vinteumorg/Floresta/blob/master/tests/prepare.sh) checks for build dependencies for both `utreexod` and `florestad`, builds them, and sets the `$FLORESTA_TEMP_DIR` environment variable. This variable points to where our functional tests will look for the binaries — specifically at `$FLORESTA_TEMP_DIR/binaries`.

* [run.sh](https://github.com/vinteumorg/Floresta/blob/master/tests/run.sh) adds the binaries found at `$FLORESTA_TEMP_DIR/binaries` to your `$PATH` and runs the tests in that environment.

Using these scripts, you have a few options for running the tests and verifying the functionality of `florestad`:

1) Manually: Build the binaries yourself and place them at `$FLORESTA_TEMP_DIR/binaries`.

2) (Recommended): Use the helper scripts — [prepare.sh](https://github.com/vinteumorg/Floresta/blob/master/tests/prepare.sh) and [run.sh](https://github.com/vinteumorg/Floresta/blob/master/tests/run.sh) — to automatically build and run the tests.

3) With installed binaries: If you've already installed the binaries system-wide, you can simply run the tests directly.

### Running Functional Tests

Additional functional tests are available (minimum python version: 3.12).

* Recommended: install [uv: a rust-based python package and project manager](https://docs.astral.sh/uv/).

* Configure an isolated environment:

```bash
# create a virtual environment
# (it's good to not mess up with your os)
uv venv

# Alternatively, you can specify a python version (e.g, 3.12),
uv venv --python 3.12

# activate the python virtual environment
source .venv/bin/activate

# check if the python path was modified
which python
```

* Install module dependencies:

```bash
# installs dependencies listed in pyproject.toml.
# in local development environment
# it do not remove existing packages.
uv pip install -r pyproject.toml

# if you're a old-school pythonist,
# install from requirements.txt
# without remove existing packages.
uv pip install -r tests/requirements.txt

# Alternatively, you can synchronize it
# uses the uv.lock file to enforce
# reproducible installations.
uv sync
```

* Format code
```bash
uv run black ./tests

# if you want to just check
uv run black --check --verbose ./tests
```


* Lint code
```bash
uv run pylint ./tests
```

* Run tests:

Our tests are separated by "test suites". Suites are folders located in `./tests/<suite>` and the tests are the `./tests/<suite>/*-test.py` files. To run all suites, type:

```bash
uv run tests/run_tests.py
```

You can list all suites with:

```bash
uv run tests/run_tests.py --list-suites
```

To run a specific suite:

```bash
uv run tests/run_tests.py --test-suite <suite>
```

You can even add more:

```bash
uv run tests/run_tests.py --test-suite <suite_A> --test-suite <suite_B>
```

### Running/Developing Functional Tests with Nix

If you have nix, you can run the tests following the instructions [here](nix.md).
