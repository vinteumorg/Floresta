### Testing Options

There's a set of tests that you can run with:

```bash
cargo test
```

For the full test suite, including long-running tests, use:

```bash
cargo test --release
```

Additional functional tests are available. Install dependencies and run the test script with:

```bash
pip3 install -r tests/requirements.txt
python tests/run_tests.py
```