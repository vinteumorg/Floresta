"""
run_tests.py

Command Line Interface to run a test by its name. The name should be placed at ./tests folder.
It's suposed that you run it through `poetry` package management and `poe` task manager, but you
can run it with `python` if you installed the packages properly, in a isolated or not isolated
environment (althought we recommend the isolated environment).

All tests will run as a spwaned subprocess and what happens will be logged to a temporary directory

```bash
# The default way to run all tests
poetry run poe tests

# The default way to run a separated test (see the ones -- or define one -- in pyproject.toml)
poetry run poe example-test

# This will do the same thing in the isolated environment
poetry run python tests/run_tests.py --test-name example_test

# You can even define the `data_dir` to logs
poetry run python tests/run_tests.py --test-name example_test --data-dir $HOME/my/path

# If you have a proper environment wit all necessary packages installed
# it can be possible to run without poetry
python tests/run_tests.py --test-name example_test --data-dir $HOME/my/path
```
"""

import os
import subprocess
import time
import argparse


from test_framework.test_framework import FlorestaTestFramework

BASE_DIR = os.path.normpath(
    os.path.join(FlorestaTestFramework.get_integration_test_dir(), "logs")
)
INFO_EMOJI = "ℹ️"
SUCCESS_EMOJI = "✅"
FAILURE_EMOJI = "❌"
ALLDONE_EMOJI = "🎉"


def list_test_suites(test_dir: str):
    """List all test suites inside ./tests"""
    print(f"{INFO_EMOJI} Available test suites:")
    for name in os.listdir(test_dir):
        p = os.path.join(test_dir, name)
        if os.path.isdir(p) and name not in ("__pycache__", "test_framework"):
            print(f"* {name}")


def main():
    """
    Create a CLI called `run_tests` with calling arguments

    usage: run_tests [-h] [-d DATA_DIR] [-t TEST_NAME]

    tool to help with function testing of Floresta

    options:
        -h, --help                show this help message and exit
        -d, --data-dir DATA_DIR   data directory of the run_tests's functional test logs
    """
    # Structure the CLI
    parser = argparse.ArgumentParser(
        prog="run_tests",
        description="tool to help with function testing of Floresta",
    )

    parser.add_argument(
        "-d",
        "--data-dir",
        help="data directory of the %(prog)s's functional test logs",
        default=BASE_DIR,
    )

    parser.add_argument(
        "-t",
        "--test-suite",
        help="test-suit directory to be tested by %(prog)s's. You can add many ",
        action="append",
        default=[],
    )

    parser.add_argument(
        "-l",
        "--list-suites",
        help="list all available test-suit directories to be tested by %(prog)s's",
        action="store_true",
        default=False,
    )

    # Parse arguments of CLI
    args = parser.parse_args()

    # Setup directories and filenames for the specific test
    test_dir = os.path.abspath(os.path.dirname(__file__))

    # if list is provided,
    # only list the available tests
    # and exit the program
    if args.list_suites:
        list_test_suites(test_dir)
        return

    # lets define the default paths of suites
    # in None is provided in CLI.
    # They should be all folders on tests/ dir,
    # excluding __pycache__ and test_framework
    if len(args.test_suite) == 0:
        for _dir in os.listdir(test_dir):
            test_suite_dir = os.path.join(test_dir, _dir)
            if os.path.isdir(test_suite_dir) and _dir not in (
                "__pycache__",
                "test_framework",
            ):
                args.test_suite.append(test_suite_dir)

    # Run all tests defined by --test_suite if any is (are) provided.
    # Run all default ones in ./tests/<test-suide-n>/*-test.py
    for _dir in args.test_suite:
        test_suite_dir = os.path.join(test_dir, _dir)

        # If a suite isnt defined in tests folder
        # raise an error and show it to the developer
        if not os.path.exists(test_suite_dir):
            raise argparse.ArgumentError(
                argument=None, message=f"Suite '{_dir}' not found"
            )

        # If the suite is found, run all tests
        # inside the folder. The tests should have
        # a suffix "-test.py"
        for file in os.listdir(test_suite_dir):
            if file.endswith("-test.py"):

                # Define the data-dir and create it
                data_dir = os.path.normpath(os.path.join(args.data_dir, file))
                if not os.path.isdir(data_dir):
                    os.makedirs(data_dir)

                # get test file and create a log for it
                test_filename = os.path.normpath(os.path.join(test_suite_dir, file))
                test_logname = os.path.normpath(
                    os.path.join(data_dir, f"{int(time.time())}.log")
                )

                # Now start the test
                with open(test_logname, "wt", encoding="utf-8") as log_file:
                    cli = ["python", test_filename]
                    cli_msg = " ".join(cli)
                    print(f"Running '{cli_msg}'")

                    with subprocess.Popen(
                        cli, stdout=log_file, stderr=log_file
                    ) as test:
                        test.wait()
                        print(f"Writing stuff to {test_logname}")

                # Check the test, if failed, log the results
                # if passed, just show that worked
                if test.returncode != 0:
                    print(f"Test {file} not passed {FAILURE_EMOJI}")
                    with open(test_logname, "rt", encoding="utf-8") as log_file:
                        raise RuntimeError(f"Tests failed: {log_file.read()}")

                print(f"Test {file} passed {SUCCESS_EMOJI}")
                print()

    print("🎉 ALL TESTS PASSED! GOOD JOB!")


if __name__ == "__main__":
    main()
