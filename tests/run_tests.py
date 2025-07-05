"""
run_tests.py

Command Line Interface to run an individual test or multiple tests in a suite.

New test suites should be added as a subdirectory of `./tests`.

Running tests using the `uv` package manager is recommended, although you
can run them using your system's Python directly (the use of a virtual environment is advised).

All tests will run as a spawned subprocess and logs will be written to a temporary directory.

For more information about how to run the tests, see
[doc/running_tests.md](doc/running_tests.md).

For more information about how to define a test, see
[tests/example](./tests/example) files.
"""

import argparse
import os
import subprocess
import time

from test_framework import FlorestaTestFramework

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


def run_test(args: argparse.Namespace, test_suite_dir: str, file: str):
    """Run a test file from the test suite directory"""
    data_dir = os.path.normpath(os.path.join(args.data_dir, file))
    if not os.path.isdir(data_dir):
        os.makedirs(data_dir)

    # get test file and create a log for it
    test_filename = os.path.normpath(os.path.join(test_suite_dir, file))
    test_logname = os.path.normpath(os.path.join(data_dir, f"{int(time.time())}.log"))

    with open(test_logname, "wt", encoding="utf-8") as log_file:
        cli = ["python", test_filename]
        cli_msg = " ".join(cli)
        print(f"{INFO_EMOJI} Running '{cli_msg}'")
        print(f"Writing stuff to {test_logname}")

        with subprocess.Popen(cli, stdout=log_file, stderr=log_file) as test:
            test.wait()

        # Check the test, if failed, log the results
        # if passed, just show that worked
        if test.returncode != 0:
            print(f"Test {file} not passed {FAILURE_EMOJI}")
            with open(test_logname, "rt", encoding="utf-8") as log_file:
                raise RuntimeError(f"Tests failed:{log_file.read()}")

        print(f"Test {file} passed {SUCCESS_EMOJI}")
        print()


def main():
    """
    Create a CLI called `run_tests` with calling arguments

    usage: run_tests [-h] [-d DATA_DIR] [-t TEST_NAME]

    Utility tool for Floresta functional tests

    options:
        -h, --help                 show this help message and exit.
        -d, --data-dir DATA_DIR    data directory of the run_tests's functional
                                   test logs.
        -t, --test-suite TEST_NAME test-suit directory to be tested by run_tests.
                                   You can add many.
        -k, --test-name TEST_NAME  test name to be tested by run_tests's.
                                   You can add many.
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
        help="test suite directory to be tested by %(prog)s's. You can add many",
        action="append",
        default=[],
    )

    parser.add_argument(
        "-k",
        "--test-name",
        help="test name in a suite to be tested by %(prog)s's. You can add many",
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

    # If `--list-suites`/`-l` is passed, list available tests and exit.
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

    # Run all tests defined by --test_suite, if any.
    for _dir in args.test_suite:
        test_suite_dir = os.path.join(test_dir, _dir)

        # If the test suite is not found, throw an error.
        if not os.path.exists(test_suite_dir):
            raise argparse.ArgumentError(
                argument=None, message=f"Suite '{_dir}' not found"
            )

        # If the test suite is found, run all of it's tests.
        for file in os.listdir(test_suite_dir):
            # Add all tests selected with `--test-name` to the queue.
            # If no tests were selected, add the whole suite to the queue.
            if file.endswith(".py") and file != "__init__.py":
                if args.test_name:
                    if any(file.startswith(name) for name in args.test_name):
                        run_test(args, test_suite_dir, file)
                else:
                    run_test(args, test_suite_dir, file)

    print("🎉 ALL TESTS PASSED! GOOD JOB!")


if __name__ == "__main__":
    main()
