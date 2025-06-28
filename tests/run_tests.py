"""
test_runner.py

Command Line Interface to run an individual test or multiple tests in a suite.

The test-suite should be placed as a subfolder at `./tests` folder and the
test-name should be a file with the suffix `-test.py` inside the test-suite
folder.

It's recommended that you run it through `uv` package management, but you can run
it with `python` if you installed the packages properly, in a isolated or not
isolated environment (althought we recommend the isolated environment).

All tests will run as a spwaned subprocess and what happens will be logged to
a temporary directory.

For more information about how to run the tests, see
[doc/running_tests.md](doc/running_tests.md).

For more information about how to define a test, see
[tests/example](./tests/example) files.
"""

import argparse
import os
import subprocess
from threading import Thread
from queue import Queue
from time import time

from test_framework import FlorestaTestFramework

BASE_LOG_DIR = os.path.normpath(
    os.path.join(str(FlorestaTestFramework.get_integration_test_dir()), "logs")
)
INFO_EMOJI = "ℹ️"
SUCCESS_EMOJI = "✅"
FAILURE_EMOJI = "❌"
ALLDONE_EMOJI = "🎉"

# Scripts that are run by default.
# Longest test should go first,
# to favor running tests in parallel.
# We use this inspired by the
# Bitcoin Core tests/functional/test_runner.py:89
BASE_TEST_SUITE = [
    ("floresta-cli", "addnode-v1"),
    ("floresta-cli", "addnode-v2"),
    ("florestad", "reorg-chain"),
    ("florestad", "ssl"),
    ("florestad", "ssl-fail"),
    ("florestad", "restart"),
    ("example", "integration"),
    ("example", "bitcoin"),
    ("example", "utreexod"),
    ("example", "functional"),
    ("floresta-cli", "getblock"),
    ("floresta-cli", "getblockchaininfo"),
    ("floresta-cli", "getblockhash"),
    ("floresta-cli", "getblockheader"),
    ("floresta-cli", "getmemoryinfo"),
    ("floresta-cli", "getpeerinfo"),
    ("floresta-cli", "getroots"),
    ("floresta-cli", "ping"),
    ("floresta-cli", "stop"),
]


def list_test_suites(test_dir: str):
    """List all test suites inside ./tests"""
    print(f"{INFO_EMOJI} Available test suites:")

    for folder, name in BASE_TEST_SUITE:
        fullpath = os.path.join(test_dir, folder, f"{name}-test.py")
        if os.path.exists(fullpath):
            print(f"--test-suite {folder} --test-name {name}")


def setup_test_suite(args: argparse.Namespace, test_dir: str) -> Queue:
    """
    Setup the test suite directories based on the provided arguments.
    If no test suite is specified, it defaults to the BASE_TEST_SUITE.
    """
    task_queue = Queue()

    if not os.path.exists(args.log_dir):
        os.makedirs(args.log_dir, exist_ok=True)

    if not args.test_suite:
        for folder, name in BASE_TEST_SUITE:
            full_path = os.path.join(test_dir, folder)
            if not os.path.exists(full_path):
                raise argparse.ArgumentError(
                    None, f"Test suite '{full_path}' does not exist"
                )

            if args.test_name and not any(name.startswith(n) for n in args.test_name):
                continue

            task_queue.put((full_path, name))

    else:
        for folder in args.test_suite:
            full_path = os.path.join(test_dir, folder)
            if not os.path.exists(full_path):
                raise argparse.ArgumentError(
                    None, f"Test suite '{full_path}' not found"
                )

            for file in os.listdir(full_path):
                if file.endswith("-test.py"):
                    if args.test_name and not any(
                        file.startswith(name) for name in args.test_name
                    ):
                        continue

                    name = file.split("-test.py")[0]
                    task_queue.put((full_path, name))

    return task_queue


def run_test_workers(task_queue: Queue, args: argparse.Namespace) -> list:
    """Run the tests in parallel"""
    results_queue = Queue()
    workers = []

    for _ in range(args.threads):
        worker = Thread(target=run_test_worker, args=(task_queue, results_queue, args))
        worker.start()
        workers.append(worker)

    for _ in workers:
        task_queue.put(None)

    for worker in workers:
        worker.join()

    results = []
    while not results_queue.empty():
        results.append(results_queue.get())

    return results


def run_test_worker(task_queue: Queue, results_queue: Queue, args: argparse.Namespace):
    """
    Worker function to run tests pulled from the task queue.
    Each test is run in a subprocess and logs output to a file.
    """
    while True:
        task = task_queue.get()
        if task is None:
            break

        test_suite_dir, name = task
        os.makedirs(args.log_dir, exist_ok=True)

        test_filename = os.path.normpath(
            os.path.join(test_suite_dir, f"{name}-test.py")
        )
        test_log_name = os.path.normpath(os.path.join(args.log_dir, f"{name}.log"))

        cli = ["python", test_filename]
        cli_msg = " ".join(cli)
        print(f"\n{INFO_EMOJI} Running '{cli_msg}'")

        start = time()
        with open(test_log_name, "wt", encoding="utf-8") as log_file:
            with subprocess.Popen(cli, stdout=log_file, stderr=log_file) as test:
                test.wait()

        results_queue.put(
            (test_filename, test.returncode == 0, test_log_name, start, time())
        )
        task_queue.task_done()


# pylint: disable=too-many-branches
def main():
    """
    Create a CLI called `run_tests` with calling arguments

    usage: run_tests [-h] [-d DATA_DIR] [-t TEST_NAME]

    Tool to help with function testing of Floresta.

    Options:
        -h, --help                 Show this help message and exit.
        -L, --log-dir DATA_DIR    Data directory for functional test logs.
        -t, --test-suite TEST_NAME Test-suite directory to be tested.
                                   You can add many.
        -k, --test-name TEST_NAME  Test name to be tested in a suite.
                                   You can add many.
        -l, --list-suites          List all available test-suite directories.
        -T, --threads              Number of threads to run tests in parallel.
    """
    # Structure the CLI
    parser = argparse.ArgumentParser(prog="run_tests")
    parser.add_argument(
        "-L",
        "--log-dir",
        default=BASE_LOG_DIR,
        help="Data directory for functional test logs.",
    )
    parser.add_argument(
        "-t",
        "--test-suite",
        action="append",
        default=None,
        help="Test-suite directory to be tested. You can add many.",
    )
    parser.add_argument(
        "-k",
        "--test-name",
        action="append",
        default=[],
        help="Test name to be tested in a suite. You can add many.",
    )
    parser.add_argument(
        "-l",
        "--list-suites",
        action="store_true",
        default=False,
        help="List all available test-suite directories.",
    )
    parser.add_argument(
        "-T",
        "--threads",
        type=int,
        default=4,
        help="Number of threads to run tests in parallel.",
    )
    args = parser.parse_args()

    args.log_dir = os.path.abspath(BASE_LOG_DIR)

    test_dir = os.path.abspath(os.path.dirname(__file__))

    if args.list_suites:
        list_test_suites(test_dir)
        return

    task_queue = setup_test_suite(args, test_dir)
    results = run_test_workers(task_queue, args)

    passed = [(name, log, start, end) for (name, ok, log, start, end) in results if ok]
    failed = [
        (name, log, start, end) for (name, ok, log, start, end) in results if not ok
    ]

    print("\nTest Summary:")
    print(f"\n{len(passed)} test(s) passed:")
    for name, log, start, end in passed:
        print(f"\n  {SUCCESS_EMOJI} {name}: {log} (took {end - start:.2f}s)")

    if failed:
        print(f"\n{len(failed)} test(s) failed:")
        for name, log, start, end in failed:
            print(f"\n  {FAILURE_EMOJI} {name} failed: {log} (took {end - start:.2f}s)")
        raise SystemExit(
            f"\n{FAILURE_EMOJI} Some tests failed. Check the logs in {args.log_dir}."
        )
    print(f"\n{ALLDONE_EMOJI} ALL TESTS PASSED! GOOD JOB!")


if __name__ == "__main__":
    main()
