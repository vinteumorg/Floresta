"""
run_tests.py

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
import time
from threading import Thread
from queue import Queue

from test_framework import FlorestaTestFramework

BASE_DIR = os.path.normpath(
    os.path.join(str(FlorestaTestFramework.get_integration_test_dir()), "logs")
)
INFO_EMOJI = "ℹ️"
SUCCESS_EMOJI = "✅"
FAILURE_EMOJI = "❌"
ALLDONE_EMOJI = "🎉"

results = []


def list_test_suites(test_dir: str):
    """List all test suites inside ./tests"""
    print(f"{INFO_EMOJI} Available test suites:")
    for name in os.listdir(test_dir):
        p = os.path.join(test_dir, name)
        if os.path.isdir(p) and name not in ("__pycache__", "test_framework"):
            print(f"* {name}")


def run_test_worker(task_queue: Queue, args: argparse.Namespace):
    """
    Worker function to run tests pulled from the task queue.
    Each test is run in a subprocess and logs output to a file.
    Collects the result but does not stop on failure.
    """
    while True:
        task = task_queue.get()
        if task is None:
            break

        test_suite_dir, file = task
        data_dir = os.path.normpath(os.path.join(args.data_dir, file))
        os.makedirs(data_dir, exist_ok=True)

        test_filename = os.path.normpath(os.path.join(test_suite_dir, file))
        test_logname = os.path.normpath(
            os.path.join(data_dir, f"{int(time.time())}.log")
        )

        cli = ["python", test_filename]
        cli_msg = " ".join(cli)
        print(f"{INFO_EMOJI} Running '{cli_msg}'")

        with open(test_logname, "wt", encoding="utf-8") as log_file:
            with subprocess.Popen(cli, stdout=log_file, stderr=log_file) as test:
                test.wait()

        if test.returncode == 0:
            results.append((file, True, test_logname))
        else:
            results.append((file, False, test_logname))

        task_queue.task_done()


def main():
    """
    Create a CLI called `run_tests` with calling arguments

    usage: run_tests [-h] [-d DATA_DIR] [-t TEST_NAME]

    Tool to help with function testing of Floresta.

    Options:
        -h, --help                  Show this help message and exit.
        -d, --data-dir DATA_DIR    Data directory for functional test logs.
        -t, --test-suite TEST_NAME Test-suite directory to be tested.
                                   You can add many.
        -k, --test-name TEST_NAME  Test name to be tested in a suite.
                                   You can add many.
        -l, --list-suites          List all available test-suite directories.
        -T, --threads              Number of threads to run tests in parallel.
    """
    # Structure the CLI
    parser = argparse.ArgumentParser(prog="run_tests")
    parser.add_argument("-d", "--data-dir", default=BASE_DIR)
    parser.add_argument("-t", "--test-suite", action="append", default=[])
    parser.add_argument("-k", "--test-name", action="append", default=[])
    parser.add_argument("-l", "--list-suites", action="store_true", default=False)
    parser.add_argument("-T", "--threads", type=int, default=4)
    args = parser.parse_args()

    test_dir = os.path.abspath(os.path.dirname(__file__))

    if args.list_suites:
        list_test_suites(test_dir)
        return

    if not args.test_suite:
        args.test_suite = [
            os.path.join(test_dir, d)
            for d in os.listdir(test_dir)
            if os.path.isdir(os.path.join(test_dir, d))
            and d not in ("__pycache__", "test_framework")
        ]

    task_queue = Queue()

    for test_suite_dir in args.test_suite:
        if not os.path.exists(test_suite_dir):
            raise argparse.ArgumentError(None, f"Suite '{test_suite_dir}' not found")

        for file in os.listdir(test_suite_dir):
            if file.endswith("-test.py"):
                if args.test_name and not any(
                    file.startswith(name) for name in args.test_name
                ):
                    continue
                task_queue.put((test_suite_dir, file))

    workers = []
    for _ in range(args.threads):
        worker = Thread(target=run_test_worker, args=(task_queue, args))
        worker.start()
        workers.append(worker)

    task_queue.join()

    for _ in workers:
        task_queue.put(None)

    for worker in workers:
        worker.join()

    passed = [(name, log) for name, ok, log in results if ok]
    failed = [(name, log) for name, ok, log in results if not ok]

    print("\nTest Summary:")
    for name, log in passed:
        print(f"  {SUCCESS_EMOJI} {name}: (log: {log})")

    if failed:
        print(f"\n{FAILURE_EMOJI} {len(failed)} test(s) failed:")
        for name, log in failed:
            print(f"  {FAILURE_EMOJI} {name} (log: {log})")
    else:
        print(f"\n{ALLDONE_EMOJI} ALL TESTS PASSED! GOOD JOB!")


if __name__ == "__main__":
    main()
