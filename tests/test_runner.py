"""i disable all pylint here because this is a temporary file, we will replace
it for pytest only soon so i dont want to lose time making it wright"""

# pylint: disable-all

import argparse
import os
import sys
import time
import importlib
import subprocess
from test_framework import FlorestaTestFramework


INFO_EMOJI = "ℹ️"
SUCCESS_EMOJI = "✅"
FAILURE_EMOJI = "❌"
ALLDONE_EMOJI = "🎉"
WARNING_EMOJI = "⚠️"
RUNNING_EMOJI = "🏃"


def import_test_class(module_path, class_name):
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


TEST_REGISTRY = {
    "addnodev2": import_test_class("floresta-cli.addnode-v2", "AddnodeTestV2"),
    "addnodev1": import_test_class("floresta-cli.addnode-v1", "AddnodeTestV1"),
    "reorg_chain": import_test_class("florestad.reorg-chain", "ChainReorgTest"),
    "getbestblockhash": import_test_class(
        "floresta-cli.getbestblockhash", "GetBestblockhashTest"
    ),
    "getblockcount": import_test_class(
        "floresta-cli.getblockcount", "GetBlockCountTest"
    ),
    "uptime": import_test_class("floresta-cli.uptime", "UptimeTest"),
    "restart": import_test_class("florestad.restart", "TestRestart"),
    "connect": import_test_class("florestad.connect", "CliConnectTest"),
    "stop": import_test_class("floresta-cli.stop", "StopTest"),
    "ping": import_test_class("floresta-cli.ping", "PingTest"),
    "getrpcinfo": import_test_class("floresta-cli.getrpcinfo", "GetRpcInfoTest"),
    "getblockhash": import_test_class("floresta-cli.getblockhash", "GetBlockhashTest"),
    "tls": import_test_class("florestad.tls", "TestSslInitialization"),
    "getroots": import_test_class("floresta-cli.getroots", "GetRootsIDBLenZeroTest"),
    "getblock": import_test_class("floresta-cli.getblock", "GetBlockTest"),
    "getmemoryinfo": import_test_class(
        "floresta-cli.getmemoryinfo", "GetMemoryInfoTest"
    ),
    "getblockheader": import_test_class(
        "floresta-cli.getblockheader", "GetBlockheaderHeightZeroTest"
    ),
    "getpeerinfo": import_test_class("floresta-cli.getpeerinfo", "GetPeerInfoTest"),
    "tls_fail": import_test_class("florestad.tls-fail", "TestSslFailInitialization"),
    "getblockchaininfo": import_test_class(
        "floresta-cli.getblockchaininfo", "GetBlockchaininfoTest"
    ),
}


class TestResult:
    """Container for test execution results"""

    def __init__(self, name, success=False, duration=0.0, error_msg=None):
        self.name = name
        self.success = success
        self.duration = duration
        self.error_msg = error_msg


def run_test_direct(test_name, test_class, verbose=False):
    """Run a single test by directly calling main()"""

    start_time = time.time()
    success = False
    error_msg = None

    try:
        # Create and run the test using main() method
        test_instance = test_class()
        test_instance.main()
        success = True

    except SystemExit as e:
        # Test framework uses sys.exit(0) for success, non-zero for failure
        success = e.code == 0
        if not success:
            error_msg = f"Test exited with code: {e.code}"
    except Exception as e:
        # Capture the exception for reporting
        error_msg = f"Error running test {test_name}: {e}"
        if verbose:
            import traceback

            print(traceback.format_exc())
        success = False

    end_time = time.time()
    duration = end_time - start_time

    return TestResult(test_name, success, duration, error_msg)


def run_all_tests(test_registry, verbose=False, continue_on_failure=True):
    """Run all tests in the registry"""

    print(f"{RUNNING_EMOJI} Running {len(test_registry)} tests...")
    print("=" * 60)

    results = []
    overall_start_time = time.time()

    for test_name, test_class in test_registry.items():
        print(f"{INFO_EMOJI} Running test: {test_name}")

        # Run the test
        result = run_test_direct(test_name, test_class, verbose)
        results.append(result)

        # Show immediate result
        if result.success:
            print(f"{SUCCESS_EMOJI} {test_name} PASSED in {result.duration:.2f}s")
        else:
            print(f"{FAILURE_EMOJI} {test_name} FAILED in {result.duration:.2f}s")
            if result.error_msg:
                print(f"    Error: {result.error_msg}")

            if not continue_on_failure:
                print(f"{WARNING_EMOJI} Stopping test execution due to failure")
                break

        print()

    overall_end_time = time.time()
    overall_duration = overall_end_time - overall_start_time

    return results, overall_duration


def print_summary(results, overall_duration, verbose=False):
    """Print a summary of all test results"""

    passed = [r for r in results if r.success]
    failed = [r for r in results if not r.success]

    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    # Overall stats
    print(f"Total tests: {len(results)}")
    print(f"Passed: {len(passed)} {SUCCESS_EMOJI}")
    print(f"Failed: {len(failed)} {FAILURE_EMOJI}")
    print(f"Overall time: {overall_duration:.2f}s")
    print()

    # Passed tests
    if passed:
        print(f"{SUCCESS_EMOJI} PASSED TESTS:")
        for result in passed:
            print(f"  • {result.name:<15} ({result.duration:.2f}s)")
        print()

    # Failed tests
    if failed:
        print(f"{FAILURE_EMOJI} FAILED TESTS:")
        for result in failed:
            print(f"  • {result.name:<15} ({result.duration:.2f}s)")
            if result.error_msg:
                print(f"    └─ {result.error_msg}")
        print()

    # Final result
    if len(failed) == 0:
        print(f"{ALLDONE_EMOJI} All tests PASSED!")
        return True
    else:
        print(f"{FAILURE_EMOJI} {len(failed)} test(s) FAILED")
        return False


def main():
    """Multi-test runner"""

    # Get integration test directory
    try:
        FlorestaTestFramework.get_integration_test_dir()
    except RuntimeError as e:
        print(f"{FAILURE_EMOJI} Environment setup error: {e}")
        print("Make sure FLORESTA_TEMP_DIR is set")
        sys.exit(1)

    # Argument parser
    parser = argparse.ArgumentParser(
        prog="test_runner", description="Run Floresta integration tests"
    )
    parser.add_argument(
        "-t",
        "--test",
        choices=list(TEST_REGISTRY.keys()) + ["all"],
        default="all",
        help="Test to run (default: all)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show verbose output on failure"
    )
    parser.add_argument(
        "--stop-on-failure",
        action="store_true",
        help="Stop running tests after first failure",
    )
    parser.add_argument(
        "--list-tests", action="store_true", help="List available tests and exit"
    )

    args = parser.parse_args()

    # Handle --list-tests
    if args.list_tests:
        print(f"{INFO_EMOJI} Available tests:")
        for test_name in sorted(TEST_REGISTRY.keys()):
            print(f"  • {test_name}")
        print(f"\nTotal: {len(TEST_REGISTRY)} tests")
        return

    # Determine which tests to run
    if args.test == "all":
        tests_to_run = TEST_REGISTRY
        print(f"{INFO_EMOJI} Running ALL tests ({len(tests_to_run)} total)")
    else:
        tests_to_run = {args.test: TEST_REGISTRY[args.test]}
        print(f"{INFO_EMOJI} Running single test: {args.test}")

    # Run the tests
    overall_start_time = time.time()

    if len(tests_to_run) == 1:
        # Single test mode - use original behavior
        test_name = list(tests_to_run.keys())[0]
        test_class = list(tests_to_run.values())[0]

        result = run_test_direct(test_name, test_class, args.verbose)

        if result.success:
            print(f"{SUCCESS_EMOJI} {test_name} PASSED in {result.duration:.2f}s")
            print(f"{ALLDONE_EMOJI} Test completed successfully!")
        else:
            print(f"{FAILURE_EMOJI} {test_name} FAILED in {result.duration:.2f}s")
            if args.verbose and result.error_msg:
                print(f"Error: {result.error_msg}")

        if not result.success:
            sys.exit(1)
    else:
        # Multi-test mode
        results, overall_duration = run_all_tests(
            tests_to_run,
            args.verbose,
            continue_on_failure=not args.stop_on_failure,
        )

        # Print summary
        all_passed = print_summary(results, overall_duration, args.verbose)

        if not all_passed:
            sys.exit(1)

    overall_end_time = time.time()
    print(f"Total runtime: {overall_end_time - overall_start_time:.2f}s")

    # Run pytest after all tests complete
    print("\n" + "=" * 60)
    print(f"{RUNNING_EMOJI} Running pytest tests...")
    print("=" * 60)

    try:
        result = subprocess.run(
            ["uv", "run", "pytest", "tests/", "-n=4"], capture_output=False, text=True
        )

        if result.returncode == 0:
            print(f"\n{SUCCESS_EMOJI} Pytest tests completed successfully!")
        else:
            print(
                f"\n{FAILURE_EMOJI} Pytest tests failed with exit code: {result.returncode}"
            )
            sys.exit(result.returncode)
    except FileNotFoundError:
        print(
            f"\n{FAILURE_EMOJI} Error: 'uv' command not found. Make sure uv is installed."
        )
        sys.exit(1)
    except Exception as e:
        print(f"\n{FAILURE_EMOJI} Error running pytest: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
