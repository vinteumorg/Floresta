import os
import subprocess
import time

BASE_DIR = "/tmp/data"
SUCCESS_EMOJI = "✔"
FAILURE_EMOJI = "❌"

tests = ["example_test", "restart"]

def main():
    print("Creating work dir")
    data_dir = BASE_DIR + f"run-{time.time()}/"
    print(f'writing stuff to {data_dir}')

    if not os.path.isdir(data_dir):
        os.makedirs(data_dir)

    for test_name in tests:
        test_dir = "./tests/" + test_name
        log_dir = data_dir + test_name.replace(".py", ".log")
        log_file = open(log_dir, "wt")
        test = subprocess.Popen(["python", test_dir + ".py"],
                                stdout=log_file, stderr=log_file)
        test.wait()
        if test.returncode != 0:
            print(f"Test {test_name} not passed {FAILURE_EMOJI}")
        else:
            print(f"Test {test_name} passed {SUCCESS_EMOJI}")


if __name__ == '__main__':
    main()
