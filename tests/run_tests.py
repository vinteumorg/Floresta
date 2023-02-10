import os
import subprocess
import time
from tqdm import tqdm

BASE_DIR = "/tmp/data"

tests = ["example_test", "restart"]


def main():
    print("Creating work dir")
    data_dir = BASE_DIR + f"run-{time.time()}/"
    if not os.path.isdir(data_dir):
        os.makedirs(data_dir)
    print("Running tests")
    for test_name in tqdm(tests):
        test_dir = "./tests/" + test_name
        log_dir = data_dir + test_name.replace(".py", ".log")
        log_file = open(log_dir, "wt")
        test = subprocess.Popen(["python", test_dir + ".py"],
                                stdout=log_file, stderr=log_file)
        test.wait()
        if test.returncode != 0:
            print(f"Test {test_name} not passed")
        else:
            print(f"Test {test_name} passed")


if __name__ == '__main__':
    main()
