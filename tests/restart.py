import subprocess
import time
import os
import filecmp
from test_framework.test_framework import TestFramework


class TestRestart(TestFramework):
    def run_test(self):
        """
            Tests if we don't corrupt our data dir between restarts. This would have caught,
            the error fixed in #9
        """
        base_testdir = "data/TestRestart/"
        self.run_node(base_testdir + "1/")
        time.sleep(5)
        self.stop_node(0)
        self.run_node(base_testdir + "2/")
        time.sleep(5)
        self.stop_node(0)
        assert (filecmp.dircmp(base_testdir + "2/", base_testdir + "1/"))
