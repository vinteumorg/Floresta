import subprocess
from threading import Thread
from mock_rpc import MockUtreexod
from json_rpc import Server


class TestFramework:
    tests = []
    nodes: list() = []
    rpc: MockUtreexod = None

    def run_node(self, datadir: str, net: Network):
        node = subprocess.Popen(["cargo", "run", "--", "--network",
                                 net, "run", "--data-dir", datadir])
        self.nodes.append(node)

    def run_rpc(self):
        # Run as a thread
        self.rpc = Thread(target=MockUtreexod)
        self.rpc.start()

    def stop_rpc(self):
        self.rpc._stop()

    def stop_node(self, idx: int):
        self.nodes[idx].send_signal(15)

    # Should be overrided by individual tests
    def run_test(self):
        raise NotImplemented
