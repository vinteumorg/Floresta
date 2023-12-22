import subprocess

from threading import Thread

from .mock_rpc import MockUtreexod

class TestFramework:
    tests = []
    nodes: list() = []
    rpc: MockUtreexod = None

    def run_node(self, datadir: str, net: str):
        node = subprocess.Popen([
            "cargo", "run", "--", "--network",
            net, "run", "--rpc-host", "http://localhost:8080",
            "--data-dir", datadir
        ])
        self.nodes.append(node)

    def run_rpc(self):
        # Run as a thread
        self.rpc = Thread(target=MockUtreexod().run)
        self.rpc.daemon = True
        self.rpc.start()

    def stop_node(self, idx: int):
        self.nodes[idx].send_signal(15)
        self.nodes[idx].wait()

    # Should be overrided by individual tests
    def run_test(self):
        raise NotImplemented

    def main(self):
        self.run_test()
