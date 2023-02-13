import time

from test_framework.electrum_client import ElectrumClient
from test_framework.test_framework import TestFramework


class ElectrumHandshakeTest(TestFramework):
    def run_test(self):
        try:
            self.run_rpc()
            time.sleep(5)
            self.run_node("./data/handshake/", "signet")
            time.sleep(4)
            client = ElectrumClient("localhost", 50001)
            version = client.get_version()
            assert (
                b'{"id":0,"jsonrpc":"2.0","result":["ElectrumX 1.16.0","1.4"]}' == version)
        except ConnectionRefusedError:
            print("Unable to connect with the electrum server")
            exit(1)
        except AssertionError:
            print("Got an invalid response")
            exit(1)
        finally:
            self.stop_node(0)


if __name__ == "__main__":
    ElectrumHandshakeTest().run_test()
