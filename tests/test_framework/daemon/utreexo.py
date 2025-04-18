"""
test_framework.daemon.utreexo.py

A test framework for testing utreexod daemon in regtest mode.
"""

from typing import List

from test_framework.daemon.base import BaseDaemon


class UtreexoDaemon(BaseDaemon):
    """
    Spawn a new utreexod process on background and run it on
    regtest mode for tests. You can use it to generate blocks
    and utreexo proofs for tests.
    """

    def create(self, target: str):
        self.name = "utreexod"
        self.target = target

    def valid_daemon_args(self) -> List[str]:
        return [
            "--datadir",
            "--logdir",
            "-C,",
            "--configfile",
            "-d,",
            "--debuglevel",
            "--dbtype",
            "--sigcachemaxsize",
            "--utxocachemaxsize",
            "--noutreexo",
            "--prune",
            "--profile",
            "--cpuprofile",
            "--memprofile",
            "--traceprofile",
            "--testnet",
            "--regtest",
            "--notls",
            "--norpc",
            "--rpccert",
            "--rpckey",
            "--rpclimitpass",
            "--rpclimituser",
            "--rpclisten",
            "--rpcmaxclients",
            "--rpcmaxconcurrentreqs",
            "--rpcmaxwebsockets",
            "--rpcquirks",
            "--proxy",
            "--proxypass",
            "--proxyuser",
            "-a",
            "--addpeer",
            "--connect",
            "--listen",
            "--nolisten",
            "--maxpeers",
            "--uacomment",
            "--trickleinterval",
            "--nodnsseed",
            "--externalip",
            "--upnp",
            "--agentblacklist",
            "--agentwhitelist",
            "--whitelist",
            "--nobanning",
            "--banduration",
            "--banthreshold",
            "--addcheckpoint",
            "--nocheckpoints",
            "--noassumeutreexo",
            "--blocksonly",
            "--maxorphantx",
            "--minrelaytxfee",
            "--norelaypriority",
            "--relaynonstd",
            "--rejectnonstd",
            "--rejectreplacement",
            "--limitfreerelay",
            "--generate",
            "--miningaddr",
            "--blockmaxsize",
            "--blockminsize",
            "--blockmaxweight",
            "--blockminweight",
            "--blockprioritysize",
            "--addrindex",
            "--txindex",
            "--utreexoproofindex",
            "--flatutreexoproofindex",
            "--utreexoproofindexmaxmemory",
            "--cfilters",
            "--nopeerbloomfilters",
            "--dropaddrindex",
            "--dropcfindex",
            "--droptxindex",
            "--droputreexoproofindex",
            "--dropflatutreexoproofindex",
            "--watchonlywallet",
            "--registeraddresstowatchonlywallet",
            "--registerextendedpubkeystowatchonlywallet",
            "--registerextendedpubkeyswithaddresstypetowatchonlywallet",
            "--nobdkwallet",
            "--electrumlisteners",
            "--tlselectrumlisteners",
            "--disableelectrum",
        ]
