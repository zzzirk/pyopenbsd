import os
import openbsd.netstat
import libpry

class uNetstat(libpry.AutoTree):
    def setUp(self):
        self.n = openbsd.netstat.Netstat()

    def tearDown(self):
        self.n.close()

    def test_ifstats(self):
        assert self.n.ifstats()["lo0"]

    def test_ipstats(self):
        assert self.n.ipstats()

    def test_ip6stats(self):
        assert self.n.ip6stats()

    def test_tcpstats(self):
        assert self.n.tcpstats()

    def test_udpstats(self):
        assert self.n.udpstats()

    def test_icmpstats(self):
        assert self.n.icmpstats()

    def test_igmpstats(self):
        assert self.n.igmpstats()

    def test_ahstats(self):
        assert self.n.ahstats()

    def test_espstats(self):
        assert self.n.espstats()

    def test_ipipstats(self):
        assert self.n.ipipstats()

    def test_ipcompstats(self):
        assert self.n.ipcompstats()

tests = []
if os.geteuid() == 0:
    tests.append(
        uNetstat()
    )
