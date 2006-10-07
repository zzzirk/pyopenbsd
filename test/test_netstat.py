import os, unittest
import openbsd.netstat
import pprint

pp = pprint.PrettyPrinter(indent=4)

if os.geteuid() == 0:
    class uKVM(unittest.TestCase):
        def setUp(self):
            self.n = openbsd.netstat.Netstat()

        def tearDown(self):
            self.n.close()

        def test_ifstats(self):
            self.failUnless(self.n.ifstats()["lo0"])

        def test_ipstats(self):
            self.failUnless(self.n.ipstats())

        def test_ip6stats(self):
            self.failUnless(self.n.ip6stats())

        def test_tcpstats(self):
            self.failUnless(self.n.tcpstats())

        def test_udpstats(self):
            self.failUnless(self.n.udpstats())

        def test_icmpstats(self):
            self.failUnless(self.n.icmpstats())

        def test_igmpstats(self):
            self.failUnless(self.n.igmpstats())

        def test_ahstats(self):
            self.failUnless(self.n.ahstats())

        def test_espstats(self):
            self.failUnless(self.n.espstats())

        def test_ipipstats(self):
            self.failUnless(self.n.ipipstats())

        def test_ipcompstats(self):
            self.failUnless(self.n.ipcompstats())


