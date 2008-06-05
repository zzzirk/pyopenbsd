import os, pprint
import openbsd.pf
import libpry
from openbsd._sysvar import *
from openbsd.utils import *

class uTable(libpry.AutoTree):
    def setUp(self):
        self.p = openbsd.pf.PF()
        self.p["pftest"].tables.add("one")
        self.tbl = self.p["pftest"].tables["one"]

    def tearDown(self):
        try:
            self.p["pftest"].tables.clear()
        except openbsd.pf.OException:
            pass

    def _testAddr(self, ao, address, af):
        self.tbl.addAddress(ao)
        a = self.tbl.getAddresses()[0]
        assert a["address"].address == address
        assert a["address"].af == af
        self.tbl.deleteAddress(a["address"])
        assert not self.tbl.getAddresses()

    def test_adddel_address_ip4(self):
        ao = Address("192.168.0.1")
        self._testAddr(ao, "192.168.0.1", AF_INET)

    def test_adddel_address_ip4net(self):
        ao = Address("192.168.0.0")
        self._testAddr(ao, "192.168.0.0", AF_INET)

    def test_adddel_address_ip6(self):
        ao = Address("::f1")
        self._testAddr(ao, "::f1", AF_INET6)

    def test_adddel_address_ip6_net(self):
        ao = Address("ff::")
        self._testAddr(ao, "ff::", AF_INET6)

    def test_doubleAdd(self):
        ao = Address("192.168.0.1")
        self.tbl.addAddress(ao)
        libpry.raises(openbsd.pf.OException, self.tbl.addAddress, ao)

    def test_adddel_address_dummy(self):
        ao = Address("192.168.0.1")
        self.tbl.addAddress(ao)
        self.tbl.deleteAddress(ao, dummy=1)
        self.tbl.deleteAddress(ao)

    def test_addAddress_dummy(self):
        ao = Address("192.168.0.1")
        self.tbl.addAddress(ao, dummy=1)

    def test_deleteNonexistent(self):
        ao = Address("192.168.0.1")
        libpry.raises(openbsd.pf.OException, self.tbl.deleteAddress, ao)

    def test_repr(self):
        repr(self.tbl)


class uTables(libpry.AutoTree):
    def setUp(self):
        self.p = openbsd.pf.PF()
        self.p["pftest"].tables.add("one")
        self.p["pftest"].tables.add("two")

    def tearDown(self):
        try:
            self.p["pftest"].tables.clear()
        except openbsd.pf.OException:
            pass

    def test_nonexistent(self):
        try:
            self.p["pftest"].tables["nonexistent"]
        except openbsd.pf.OException:
            return
        self.fail()

    def test_add(self):
        self.p["pftest"].tables.add("three")
        self.p["pftest"].tables.delete("three")

    def test_add_tflags(self):
        self.p["pftest"].tables.add("four", persist = 1)
        assert self.p["pftest"].tables["four"].flags & openbsd.pf.PFR_TFLAG_PERSIST
        self.p["pftest"].tables.add("five", const = 1)
        assert self.p["pftest"].tables["five"].flags & openbsd.pf.PFR_TFLAG_CONST

    def test_add_iflags(self):
        self.p["pftest"].tables.add("four", dummy = 1)
        assert not self.p["pftest"].tables.has_key("four")

    def test_addDouble(self):
        libpry.raises(openbsd.pf.OException, self.p["pftest"].tables.add, "one")

    def test_delteDouble(self):
        libpry.raises(openbsd.pf.OException, self.p["pftest"].tables.delete, "nonexistent")

    def test_delte_dummy(self):
        self.p["pftest"].tables.delete("two", dummy = 1)
        assert self.p["pftest"].tables.has_key("two")

    def test_clear(self):
        assert self.p["pftest"].tables.clear() == 2
        assert not self.p.has_key("pftest")

    def test_clear_dummy(self):
        assert self.p["pftest"].tables.clear(dummy=1) == 2
        assert self.p["pftest"].tables.has_key("one")
        assert self.p["pftest"].tables.has_key("two")

    def test_keys(self):
        assert len(self.p["pftest"].tables) == 2
        assert len(self.p["pftest"].tables.keys()) == 2


class uAnchor(libpry.AutoTree):
    def setUp(self):
        self.p = openbsd.pf.PF()

    def test_construction(self):
        a = openbsd.pf.Anchor(self.p)["foo"]["bar"]
        assert a.name == "foo/bar"

    def test_rootAnchorConstruction(self):
        a = self.p["foo"]["bar"]
        assert a.name == "foo/bar"

    def test_repr(self):
        repr(self.p["foo"])


class uAnchorContainment(libpry.AutoTree):
    def setUp(self):
        self.p = openbsd.pf.PF()
        self.p["pftest"].tables.add("foo")
        self.p["pftest2"].tables.add("bar")

    def tearDown(self):
        self.p["pftest"].tables.delete("foo")
        self.p["pftest2"].tables.delete("bar")

    def test_len(self):
        assert len(self.p) >= 2

    def test_keys(self):
        x = self.p.keys()
        x.sort()
        assert "pftest" in x
        assert "pftest2" in x

    def test_items(self):
        assert self.p.items()


class uPF(libpry.AutoTree):
    def setUp(self):
        self.p = openbsd.pf.PF()

    def test_start_stop(self):
        # FIXME: Test assumes that pf is disabled. 
        if self.p.getStatistics()["running"]:
            self.p.stop()
            self.p.start()
        else:
            self.p.start()
            self.p.stop()
        
    def test_startALTQ_stopALTQ(self):
        # FIXME: Test assumes that ALTQ is disabled. 
        self.p.startALTQ()
        self.p.stopALTQ()

    def test_getInterfaces(self):
        assert self.p.getInterfaces()

    def test_setLogInterface(self):
        self.p.setLogInterface("lo0")
        self.p.setLogInterface(None)

    def test_getStatistics(self):
        self.p.setLogInterface("fxp0")
        assert self.p.getStatistics()

    def test_clearStatistics(self):
        self.p.clearStatistics()

    def test_getStates(self):
        self.p.getStates()

    def test_clearStates(self):
        self.p.clearStates()
        self.p.clearStates("lo0")

    def test_killStates(self):
        self.p.killStates(interface="lo0", dst="0.0.0.7")
        self.p.killStates(dst="0.0.0.7")
        self.p.killStates(src="0.0.0.7")
        self.p.killStates(dst="10.0.0.7", src="192.168.0.2")
        self.p.killStates(dst="10.0.0.1", dstmask="255.255.255.0")
        self.p.killStates(src="10.0.0.1", srcmask="255.255.255.0")

    def test_killStates6(self):
        self.p.killStates(src="fe::")

    def test_killStates_port(self):
        self.p.killStates(srcport=66666)
        self.p.killStates(dstport=66666)

    def test_killStates_err(self):
        libpry.raises(ValueError, self.p.killStates, src="fe::", dst="10.0.0.1")
        libpry.raises(ValueError, self.p.killStates, src="fe::", srcmask="10.0.0.1")
        libpry.raises(ValueError, self.p.killStates, dst="fe::", dstmask="10.0.0.1")

    def test_repr(self):
        repr(self.p)


class u_makeTree(libpry.AutoTree):
    def test_flatTreeWalker(self):
        x = [i for i in openbsd.pf._flatTreeWalker(["a", "b"], ["c", "d"])]
        assert x == [['a', 'c'], ['a', 'd'], ['b', 'c'], ['b', 'd']]

    def test_makeTree(self):
        x = openbsd.pf._makeTree([1, 2, 3, 4], ["a", "b"], ["c", "d"])
        assert x == {'a': {'c': 1, 'd': 2}, 'b': {'c': 3, 'd': 4}}


tests = [
    u_makeTree()
]
if os.geteuid() == 0:
    tests.extend(
        [
            uTable(),
            uTables(),
            uAnchor(),
            uAnchorContainment(),
            uPF(),
        ]
    )

