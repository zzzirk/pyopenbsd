import os
import libpry
import openbsd.ifconfig
import openbsd._ifconfig
from openbsd.utils import *

MEDIATYPE = "Ethernet"
# Interface for testing creation and destruction. Should not exist.
CDIFNAME = "tun6"       


class uIfconfig(libpry.AutoTree):
    def setUp(self):
        self.ic = openbsd.ifconfig.IFConfig()

    def test_has_key(self):
        assert self.ic.has_key("lo0")

    def test_getitem(self):
        assert self.ic["lo0"].Name == "lo0"

    def test_keys(self):
        assert self.ic.keys()

    def test_repr(self):
        repr(self.ic)


class uInterface(libpry.AutoTree):
    def setUp(self):
        self.ic = openbsd.ifconfig.IFConfig()

    def test_getinfo(self):
        assert self.ic["lo0"]._getinfo()


class uInterfaceCreateDestroy(libpry.AutoTree):
    def setUp(self):
        self.ic = openbsd.ifconfig.IFConfig()
        if self.ic.has_key(CDIFNAME):
            self.ic.destroy(CDIFNAME)

    def tearDown(self):
        try:
            self.ic.destroy(CDIFNAME)
        except openbsd.ifconfig.OException:
            pass

    if os.geteuid() == 0:
        def test_createdestroy(self):
            self.ic.create(CDIFNAME)
            assert self.ic.has_key(CDIFNAME)
            self.ic.destroy(CDIFNAME)
            assert not self.ic.has_key(CDIFNAME)

        def test_addAddress(self):
            self.ic.create(CDIFNAME)
            self.ic[CDIFNAME].addAddress("10.0.0.1", "255.0.0.0")
            ifadd = self.ic[CDIFNAME].getAddresses()[0]["address"]
            assert ifadd == "10.0.0.1"
            ifmask = self.ic[CDIFNAME].getAddresses()[0]["mask"]
            assert ifmask == Address("255.0.0.0")
           
        def test_addAddressPrefix(self):
            self.ic.create(CDIFNAME)
            self.ic[CDIFNAME].addAddress("10.0.0.1", 8)
            ifadd = self.ic[CDIFNAME].getAddresses()[0]["address"]
            assert ifadd == "10.0.0.1"
            ifmask = self.ic[CDIFNAME].getAddresses()[0]["mask"]
            assert ifmask == Address("255.0.0.0")

        def test_addAddress6(self):
            self.ic.create(CDIFNAME)
            self.ic[CDIFNAME].addAddress("fe::1", 64)
            ifadd = self.ic[CDIFNAME].getAddresses()[0]["address"]
            assert ifadd == "fe::1"
            ifadd = self.ic[CDIFNAME].getAddresses()[0]["mask"]
            assert ifadd == Address("ffff:ffff:ffff:ffff::")

        def test_addAddress6Prefix(self):
            self.ic.create(CDIFNAME)
            self.ic[CDIFNAME].addAddress("fe::1", mask=64)
            ifadd = self.ic[CDIFNAME].getAddresses()[0]["address"]
            assert ifadd, "fe::1"
            ifadd = self.ic[CDIFNAME].getAddresses()[0]["mask"]
            assert ifadd, Address("ffff:ffff:ffff:ffff::")

        def test_delAddress(self):
            self.ic.create(CDIFNAME)
            self.ic[CDIFNAME].addAddress("10.0.0.1", "255.0.0.0")
            self.ic[CDIFNAME].delAddress("10.0.0.1")
            assert not self.ic[CDIFNAME].getAddresses()

        def test_delAddressErr(self):
            self.ic.create(CDIFNAME)
            self.ic[CDIFNAME].addAddress("10.0.0.1", "255.0.0.0")
            libpry.raises(  openbsd.ifconfig.OException,
                                    self.ic[CDIFNAME].delAddress,
                                    "10.0.0.2")

        def test_delAddress6(self):
            self.ic.create(CDIFNAME)
            self.ic[CDIFNAME].addAddress("fe::1")
            self.ic[CDIFNAME].delAddress("fe::1")
            assert not self.ic[CDIFNAME].getAddresses()

        def test_delAddressErr6(self):
            self.ic.create(CDIFNAME)
            self.ic[CDIFNAME].addAddress("fe::1")
            libpry.raises(  openbsd.ifconfig.OException,
                                    self.ic[CDIFNAME].delAddress,
                                    "fe::2")

        def test_setAddress(self):
            self.ic.create(CDIFNAME)
            self.ic[CDIFNAME].setAddress("10.0.0.1")
            self.ic[CDIFNAME].setAddress("10.0.0.2")
            assert len(self.ic[CDIFNAME].getAddresses()) == 1
            add = self.ic[CDIFNAME].getAddresses()[0]["address"]
            assert add == "10.0.0.2"
            self.ic[CDIFNAME].setAddress("fe::01")
            assert len(self.ic[CDIFNAME].getAddresses()) == 2
            self.ic[CDIFNAME].setAddress("fe::02")
            assert len(self.ic[CDIFNAME].getAddresses()) == 2

        def test_setIFGroup(self):
            self.ic.create(CDIFNAME)
            self.ic[CDIFNAME].addGroup('foo')
            assert not 'foo' not in self.ic[CDIFNAME].getGroups()

        def test_setIFGroupErrTooLong(self):
            self.ic.create(CDIFNAME)
            libpry.raises(  openbsd.ifconfig.OException,
                                    self.ic[CDIFNAME].addGroup,
                                    '1234567890123456A')

        def test_setIFGroupErrNumericEnd(self):
            self.ic.create(CDIFNAME)
            libpry.raises(  openbsd.ifconfig.OException,
                                    self.ic[CDIFNAME].addGroup,
                                    '12345678901234567')
            
        def test_unsetIFGroup(self):
            self.ic.create(CDIFNAME)
            self.ic[CDIFNAME].addGroup('foo')
            self.ic[CDIFNAME].delGroup('foo')
            assert not 'foo' in self.ic[CDIFNAME].getGroups()

        def test_unsetIFGroupErrGrpMissing(self):
            self.ic.create(CDIFNAME)
            libpry.raises(  openbsd.ifconfig.OException,
                                    self.ic[CDIFNAME].delGroup,
                                    'bar')

        def test_unsetIFGroupErrGrpTooLong(self):
            self.ic.create(CDIFNAME)
            libpry.raises(  openbsd.ifconfig.OException,
                                    self.ic[CDIFNAME].delGroup,
                                    '0123456789012345A')

        def test_unsetIFGroupErrGrpNumericEnd(self):
            self.ic.create(CDIFNAME)
            libpry.raises(openbsd.ifconfig.OException,
                          self.ic[CDIFNAME].delGroup,
                          '012345678901234')

        def test_getIFGroups(self):
            self.ic.create(CDIFNAME)
            self.ic[CDIFNAME].addGroup('foo')
            self.ic[CDIFNAME].addGroup('bar')
            assert not ['tun', 'foo','bar'] != self.ic[CDIFNAME].getGroups()


class uMedia(libpry.AutoTree):
    def setUp(self):
        ic = openbsd.ifconfig.IFConfig()
        for i in ic.keys():
            if ic[i].media and ic[i].media.mtype == MEDIATYPE:
                self.iface = ic[i]
                return
        raise ValueError, "Could not find %s interface for media testing."%MEDIATYPE

    def test_subtype(self):
        self.iface.media.subtype

    def test_getAllSubtypes(self):
        assert self.iface.media.getAllSubtypes()

    def test_getAllOptions(self):
        self.iface.media.getAllOptions(self.iface.media.subtype)

    def test_options(self):
        self.iface.media.options

    def test_subtype(self):
        assert self.iface.media.subtype

    def test_active_subtype(self):
        assert self.iface.media.active_subtype

    def test_active_options(self):
        self.iface.media.active_options

    def test_repr(self):
        repr(self.iface.media)


class uFlags(libpry.AutoTree):
    def setUp(self):
        self.ic = openbsd.ifconfig.IFConfig()
        if not self.ic.has_key(CDIFNAME):
            self.ic.create(CDIFNAME)
        self.ifp = self.ic[CDIFNAME]

    if os.geteuid() == 0:
        def tearDown(self):
            self.ic.destroy(CDIFNAME)

        def test_get(self):
            assert self.ifp.flags

        def test_set(self):
            self.ifp.flags = self.ifp.flags & (~openbsd.ifconfig.IFF_UP)
            assert not self.ifp.flags & openbsd.ifconfig.IFF_UP

        def test_updown(self):
            self.ifp.up()
            assert self.ifp.flags & openbsd.ifconfig.IFF_UP
            self.ifp.down()
            assert not self.ifp.flags & openbsd.ifconfig.IFF_UP

        def test_repr(self):
            repr(self.ifp.flags)
        

class uMTU(libpry.AutoTree):
    def setUp(self):
        ic = openbsd.ifconfig.IFConfig()
        self.ifp = ic["lo0"]

    def test_get(self):
        self.ifp.mtu

    if os.geteuid() == 0:
        def test_set(self):
            f = self.ifp.mtu
            self.ifp.mtu = 800
            self.ifp.mtu
            assert self.ifp.mtu == 800
            self.ifp.mtu = f


class uMetric(libpry.AutoTree):
    def setUp(self):
        ic = openbsd.ifconfig.IFConfig()
        self.ifp = ic["lo0"]

    def test_get(self):
        self.ifp.metric

    if os.geteuid() == 0:
        def test_set(self):
            f = self.ifp.metric
            self.ifp.metric = 800
            assert self.ifp.metric == 800
            self.ifp.metric = f


tests = [
    uIfconfig(),
    uInterface(),
    uInterfaceCreateDestroy(),
    uMetric(),
    uMedia(),
    uFlags(),
    uMTU()
]
