import unittest
from openbsd.utils import *

class uUtility(unittest.TestCase):
    def test_multiord(self):
        self.failUnlessEqual(multiord("a"), 0x61)
        self.failUnlessEqual(multiord(""), 0)
        self.failUnlessEqual(multiord("aa"), 24929)

    def test_multichar(self):
        self.failUnlessEqual(multichar(0x61, 1), "\x61")
        self.failUnlessEqual(multichar(0x61, 2), "\x00\x61")
        self.failUnlessEqual(multichar(257, 2), "\x01\x01")
        self.failUnlessEqual(multichar(257, 4), "\x00\x00\x01\x01")
        self.failUnlessRaises(ValueError, multichar, 257, 1)

    def test_checksumBasic(self):
        # FIXME: More unit tests here.
        tstr = "".join([chr(i) for i in range(9)])
        self.failUnlessEqual(cksum16(tstr), 60399)

    def test_findLongestSubsequence(self):
        fls = findLongestSubsequence
        self.failUnlessEqual(fls("ffaaaff", "a"), (2, 4))
        self.failUnlessEqual(fls("ffaaaffaaaa", "a"), (7, 10))
        self.failUnlessEqual(fls("ffaaaffaaa", "a"), (2, 4))
        self.failUnlessEqual(fls("aaaffaaa", "a"), (0, 2))
        self.failUnlessEqual(fls("aaa", "a"), (0, 2))

    def test_isStringLike(self):
        self.failUnless(isStringLike("sdf"))
        self.failIf(isStringLike(2))

    def test_isNumberLike(self):
        self.failUnless(isNumberLike(2))
        self.failIf(isNumberLike("sdfs"))






class uDoubleAssociation(unittest.TestCase):
    def setUp(self):
        self.d = DoubleAssociation()

    def test_setitem(self):
        self.d["one"] = 1
        self.failUnlessEqual(self.d["one"], 1)
        self.failUnlessEqual(self.d[1], "one")

    def test_initialisation(self):
        d = DoubleAssociation({"one": 1})
        self.failUnlessEqual(d["one"], 1)
        self.failUnlessEqual(d[1], "one")


class uAddrBase(unittest.TestCase):
    def test_eq(self):
        a = IPAddress("1.2.4.8")
        b = IPAddress("1.2.4.8")
        self.failUnless(a == "1.2.4.8")
        self.failUnless(a == b)
        self.failIf(a == "1.2.3.5")

    def test_err(self):
        a = IPAddress("1.2.4.8")
        self.failUnlessRaises(ValueError, cmp, a, "twenty")


class uIPAddress(unittest.TestCase):
    def test_create(self):
        a = IPAddress("1.2.4.8")
        self.failUnlessEqual(a.address, "1.2.4.8")
        self.failUnlessEqual(a.af, AF_INET)

        a = IPAddress("1.2.4.8")
        self.failUnlessEqual(a.address, "1.2.4.8")
        self.failUnlessEqual(a.af, AF_INET)

        a = IPAddress("1.2.4.8")
        self.failUnlessEqual(a.address, "1.2.4.8")
        self.failUnlessEqual(a.af, AF_INET)

    def test_fromBytes(self):
        self.failUnlessEqual(   IPAddress.fromBytes("\xff\xff\x00\x01"),
                                "255.255.0.1")
        self.failUnlessEqual(   IPAddress.fromBytes("\x00\x00\x00\x00"),
                                "0.0.0.0")

    def test_fromBytes_err(self):
        self.failUnlessRaises(  ValueError,
                                IPAddress.fromBytes,
                                "\xff\xff\xff\x00\x01")
        self.failUnlessRaises(  ValueError,
                                IPAddress.fromBytes,
                                "\x00\x00\x00")

    def test_create_err(self):
        self.failUnlessRaises(ValueError, IPAddress, "256.255.0.1")
        self.failUnlessRaises(ValueError, IPAddress, "af.255.0.1")
        self.failUnlessRaises(ValueError, IPAddress, "255.0.1")
        self.failUnlessRaises(ValueError, IPAddress, "255.0.1.1.1")

    def test_bytes(self):
        a = Address("1.2.4.8")
        self.failUnlessEqual(a.bytes, '\x01\x02\x04\x08')
        self.failUnlessEqual(Address("255.255.0.1").bytes, "\xff\xff\x00\x01")
        self.failUnlessEqual(Address("0.0.0.0").bytes, "\x00\x00\x00\x00")

    def test_repr(self):
        a = Address("1.2.4.8")
        repr(a)


class uIPMask(unittest.TestCase):
    def test_create(self):
        self.failUnlessEqual(IPMask("255.255.0.0"), "255.255.0.0")
        self.failUnlessEqual(IPMask(1), "128.0.0.0")
        self.failUnlessEqual(IPMask(0), "0.0.0.0")
        self.failUnlessEqual(IPMask(8), "255.0.0.0")
        self.failUnlessEqual(IPMask(32), "255.255.255.255")
        self.failUnlessEqual(IPMask(9), "255.128.0.0")
        self.failUnlessEqual(IPMask(12), "255.240.0.0")

    def test_create_err(self):
        self.failUnlessRaises(ValueError, IPMask, "255.255.0.1")
        self.failUnlessRaises(ValueError, IPMask, "255.255.1.0")
        self.failUnlessRaises(ValueError, IPMask, -1)
        self.failUnlessRaises(ValueError, IPMask, 33)
        
    def test_prefix(self):
        self.failUnlessEqual(IPMask("255.255.0.0").prefix, 16)
        self.failUnlessEqual(IPMask("0.0.0.0").prefix, 0)
        self.failUnlessEqual(IPMask("255.255.255.255").prefix, 32)
        self.failUnlessEqual(IPMask("255.128.0.0").prefix, 9)
        self.failUnlessEqual(IPMask("255.240.0.0").prefix, 12)


class uIP6Address(unittest.TestCase):
    def test_create(self):
        a = IP6Address("::1")
        self.failUnlessEqual(a.address, "::1")
        self.failUnlessEqual(a.af, AF_INET6)

        a = IP6Address("::1")
        self.failUnlessEqual(a.address, "::1")
        self.failUnlessEqual(a.af, AF_INET6)

    def test_create_err(self):
        self.failUnlessRaises(ValueError, IP6Address, "10.0.0.0")
        self.failUnlessRaises(ValueError, IP6Address, "ffx::")

    def test_repr(self):
        a = IP6Address("::fe")
        repr(a)

    def test_bytes(self):
        a = IP6Address("::1")
        self.failUnlessEqual(a.bytes, '\x00'*15+'\x01')

    def test_bytes(self):
        self.failUnlessEqual(IP6Address(":".join(["ffff"]*8)).bytes, "\xff"*16)
        self.failUnlessEqual(IP6Address("::1").bytes, "\x00"*15+"\x01")
        self.failUnlessEqual(IP6Address("102::1").bytes, "\x01\x02" + "\x00"*13+"\x01")

    def test_ip6ToBytesErr(self):
        self.failUnlessRaises(ValueError, IP6Address, "0::0::1")
        self.failUnlessRaises(ValueError, IP6Address, "1:0:0:1:1:1:1:1:1")

    def test_fromBytes(self):
        self.failUnlessEqual(IP6Address.fromBytes("\xff"*16), ":".join(["ffff"]*8))
        self.failUnlessEqual(IP6Address.fromBytes("\x00"*15+"\x01"), "::1")
        self.failUnlessEqual(IP6Address.fromBytes("\x01\x02" + "\x00"*13+"\x01"), "102::1")

    def test_ip6ToStrErr(self):
        self.failUnlessRaises(ValueError, IP6Address.fromBytes, "\xff\xff\xff\x00\x01")

    def test_Roundtrips(self):
        addrs = [
            "0:9:6b:e0:ca:ce:0:1",
            "fe80::1"
        ]
        for i in addrs:
            self.failUnlessEqual(i, IP6Address.fromBytes(IP6Address(i).bytes))


class uIP6Mask(unittest.TestCase):
    def test_create(self):
        self.failUnlessEqual(IP6Mask(0), "::")
        self.failUnlessEqual(IP6Mask(128),
                                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
        self.failUnlessEqual(IP6Mask(8), "ff00::")
        self.failUnlessEqual(IP6Mask(32), "ffff:ffff::")
        self.failUnlessEqual(IP6Mask(9), "ff80::")
        self.failUnlessEqual(IP6Mask(12), "fff0::")

    def test_create_err(self):
        self.failUnlessRaises(ValueError, IP6Mask, -1)
        self.failUnlessRaises(ValueError, IP6Mask, 129)
        self.failUnlessRaises(ValueError, IP6Mask, "::1")
        self.failUnlessRaises(ValueError, IP6Mask, "ff::1:ffff")

    def test_prefix(self):
        self.failUnlessEqual(IP6Mask("::").prefix, 0)
        self.failUnlessEqual(IP6Mask("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").prefix, 128)
        self.failUnlessEqual(IP6Mask("ff00::").prefix, 8)
        self.failUnlessEqual(IP6Mask("ffff:ffff::").prefix, 32)
        self.failUnlessEqual(IP6Mask("ff80::").prefix, 9)
        self.failUnlessEqual(IP6Mask("fff0::").prefix, 12)


class uEthernetAddress(unittest.TestCase):
    def test_creation_err(self):
        self.failUnlessRaises(ValueError, EthernetAddress, "\xff"*5)
        self.failUnlessRaises(ValueError, EthernetAddress, "::fe")
        self.failUnlessRaises(ValueError, EthernetAddress, "10.0.0.1")
        self.failUnlessRaises(ValueError, EthernetAddress, ":".join(["00"]*5))
        self.failUnlessRaises(ValueError, EthernetAddress, ":".join(["00"]*7))

    def test_create(self):
        eth = ":".join(["ff"]*6)
        a = EthernetAddress(eth)
        self.failUnlessEqual(a.address, eth)
        self.failUnlessEqual(a.af, AF_LINK)

    def test_repr(self):
        eth = ":".join(["ff"]*6)
        a = Address(eth)
        repr(a)

    def test_fromBytes(self):
        self.failUnlessEqual(EthernetAddress.fromBytes("\xff"*6).address, ":".join(["ff"]*6))
        self.failUnlessEqual(EthernetAddress.fromBytes("\x0f"*6).address, ":".join(["0f"]*6))
        self.failUnlessEqual(EthernetAddress.fromBytes("\x00"*6).address, ":".join(["00"]*6))

    def test_fromBytes_err(self):
        self.failUnlessRaises(ValueError, EthernetAddress.fromBytes, "\xff"*5)
        self.failUnlessRaises(ValueError, EthernetAddress.fromBytes, "\xff"*8)

    def test_ethToBytes(self):
        self.failUnlessEqual(EthernetAddress(":".join(["ff"]*6)).bytes, "\xff"*6)
        self.failUnlessEqual(EthernetAddress(":".join(["0f"]*6)).bytes, "\x0f"*6)
        self.failUnlessEqual(EthernetAddress(":".join(["00"]*6)).bytes, "\x00"*6)

