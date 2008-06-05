import libpry
from openbsd.utils import *

class uUtility(libpry.AutoTree):
    def test_multiord(self):
        assert multiord("a") == 0x61
        assert multiord("") == 0
        assert multiord("aa") == 24929

    def test_multichar(self):
        assert multichar(0x61, 1) == "\x61"
        assert multichar(0x61, 2) == "\x00\x61"
        assert multichar(257, 2) == "\x01\x01"
        assert multichar(257, 4) == "\x00\x00\x01\x01"
        libpry.raises(ValueError, multichar, 257, 1)

    def test_checksumBasic(self):
        # FIXME: More unit tests here.
        tstr = "".join([chr(i) for i in range(9)])
        assert cksum16(tstr) == 60399

    def test_findLongestSubsequence(self):
        fls = findLongestSubsequence
        assert fls("ffaaaff", "a") == (2, 4)
        assert fls("ffaaaffaaaa", "a") == (7, 10)
        assert fls("ffaaaffaaa", "a") == (2, 4)
        assert fls("aaaffaaa", "a") == (0, 2)
        assert fls("aaa", "a") == (0, 2)

    def test_isStringLike(self):
        assert isStringLike("sdf")
        assert not isStringLike(2)

    def test_isNumberLike(self):
        assert isNumberLike(2)
        assert not isNumberLike("sdfs")


class uDoubleAssociation(libpry.AutoTree):
    def setUp(self):
        self.d = DoubleAssociation()

    def test_setitem(self):
        self.d["one"] = 1
        assert self.d["one"] == 1
        assert self.d[1] == "one"

    def test_initialisation(self):
        d = DoubleAssociation({"one": 1})
        assert d["one"] == 1
        assert d[1] == "one"


class uAddrBase(libpry.AutoTree):
    def test_eq(self):
        a = IPAddress("1.2.4.8")
        b = IPAddress("1.2.4.8")
        assert a == "1.2.4.8"
        assert a == b
        assert not a == "1.2.3.5"

    def test_err(self):
        a = IPAddress("1.2.4.8")
        libpry.raises(ValueError, cmp, a, "twenty")


class uIPAddress(libpry.AutoTree):
    def test_create(self):
        a = IPAddress("1.2.4.8")
        assert a.address == "1.2.4.8"
        assert a.af == AF_INET

        a = IPAddress("1.2.4.8")
        assert a.address == "1.2.4.8"
        assert a.af == AF_INET

        a = IPAddress("1.2.4.8")
        assert a.address == "1.2.4.8"
        assert a.af == AF_INET

    def test_fromBytes(self):
        assert IPAddress.fromBytes("\xff\xff\x00\x01") == "255.255.0.1"
        assert IPAddress.fromBytes("\x00\x00\x00\x00") == "0.0.0.0"

    def test_fromBytes_err(self):
        libpry.raises(  ValueError,
                                IPAddress.fromBytes,
                                "\xff\xff\xff\x00\x01")
        libpry.raises(  ValueError,
                                IPAddress.fromBytes,
                                "\x00\x00\x00")

    def test_create_err(self):
        libpry.raises(ValueError, IPAddress, "256.255.0.1")
        libpry.raises(ValueError, IPAddress, "af.255.0.1")
        libpry.raises(ValueError, IPAddress, "255.0.1")
        libpry.raises(ValueError, IPAddress, "255.0.1.1.1")

    def test_bytes(self):
        a = Address("1.2.4.8")
        assert a.bytes == '\x01\x02\x04\x08'
        assert Address("255.255.0.1").bytes == "\xff\xff\x00\x01"
        assert Address("0.0.0.0").bytes == "\x00\x00\x00\x00"

    def test_repr(self):
        a = Address("1.2.4.8")
        repr(a)


class uIPMask(libpry.AutoTree):
    def test_create(self):
        assert IPMask("255.255.0.0") == "255.255.0.0"
        assert IPMask(1) == "128.0.0.0"
        assert IPMask(0) == "0.0.0.0"
        assert IPMask(8) == "255.0.0.0"
        assert IPMask(32) == "255.255.255.255"
        assert IPMask(9) == "255.128.0.0"
        assert IPMask(12) == "255.240.0.0"

    def test_create_err(self):
        libpry.raises(ValueError, IPMask, "255.255.0.1")
        libpry.raises(ValueError, IPMask, "255.255.1.0")
        libpry.raises(ValueError, IPMask, -1)
        libpry.raises(ValueError, IPMask, 33)
        
    def test_prefix(self):
        assert IPMask("255.255.0.0").prefix == 16
        assert IPMask("0.0.0.0").prefix == 0
        assert IPMask("255.255.255.255").prefix == 32
        assert IPMask("255.128.0.0").prefix == 9
        assert IPMask("255.240.0.0").prefix == 12


class uIP6Address(libpry.AutoTree):
    def test_create(self):
        a = IP6Address("::1")
        assert a.address == "::1"
        assert a.af == AF_INET6

        a = IP6Address("::1")
        assert a.address == "::1"
        assert a.af == AF_INET6

    def test_create_err(self):
        libpry.raises(ValueError, IP6Address, "10.0.0.0")
        libpry.raises(ValueError, IP6Address, "ffx::")

    def test_repr(self):
        a = IP6Address("::fe")
        repr(a)

    def test_bytes(self):
        a = IP6Address("::1")
        assert a.bytes == '\x00'*15+'\x01'

    def test_bytes(self):
        assert IP6Address(":".join(["ffff"]*8)).bytes == "\xff"*16
        assert IP6Address("::1").bytes == "\x00"*15+"\x01"
        assert IP6Address("102::1").bytes == "\x01\x02" + "\x00"*13+"\x01"

    def test_ip6ToBytesErr(self):
        libpry.raises(ValueError, IP6Address, "0::0::1")
        libpry.raises(ValueError, IP6Address, "1:0:0:1:1:1:1:1:1")

    def test_fromBytes(self):
        assert IP6Address.fromBytes("\xff"*16) == ":".join(["ffff"]*8)
        assert IP6Address.fromBytes("\x00"*15+"\x01") == "::1"
        assert IP6Address.fromBytes("\x01\x02" + "\x00"*13+"\x01") == "102::1"

    def test_ip6ToStrErr(self):
        libpry.raises(ValueError, IP6Address.fromBytes, "\xff\xff\xff\x00\x01")

    def test_Roundtrips(self):
        addrs = [
            "0:9:6b:e0:ca:ce:0:1",
            "fe80::1"
        ]
        for i in addrs:
            assert i == IP6Address.fromBytes(IP6Address(i).bytes)


class uIP6Mask(libpry.AutoTree):
    def test_create(self):
        assert IP6Mask(0) == "::"
        assert IP6Mask(128) == "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        assert IP6Mask(8) == "ff00::"
        assert IP6Mask(32) == "ffff:ffff::"
        assert IP6Mask(9) == "ff80::"
        assert IP6Mask(12) == "fff0::"

    def test_create_err(self):
        libpry.raises(ValueError, IP6Mask, -1)
        libpry.raises(ValueError, IP6Mask, 129)
        libpry.raises(ValueError, IP6Mask, "::1")
        libpry.raises(ValueError, IP6Mask, "ff::1:ffff")

    def test_prefix(self):
        assert IP6Mask("::").prefix == 0
        assert IP6Mask("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").prefix == 128
        assert IP6Mask("ff00::").prefix == 8
        assert IP6Mask("ffff:ffff::").prefix == 32
        assert IP6Mask("ff80::").prefix == 9
        assert IP6Mask("fff0::").prefix == 12


class uEthernetAddress(libpry.AutoTree):
    def test_creation_err(self):
        libpry.raises(ValueError, EthernetAddress, "\xff"*5)
        libpry.raises(ValueError, EthernetAddress, "::fe")
        libpry.raises(ValueError, EthernetAddress, "10.0.0.1")
        libpry.raises(ValueError, EthernetAddress, ":".join(["00"]*5))
        libpry.raises(ValueError, EthernetAddress, ":".join(["00"]*7))

    def test_create(self):
        eth = ":".join(["ff"]*6)
        a = EthernetAddress(eth)
        assert a.address == eth
        assert a.af == AF_LINK

    def test_repr(self):
        eth = ":".join(["ff"]*6)
        a = Address(eth)
        repr(a)

    def test_fromBytes(self):
        assert EthernetAddress.fromBytes("\xff"*6).address == ":".join(["ff"]*6)
        assert EthernetAddress.fromBytes("\x0f"*6).address == ":".join(["0f"]*6)
        assert EthernetAddress.fromBytes("\x00"*6).address == ":".join(["00"]*6)

    def test_fromBytes_err(self):
        libpry.raises(ValueError, EthernetAddress.fromBytes, "\xff"*5)
        libpry.raises(ValueError, EthernetAddress.fromBytes, "\xff"*8)

    def test_ethToBytes(self):
        assert EthernetAddress(":".join(["ff"]*6)).bytes == "\xff"*6
        assert EthernetAddress(":".join(["0f"]*6)).bytes == "\x0f"*6
        assert EthernetAddress(":".join(["00"]*6)).bytes == "\x00"*6


tests = [
    uUtility(),
    uDoubleAssociation(),
    uAddrBase(),
    uIPAddress(),
    uIPMask(),
    uIP6Address(),
    uIP6Mask(),
    uEthernetAddress()
]

