#    Copyright (c) 2003, Nullcube Pty Ltd 
#    All rights reserved.
#
#    Redistribution and use in source and binary forms, with or without
#    modification, are permitted provided that the following conditions are met:
#
#    *   Redistributions of source code must retain the above copyright notice, this
#        list of conditions and the following disclaimer.
#    *   Redistributions in binary form must reproduce the above copyright notice,
#        this list of conditions and the following disclaimer in the documentation
#        and/or other materials provided with the distribution.
#    *   Neither the name of Nullcube nor the names of its contributors may be used to
#        endorse or promote products derived from this software without specific
#        prior written permission.
#
#    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
#    ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
#    ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
import math
from _sysvar import *


def multiord(x):
    """
        Like ord(), but takes multiple characters. I.e. calculate the
        base10 equivalent of a string considered as a set of base-256 digits.
    """
    num = 0
    scale = 1
    for i in range(len(x)-1, -1, -1):
        num = num + (ord(x[i])*scale)
        scale = scale*256
    return num


def multichar(a, width):
    """
        Like chr(), but takes a large integer that could fill many bytes,
        and returns a string. I.e. calculate the base256 equivalent string,
        from a given base10 integer.

        The return string will be padded to the left to ensure that it is of
        length "width".
    """
    chars = []
    while (a != 0):
        chars.insert(0, chr(a%256))
        a = a/256
    if len(chars) > width:
        raise ValueError, "Number too wide for width."
    ret = ["\0"]*(width-len(chars)) + chars
    return "".join(ret)


def cksum16(data):
    """
        Calculates the 16-bit CRC checksum accross data.
    """
    sum = 0
    try:
        for i in range(0, len(data), 2):
            a = ord(data[i])
            b = ord(data[i+1])
            sum = sum + ((a<<8) + b)
    except IndexError:
        sum = sum + (a<<8)
    while (sum >> 16):
        sum = (sum & 0xFFFF) + (sum >> 16)
    return (~sum & 0xFFFF)


def isStringLike(anobj):
    try:
        anobj + ''
    except:
        return 0
    else:
        return 1


def isNumberLike(s):
    try:
        s+0
    except:
        return False
    else:
        return True


def findLongestSubsequence(seq, value):
    """
        Find the longest subsequence consisting only of "value".
    """
    itr = iter(range(len(seq)))
    maxseq = (0, 0)
    for i in itr:
        if seq[i] == value:
            start = i
            for j in itr:
                if not seq[j] == value:
                    j -= 1
                    break
            if (j-start) > (maxseq[1]-maxseq[0]):
                maxseq = (start, j)
    return maxseq


class DoubleAssociation(dict):
    """
        A double-association is a broadminded dictionary - it goes both ways.
            
        The rather simple implementation below requires the keys and values to
        be two disjoint sets. That is, if a given value is both a key and a
        value in a DoubleAssociation, you get unexpected behaviour.
    """
    # FIXME:
    #   While DoubleAssociation is adequate for our use, it is not entirely complete:
    #       - Deletion should delete both associations
    #       - Other dict methods that set values (eg. setdefault) will need to be over-ridden.
    def __init__(self, idict=None):
        if idict:
            for k, v in idict.items():
                self[k] = v

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)
        dict.__setitem__(self, value, key)


#
# Manipulation of addresses
#
def getBlocks(addr):
    """
        Get the 16-bit hexadecimal blocks from a ":"-delimited address definition.
        Applicable to Ethernet and IPv6 addresses.
    """
    numstrs = addr.split(":")
    nums = []
    for i in numstrs:
        if not i:
            continue
        try:
            num = int(i, 16)
        except ValueError:
            raise ValueError, "Malformed address."
        if num > 0xffff:
            raise ValueError, "Malformed address."
        nums.append(num)
    return nums
            

class _MaskMixin(object):
    _prefTable = {
        0:   0,
        128: 1,
        192: 2,
        224: 3,
        240: 4,
        248: 5,
        252: 6,
        254: 7
    }
    def _countPrefix(self, bytes):
        num = 0
        itr = iter(bytes)
        for b in itr:
            if b == "\xff":
                num += 8
            else:
                break
        else:
            return num
        try:
            num += self._prefTable[ord(b)]
        except KeyError:
            raise ValueError, "Invalid mask."
        for b in itr:
            if not b == "\x00":
                raise ValueError, "Invalid mask."
        return num


class _AddrBase(object):
    def __eq__(self, other):
        if not isinstance(other, _AddrBase):
            other = Address(other)
        return (self.bytes == other.bytes)


class EthernetAddress(_AddrBase):
    af = AF_LINK
    def __init__(self, address):
        self.address = address
        self.bytes = self._bytes()

    @staticmethod
    def fromBytes(addr):
        if len(addr) != 6:
            raise ValueError, "Ethernet address must have 6 bytes."
        octets = []
        for i in addr:
            next = "%x"%ord(i)
            if len(next) == 1:
                next = "0"+next
            octets.append(next)
        return EthernetAddress(":".join(octets))

    def _bytes(self):
        nums = getBlocks(self.address)
        if len(nums) != 6:
            raise ValueError, "Malformed Ethernet address."
        return "".join([chr(i) for i in nums])

    def __repr__(self):
        return self.address


class _IPBase(_AddrBase):
    def __repr__(self):
        return self.address

    def _getMask(self, mask, func):
        """
            Takes a numeric mask, and a prefix function.
        """
        if mask is None:
            return self.MAXMASK
        try:
            int(mask)
            return mask
        except (TypeError, ValueError):
            return func(mask)


class IPAddress(_IPBase):
    af = AF_INET
    def __init__(self, address):
        self.address = address
        self.bytes = self._bytes()

    @staticmethod
    def fromBytes(bytes):
        """
            Converts a sequence of 4 bytes to an IPv4 address.
        """
        if len(bytes) != 4:
            raise ValueError, "IP Address must have 4 bytes."
        octets = []
        for i in bytes:
            val = ord(i)
            octets.append(str(val))
        addr = ".".join(octets)
        return IPAddress(addr)

    def _bytes(self):
        nums = self.address.split(".")
        if len(nums) != 4:
            raise ValueError, "Mal-formed IP address."
        ret = []
        for i in nums:
            num = int(i)
            if num > 255 or num < 0:
                raise ValueError, "Mal-formed IP address."
            ret.append(chr(num))
        return "".join(ret)

    def mask(self, *args, **kwargs):
        """
            Instantiate a mask object of the appropriate type.
        """
        return IPMask(*args, **kwargs)


class IPMask(IPAddress, _MaskMixin):
    def __init__(self, mask):
        if mask is None:
            mask = 32
        if isNumberLike(mask):
            mask = self._ipFromPrefix(mask)
        IPAddress.__init__(self, mask)
        self.prefix = self._countPrefix(self.bytes)

    def _bytesFromIPPrefix(self, prefix):
        """
            Produce a binary IPv4 address (netmask) from a prefix length.
        """
        if (prefix > 32) or (prefix < 0):
            raise ValueError, "Prefix must be between 0 and 32."
        addr = "\xff" * (prefix/8)
        if prefix%8:
            addr += chr((255 << (8-(prefix%8)))&255)
        addr += "\0"*(4 - len(addr))
        return addr

    def _ipFromPrefix(self, prefix):
        """
            Produce an IPv4 address (netmask) from a prefix length.
        """
        return IPMask.fromBytes(self._bytesFromIPPrefix(prefix)).address


class IP6Address(_IPBase):
    af = AF_INET6
    def __init__(self, address):
        self.address = address
        # Conformance check: raises on error.
        self.bytes = self._bytes()

    @staticmethod
    def fromBytes(addr):
        """
            Converts a standard 16-byte IPv6 address to a human-readable string.
        """
        if len(addr) != 16:
            raise ValueError, "IPv6 address must have 16 bytes: %s"%repr(addr)
        octets = []
        for i in range(8):
            octets.append(hex(multiord(addr[2*i:2*i+2]))[2:])
        start, finish = findLongestSubsequence(octets, "0")
        if finish:
            return IP6Address(":".join(octets[0:start]) + "::" + ":".join(octets[finish+1:]))
        else:
            return IP6Address(":".join(octets))

    def _bytes(self):
        """
            Converts a standard IPv6 address to 16 bytes.
        """
        abbr = self.address.count("::")
        if self.address.find("::") > -1:
            if (self.address.count("::") > 1):
                raise ValueError, "Mal-formed IPv6 address: only one :: abbreviation allowed."
            first, second = self.address.split("::")
            first = getBlocks(first)
            second = getBlocks(second)
            padlen = 8 - len(first) - len(second)
            nums = first + [0]*padlen + second
        else:
            nums = getBlocks(self.address)
        if len(nums) != 8:
            raise ValueError, "Mal-formed IPv6 address."
        return "".join([multichar(i, 2) for i in nums])

    def mask(self, *args, **kwargs):
        """
            Instantiate a mask object of the appropriate type.
        """
        return IP6Mask(*args, **kwargs)


class IP6Mask(IP6Address, _MaskMixin):
    def __init__(self, mask):
        if mask is None:
            mask = 128
        if isNumberLike(mask):
            mask = self._ip6FromPrefix(mask)
        IP6Address.__init__(self, mask)
        self.prefix = self._countPrefix(self.bytes)

    def _bytesFromIP6Prefix(self, prefix):
        """
            Produce a binary IPv6 address (netmask) from a prefix length.
        """
        if (prefix > 128) or (prefix < 0):
            raise ValueError, "Prefix must be between 0 and 128."
        addr = "\xff" * (prefix/8)
        if prefix%8:
            addr += chr((255 << (8-(prefix%8)))&255)
        addr += "\0"*(16 - len(addr))
        return addr

    def _ip6FromPrefix(self, prefix):
        """
            Produce an IPv6 address (netmask) from a prefix length.
        """
        return IP6Mask.fromBytes(self._bytesFromIP6Prefix(prefix)).address


def Address(address):
    """
        Create an address, and auto-detectint the type.
    """
    if isinstance(address, _AddrBase):
        return address
    try:
        return IPAddress(address)
    except ValueError:
        pass
    try:
        return IP6Address(address)
    except ValueError:
        pass
    try:
        return EthernetAddress(address)
    except ValueError:
        pass
    raise ValueError, "Not a valid address."


def AddressFromBytes(bytes):
    if len(bytes) == 4:
        return IPAddress.fromBytes(bytes)
    elif len(bytes) == 16:
        return IP6Address.fromBytes(bytes)
    else:
        raise ValueError, "Address not recognized."


def Mask(address):
    """
        Create a nework mask object, and auto-detecting the type.
    """
    if isinstance(address, _AddrBase):
        return address
    try:
        return IPMask(address)
    except ValueError:
        pass
    try:
        return IP6Mask(address)
    except ValueError:
        pass
    raise ValueError, "Not a valid mask."

