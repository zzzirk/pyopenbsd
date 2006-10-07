#    Copyright (c) 2003, Aldo Cortesi
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
import socket
import utils


class Options:
    """
        A dictionary for holding field options. It is essentially a cut-back
        dictionary implementation that has case-insensitive keys.  Keys are
        retained in their original form when queried with .keys() or .items().
    """
    def __init__(self, **kwargs):
        self._ndict = {}
        self._vdict = {}
        for k,v in kwargs.items():
            self._set(k, v)

    def __getitem__(self, key):
        k = key.lower()
        return self._ndict[k][1]

    def _set(self, key, value):
        """
            If 'key' already exists, but in different case, it will be
            replaced.
        """
        k = key.lower()
        self._ndict[k] = (key, value)
        self._vdict[value] = key

    def has_key(self, key):
        k = key.lower()
        return self._ndict.has_key(k)

    def keys(self):
        return [v[0] for v in self._ndict.values()]

    def values(self):
        return [v[1] for v in self._ndict.values()]

    def toStr(self, val):
        """
            Turn a value into a string.
        """
        return self._vdict.get(val, str(val))


class IntField(object):
    """
        An integer field spanning a whole number of bytes.

        If the field has a specific number of pre-defined options, they can be
        passed to the constructor as a list of (name, value) tuples. The field
        can then be manipulated as follows: 
            
                protocol.field = 1
                protocol.field = "option"
                protocol.field = protocol.field.options["option"]

        Option names are always case insensitive.
    """
    def __init__(self, frm, tlen, doc = "", options = None):
        """
            frm  : The offset in bytes from which the field begins. 
            tlen : The length of the field in bytes. 
        """
        self.frm = frm
        self.tlen = tlen
        self.options = options
        if self.options:
            self.__doc__ = "%s (%s)"%(doc, ", ".join(self.options.keys()))
        else:
            self.__doc__ = doc

    def _getConversion(self, num):
        return num

    def _setConversion(self, num):
        return num

    def __get__(self, obj, objtype):
        if not obj:
            return None
        return self._getConversion(obj._getIntField(self.frm, self.tlen))

    def __set__(self, obj, val):
        if self.options:
            if self.options.has_key(str(val)):
                val = self.options[str(val)]
        obj._setIntField(self.frm, self.tlen, self._setConversion(val))


class HOInt32Field(IntField):
    """
        A 32-bit host order integer field.

        If the field has a specific number of pre-defined options, they can be
        passed to the constructor as a list of (name, value) tuples. The field
        can then be manipulated as follows: 
            
                protocol.field = 1
                protocol.field = "option"
                protocol.field = protocol.field.options["option"]

        Option names are always case insensitive.
    """
    def __init__(self, frm, doc = "", options = None):
        """
            frm  : The offset in bytes from which the field begins. 
            tlen : The length of the field in bytes. 
        """
        IntField.__init__(self, frm, 4, doc=doc, options=options)

    def _getConversion(self, num):
        return socket.htonl(num)

    def _setConversion(self, num):
        return socket.ntohl(num)


class ByteField(object):
    """
        A binary field spanning a whole number of bytes.
    """
    def __init__(self, frm, tlen, doc=""):
        """
            frm  : The offset in bytes from which the field begins. 
            tlen : The length of the field in bytes. 
        """
        self.frm = frm
        self.tlen = tlen
        self.__doc__ = doc

    def __get__(self, obj, objtype):
        if not obj:
            return None
        return obj._getByteField(self.frm, self.tlen)

    def __set__(self, obj, val):
        obj._setByteField(self.frm, self.tlen, val)


class PaddedString(object):
    """
        A padded string. When setting a string, it is padded at the end with
        null bytes. When getting a string, null bytes are stripped off.
    """
    def __init__(self, frm, tlen, doc = ""):
        """
            frm  : The offset in bytes from which the field begins. 
            tlen : The length of the field in bytes. 
        """
        self.frm = frm
        self.tlen = tlen
        self.__doc__ = doc

    def __get__(self, obj, objtype):
        if not obj:
            return None
        ret = obj._getByteField(self.frm, self.tlen)
        return ret.split("\0")[0]

    def __set__(self, obj, val):
        val = val + "\0"*(self.tlen - len(val))
        obj._setByteField(self.frm, self.tlen, val)


class BitField(object):
    """
        A bit field that spans some non-whole fraction of bytes. 
    """
    def __init__(self, frm, bitoffset, bitlen, doc=""):
        """
            frm         : The offset from which the field begins. 
            bitoffset   : The offset of the bitfield from the byte specified by frm. 
            bitlen      : The number of bits in the field. 
        """
        self.frm = frm
        self.bitoffset = bitoffset
        self.bitlen = bitlen
        self.__doc__ = doc

    def __get__(self, obj, objtype):
        if not obj:
            return None
        return obj._getBitField(self.frm, self.bitoffset, self.bitlen)

    def __set__(self, obj, val):
        return obj._setBitField(self.frm, self.bitoffset, self.bitlen, val)


class FlagsField(BitField):
    """
        A binary field that is composed of a number of bit flags. Like
        IntFields, these fields can take an Option dictionary.

        FlagsFields can be manipulated as follows:

            p["field"] = 12
            p["field"] = "flag"
            p["field"] = p["field"] & p["field"].FlagsOptions["flag1"]
            p["field"] = ["flag1", "flag2", "flag3"]

        In the last case, the field will be set to the bitwise OR of the
        specified flags.
    """
    def __init__(self, frm, bitoffset, bitlen, doc="", options=None):
        BitField.__init__(self, frm, bitoffset, bitlen, doc)
        self.options = options
        if self.options:
            self.__doc__ = "%s (flags: %s)"%(doc, ", ".join(self.options.keys()))
        else:
            self.__doc__ = doc

    def _getConversion(self, num):
        return num

    def _setConversion(self, num):
        return num

    def __get__(self, obj, objtype):
        if not obj:
            return None
        return self._getConversion(BitField.__get__(self, obj, objtype))

    def __set__(self, obj, val):
        try:
            int(val)
        except (ValueError, TypeError):
            if self.options:
                if utils.isStringLike(val):
                    if self.options.has_key(str(val)):
                        val = self.options[str(val)]
                else:
                    cval = 0
                    for i in val:
                        cval |= self.options[str(i)]
                    val = cval
        return BitField.__set__(self, obj, self._setConversion(val))


class HOInt32FlagsField(FlagsField):
    """
        A 32-bit host order flags field.
    """
    def __init__(self, frm, doc = "", options = None):
        """
            frm  : The offset in bytes from which the field begins. 
        """
        FlagsField.__init__(self, frm, 0, 32, doc=doc, options=options)

    def _getConversion(self, num):
        return socket.htonl(num)

    def _setConversion(self, num):
        return socket.ntohl(num)


class IPAddress(object):
    """
        An IPv4 address. Examples:
            192.168.0.2
    """
    def __init__(self, frm, doc=""):
        self.frm = frm
        self.__doc__ = doc

    def __get__(self, obj, objtype):
        if not obj:
            return None
        return utils.IPAddress.fromBytes(obj._getByteField(self.frm, 4)).address

    def __set__(self, obj, val):
        bytes = utils.IPAddress(val).bytes
        obj._setByteField(self.frm, 4, bytes)


class IPAddressList(object):
    """
        A list of 4-byte IPv4 addresses.

        These descriptors are specific to IPOptions, and modify values in the
        IPOptions header. This should be refactored to give better
        encapsulation.
    """
    def __init__(self, frm, tlen, doc=""):
        self.frm, self.tlen, = frm, tlen
        if (tlen%4):
            raise ValueError, "IPAddressList must span a multiple of 4 bytes."
        self.__doc__ = doc

    def __get__(self, obj, objtype):
        if not obj:
            return None
        addrlist = []
        for i in range(self.frm, self.tlen, 4):
            addrlist.append(utils.IPAddress.fromBytes(obj._getByteField(i, 4)).address)
        return addrlist

    def __set__(self, obj, val):
        bytes = []
        for i in val:
            bytes.append(utils.IPAddress(i).bytes)
        bytes = "".join(bytes)
        obj._splice(self.frm, self.tlen, bytes)
        obj.length = len(bytes) + 3
        obj.initialise()


class IPv6Address(object):
    """
        An IPv6 address. Examples:
                ::1
                fe80::1
                1:2:3:4:5:6:7:8
    """
    def __init__(self, frm, doc=""):
        self.frm = frm
        self.__doc__ = doc

    def __get__(self, obj, objtype):
        if not obj:
            return None
        return utils.IP6Address.fromBytes(obj._getByteField(self.frm, 16)).address

    def __set__(self, obj, val):
        obj._setByteField(self.frm, 16, utils.IP6Address(val).bytes)
        

class EthernetAddress(object):
    """
        An Ethernet address.
    """
    def __init__(self, frm, doc=""):
        self.frm = frm
        self.__doc__ = doc

    def __get__(self, obj, objtype):
        if not obj:
            return None
        return utils.EthernetAddress.fromBytes(obj._getByteField(self.frm, 6)).address

    def __set__(self, obj, val):
        obj._setByteField(self.frm, 6, utils.EthernetAddress(val).bytes)


class Payload(object):
    """
        Descriptor representing the payload of a packet. It relies on the
        _getPayloadOffsets() method of the specified protocol.
        _getPayloadOffsets should return a tuple (start, len) indicating the
        current start and length of the payload section.
    """
    def __init__(self, doc=""):
        self.__doc__ = doc
    
    def __get__(self, obj, objtype):
        if not obj:
            return None
        return obj._getByteField(*obj._getPayloadOffsets())

    def __set__(self, obj, val):
        offset, datalen = obj._getPayloadOffsets()
        assert(datalen >= 0)
        assert(offset >= 0)
        obj._splice(offset, offset+datalen, val)


class DescriptorProxy(object):
    """
        This class defines a proxy for descriptors. When the object is
        accessed, it defers all calls to the "name" attribute of "obj".
    """
    def __init__(self, name, doc=""):
        self.name = name
        self.__doc__ = doc

    def __get__(self, obj, objtype):
        if not obj:
            return None
        uobj = getattr(obj, self.name)
        return uobj.__get__(obj, objtype)

    def __set__(self, obj, val):
        uobj = getattr(obj, self.name)
        return uobj.__set__(obj, val)
