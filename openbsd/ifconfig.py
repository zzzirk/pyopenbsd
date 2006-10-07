#    Copyright (c) 2005, Aldo Cortesi
#    Copyright (c) 2006, David Harrison
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
"""
    A Python module for querying and manipulating network interfaces.
"""
#    TODO:
#       - Wireless network operations.
#       - Groups. See "ifconfig egress", printgroup in ifconfig sources.

import pprint
import _ifconfig, _sysvar, utils
from _sysvar import *
from _global import *

def unique(lst):
    vals = {}
    for i in lst:
        vals[i] = 0
    return vals.keys()

    
class FlagVal(int):
    _flags = [
        (IFF_UP,            "UP"),
        (IFF_BROADCAST,     "BROADCAST"),
        (IFF_DEBUG,         "DEBUG"),
        (IFF_LOOPBACK,      "LOOPBACK"),
        (IFF_POINTOPOINT,   "POINTOPOINT"),
        (IFF_NOTRAILERS,    "NOTRAILERS"),
        (IFF_RUNNING,       "RUNNING"),
        (IFF_NOARP,         "NOARP"),
        (IFF_PROMISC,       "PROMISC"),
        (IFF_ALLMULTI,      "ALLMULTI"),
        (IFF_OACTIVE,       "OACTIVE"),
        (IFF_SIMPLEX,       "SIMPLEX"),
        (IFF_LINK0,         "LINK0"),
        (IFF_LINK1,         "LINK1"),
        (IFF_LINK2,         "LINK2"),
        (IFF_MULTICAST,     "MULTICAST"),
    ]
    def flagdesc(self):
        strs = []
        for i in self._flags:
            if self&i[0]:
                strs.append(i[1])
        return "|".join(strs)

    def __str__(self):
        return "%x <%s>"%(self, self.flagdesc())

class IFDescription(object):
    def __get__(self, obj, val):
        return obj._getinfo()["description"]

    def __set__(self, obj, val):
        obj._setifdescr(val)

class Flags(object):
    def __get__(self, obj, val):
        return FlagVal(obj._getinfo()["flags"])

    def __set__(self, obj, val):
        obj._setflags(val)


class MTU(object):
    def __get__(self, obj, val):
        return obj._getinfo()["mtu"]

    def __set__(self, obj, val):
        obj._setmtu(val)


class Metric(object):
    def __get__(self, obj, val):
        return obj._getinfo()["metric"]

    def __set__(self, obj, val):
        obj._setmetric(val)


class Media(object):
    """
        Class representing the media for a single interface. Interface media
        have the following attributes:

            mtype       The media type. This is static for an interface, and cannot
                        be changed. E.g. "Ethernet"

            subtype     This is the value we modify to change the media for an
                        interface. E.g. "10baseT"

            options     Every subtype has a set of options. E.g. "Full Duplex"
    """
    def __init__(self, interface):
        self._interface = interface

    def __repr__(self):
        return "media: %s %s"%(self.mtype, self.subtype)

    def _getType(self):
        return _ifconfig.getifmedia(self._interface)["current"][0]

    def _getSubType(self):
        return _ifconfig.getifmedia(self._interface)["current"][1]

    def _getOptions(self):
        return _ifconfig.getifmedia(self._interface)["current"][2]

    def _getActiveSubType(self):
        return _ifconfig.getifmedia(self._interface)["active"][1]

    def _getActiveOptions(self):
        return _ifconfig.getifmedia(self._interface)["active"][2]
    
    def getAllSubtypes(self):
        """
            Retrieve all possible subtypes for this interface.
        """
        return unique([i[1] for i in _ifconfig.getifmedia(self._interface)["options"]])

    def getAllOptions(self, subtype):
        """
            Retrieve all possible options for a given subtype.
        """
        options = []
        for i in _ifconfig.getifmedia(self._interface)["options"]:
            if i[1] == subtype:
                options.extend(i[2])
        return options

    mtype = property(_getType, None, None)
    subtype = property(_getSubType, None, None)
    options = property(_getOptions, None, None)
    active_subtype = property(_getActiveSubType, None, None)
    active_options = property(_getActiveOptions, None, None)


class Interface(object):
    """
        Each interface contains the following information:
            - Interface Flags
            - Interface Groups
            - Media information
            - A list of addresses, each with associated information.
    """
    Iftype = "unknown"
    flags = Flags()
    mtu = MTU()
    description = IFDescription()
    metric = Metric()
    _addrTypeLookup = {
        AF_INET:    "inet",
        AF_INET6:   "inet6",
        AF_LINK:    "link"
    }
    def __init__(self, name):
        self.Name = name
        try:
            _ifconfig.getifmedia(self.Name)
            self.media = Media(self.Name)
        except OException:
            self.media = None
        # We de-reference this once, so we get the Iftype
        self.getAddresses()

    def _getinfo(self):
        return _ifconfig.getifinfo(self.Name)

    def _setifdescr(self, val):
        _ifconfig.setifdescr(self.Name, val)

    def _setflags(self, val):
        _ifconfig.setifflags(self.Name, val)

    def _setmtu(self, val):
        _ifconfig.setifmtu(self.Name, val)

    def _setmetric(self, val):
        _ifconfig.setifmetric(self.Name, val)

    def getAddresses(self):
        """
            Returns a list of Address objects (IPAddress, IP6Address, or
            EthernetAddress), or, if the address type is unknown, a dictionary
            interface specification.

            Address objects have a "mask" attribute, which is an Address
            object, and "destination" attribute, which is an Address object or
            None.
        """
        addrlist = _ifconfig.getifaddrs()
        addresses = []
        for i in addrlist:
            if i["name"] == self.Name:
                d = {}
                if i["address"].has_key("iftype"):
                    # This is a link-layer address.
                    self.Iftype = i["address"]["iftype"]
                if i["address"]["address"]:
                    af = i["address"]["sa_family"]
                    del i["name"]
                    if  af == AF_INET:
                        d["address"] = utils.IPAddress.fromBytes(i["address"]["address"])
                        if i["netmask"]["address"]:
                            d["mask"] = utils.IPMask.fromBytes(i["netmask"]["address"])
                        if i.has_key("dstaddr"):
                            if i["dstaddr"]["address"]:
                                d["destination"] = utils.IPAddress.fromBytes(i["dstaddr"]["address"])
                            else:
                                d["destination"] = None
                    elif af == AF_INET6:
                        d["address"] = utils.IP6Address.fromBytes(i["address"]["address"])
                        if i["netmask"]["address"]:
                            d["mask"] = utils.IP6Mask.fromBytes(i["netmask"]["address"])
                        if i.has_key("dstaddr"):
                            if i["dstaddr"]["address"]:
                                d["destination"] = utils.IP6Address.fromBytes(i["dstaddr"]["address"])
                            else:
                                d["destination"] = None
                    elif af == AF_LINK:
                        d = {
                                "address": utils.EthernetAddress.fromBytes(i["address"]["address"])
                            }
                    else:
                        # Unidentified.
                        d = i
                    addresses.append(d)
        return addresses

    def __repr__(self):
        s = "%s: flags=%s mtu %s"%(self.Name, self.flags, self.mtu)
        addrs = [""]
        if self.description:
            addrs.append("\t description: %s"%(self.description))
        if self.media:
            addrs.append("\t media: %s %s"%(self.media.mtype, self.media.subtype))
        for i in self.getAddresses():
            atype = self._addrTypeLookup.get(i["address"].af, "unknown")
            addrs.append("\t %s: %s"%(atype, i["address"]))
        return s + "\n".join(addrs)

    def getGroups(self):
        """
            Get list of groups this interface is assigned to
        """
        return _ifconfig.getifgroups(self.Name)

    def addGroup(self, groupName):
        """
            Add an interface group to this interface
        """
        _ifconfig.setifgroup(self.Name, groupName)

    def delGroup(self, groupName):
        """
            Remove an interface group from this interface
        """
        _ifconfig.unsetifgroup(self.Name, groupName)

    def addAddress(self, address, mask=None):
        """
            Add an IP or IPv6 address to this interface. 
        """
        a = utils.Address(address)
        m = a.mask(mask)
        _ifconfig.addaddr(self.Name, a.af, a.bytes, m.bytes)

    def delAddress(self, address):
        """
            Remove an IP or IPv6 address from this interface. 
        """
        a = utils.Address(address)
        _ifconfig.deladdr(self.Name, a.af, a.bytes)

    def setAddress(self, address, mask=None):
        """
            Change an interface address.

            This function operates as follows:
                - If are existing addresses of the same type as the specified
                  address (i.e. IPv4 or IPv6), remove the first address found.
                - Then add the specified address to the interface.
        """
        a = utils.Address(address)
        m = a.mask(mask)
        for i in self.getAddresses():
            if i["address"].af == a.af:
                self.delAddress(i["address"])
                break
        self.addAddress(a, m.prefix)

    def up(self):
        """
            A convenience function that sets the "up" flag for an interface.
        """
        self.flags = self.flags | IFF_UP

    def down(self):
        """
            A convenience function that unsets the "up" flag for an interface.
        """
        self.flags = self.flags & (~IFF_UP)


class IFConfig(object):
    def _getInterfaces(self):
        interfaces = {}
        addrlist = _ifconfig.getifaddrs()
        for i in addrlist:
            if not interfaces.has_key(i["name"]):
                interfaces[i["name"]] = Interface(i["name"])
        return interfaces

    def __getitem__(self, item):
        return self.interfaces.__getitem__(item)

    def has_key(self, item):
        return self.interfaces.has_key(item)

    def keys(self):
        return self.interfaces.keys()

    def create(self, ifname):
        _ifconfig.create(ifname)

    def destroy(self, ifname):
        _ifconfig.destroy(ifname)

    def __repr__(self):
        out = []
        ifaces = self.interfaces.keys()
        ifaces.sort()
        for i in ifaces:
            out.append(repr(self.interfaces[i]))
        return "\n".join(out)

    interfaces = property(_getInterfaces, None, None)
