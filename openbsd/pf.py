#    Copyright (c) 2005, Aldo Cortesi
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

# TODO
# 
# - Various parts of the API need to be able to take multiple arguments. I.e.
# Table.addAddress needs to become Table.addAddresses
# - Create forward iterators to traverse the PF anchor tree

import _pf, utils
from _sysvar import *
from _global import *
import socket, datetime

class Table(object):
    def __init__(self, anchor, name, flags):
        self.anchor, self.name, self.flags = anchor, name, flags

    def addAddress(self, address, mask = None, dummy = 0):
        """
            Add an address or network to the table. IP and IPv6 are supported.
            Networks are specified by passing a numeric mask specification.
        """
        iflags = 0
        if dummy:
            iflags |= PFR_FLAG_DUMMY
        address = utils.Address(address)
        mask = address.mask(mask)
        if not _pf.add_address(self.anchor, self.name, address.bytes, address.af, mask.prefix, iflags):
            raise OException, "Could not add addresss."

    def getAddresses(self):
        addrs = []
        for i in _pf.get_addresses(self.anchor, self.name):
            address = utils.AddressFromBytes(i["address"])
            addrs.append({
                "address": address,
                "mask": address.mask(i["mask"])
            })
        return addrs

    def deleteAddress(self, address, mask = None, dummy = 0):
        iflags = 0
        if dummy:
            iflags |= PFR_FLAG_DUMMY
        address = utils.Address(address)
        mask = address.mask(mask)
        if not _pf.delete_address(self.anchor, self.name, address.bytes, address.af, mask.prefix, iflags):
            raise OException, "Could not delete addresss."

    def __repr__(self):
        attrs = []
        if (self.flags & PFR_TFLAG_PERSIST):
            attrs.append("PERSIST")
        if (self.flags & PFR_TFLAG_CONST):
            attrs.append("CONST")
        if (self.flags & PFR_TFLAG_ACTIVE):
            attrs.append("ACTIVE")
        if (self.flags & PFR_TFLAG_INACTIVE):
            attrs.append("INACTIVE")
        if (self.flags & PFR_TFLAG_REFERENCED):
            attrs.append("REFERENCED")
        return "table %s: %s"%(self.name, "|".join(attrs))
    

class Tables(object):
    def __init__(self, anchor):
        self.anchor = anchor

    def add(self, name, persist = 0, const = 0, dummy = 0):
        tflags = iflags = 0
        if persist:
            tflags |= PFR_TFLAG_PERSIST
        if const:
            tflags |= PFR_TFLAG_CONST
        if dummy:
            iflags |= PFR_FLAG_DUMMY
        if not _pf.add_table(name, self.anchor, tflags, iflags):
            raise OException, "Could not add table."

    def delete(self, name,  dummy = 0):
        iflags = 0
        if dummy:
            iflags |= PFR_FLAG_DUMMY
        if not _pf.delete_table(name, self.anchor, 0, iflags):
            raise OException, "Could not delete table."

    def clear(self, dummy = 0):
        """
            Remove all tables. Return the number of tables deleted.
        """
        iflags = 0
        if dummy:
            iflags |= PFR_FLAG_DUMMY
        return _pf.clear_tables(self.anchor, iflags)

    def keys(self):
        return _pf.get_tables(self.anchor).keys()

    def has_key(self, key):
        return _pf.get_tables(self.anchor).has_key(key)

    def __getitem__(self, key):
        try:
            t = _pf.get_tables(self.anchor)[key]
        except KeyError:
            raise OException, "Table does not exist."
        return Table(self.anchor, key, t)

    def __len__(self):
        return len(_pf.get_tables(self.anchor))

    def __str__(self):
        return "tables %s: %s"%(self.anchor, ", ".join(self.keys()))


class State(object):
    _protos = {
        IPPROTO_TCP:    "tcp",
        IPPROTO_UDP:    "udp",
        IPPROTO_ICMP:   "icmp"
    }
    def __init__(self, pf, attrs):
        self.pf = pf
        attrs["ext"]["address"] = utils.AddressFromBytes(attrs["ext"]["address"])
        attrs["lan"]["address"] = utils.AddressFromBytes(attrs["lan"]["address"])
        attrs["gwy"]["address"] = utils.AddressFromBytes(attrs["gwy"]["address"])
        attrs["packets"] = {
            "out": attrs["packets"][0],
            "in": attrs["packets"][1]
        }
        attrs["bytes"] = {
            "out": attrs["bytes"][0],
            "in": attrs["bytes"][1]
        }
        # See pf_print_state.c in pfctl
        if attrs["direction"] != PFDIR_OUT:
            (attrs.src, attrs.dst) = (attrs.dst, attrs.src)
        self.__dict__.update(attrs)

    def __repr__(self):
        return "%s %s %s:%s -> %s:%s -> %s:%s"%(
            self.ifname,
            self._protos.get(self.proto, "unknown"),
            self.lan["address"], self.lan["port"],
            self.gwy["address"], self.gwy["port"],
            self.ext["address"], self.ext["port"],
        )


class Anchor(object):
    def __init__(self, pf, name = ""):
        self.pf = pf
        self.name = name
        self.tables = Tables(name)

    def __repr__(self):
        return "Anchor(%s)"%self.name

    # Container methods
    def __getitem__(self, name):
        if self.name:
            n = "%s/%s"%(self.name, name)
        else:
            n = name
        return Anchor(self.pf, n)

    def __len__(self):
        return len(_pf.get_anchors(self.name))

    def keys(self):
        return _pf.get_anchors(self.name)

    def has_key(self, key):
        return (key in _pf.get_anchors(self.name))

    def items(self):
        return [Anchor(self.pf, i) for i in self.keys()]


def _dirmaker(dct, value, *args):
    s = dct
    for i in args[:-1]:
        s = s.setdefault(i, {})
    s[args[len(args)-1]] = value


def _flatTreeWalker(*labels):
    """
        This generator takes a multi-dimensional specification represented as a
        list of lists, and "walks" all the discrete paths to end-nodes.
    """
    place = [0 for i in labels]
    while 1:
        yield [j[i] for (i, j) in zip(place, labels)]
        for i in range(len(place) - 1, -1, -1):
            if place[i] == (len(labels[i]) - 1):
                place[i] = 0
            else:
                place[i] += 1
                break
        if place == [0 for i in labels]:
            return


def _makeTree(values, *labels):
    """
        Take a multi-dimensional array "flattened" by a depth-first traversal,
        and a multi-dimensional table specification in the form of a list of
        labels.  Generate a matching nested dictionary structure.
    """
    dct = {}
    for i, labs in enumerate(_flatTreeWalker(*labels)):
        _dirmaker(dct, values[i], *labs)
    return dct
            
    
class PF(Anchor):
    """
        The top-level PF class is an extension of the root Anchor object.
    """
    def __init__(self):
        Anchor.__init__(self, self)
        _pf._init()

    def running(self):
        return self.getStatistics()["running"]

    def start(self):
        return _pf.start()

    def stop(self):
        return _pf.stop()

    def startALTQ(self):
        return _pf.start_altq()

    def stopALTQ(self):
        return _pf.stop_altq()

    def getInterfaces(self):
        data = _pf.get_ifaces()
        for i in data.values():
            tdict = {}
            i["tzero"] = datetime.datetime.fromtimestamp(i["tzero"])
            i["trafinfo"] = _makeTree(
                                    i["trafinfo"],
                                    ["ipv4", "ipv6"],
                                    ["in", "out"],
                                    ["pass", "blocK"],
                                    ["packets", "bytes"]
                                )
        return data

    def setLogInterface(self, ifname):
        return _pf.set_log_iface(ifname)

    def getStatistics(self):
        x = _pf.get_stats()
        x["packets"] = _makeTree(
                                    x["packets"],
                                    ["ipv4", "ipv6"],
                                    ["in", "out"],
                                    ["pass", "block", "unknown"],
                                )
        x["bytes"] = _makeTree(
                                    x["bytes"],
                                    ["ipv4", "ipv6"],
                                    ["in", "out"],
                                )
        return x

    def clearStatistics(self):
        return _pf.clear_stats()

    def getStates(self):
        states = []
        for i in _pf.get_states():
            states.append(State(self, i))
        return states

    def clearStates(self, interface = None):
        return _pf.clear_states(interface)

    # FIXME: This function could be made more sophisticated, using port
    # matching operators.
    def killStates(self,
            interface = None,
            src = None,
            srcmask = None,
            dst = None,
            dstmask = None,
            srcport = 0,
            dstport = 0,
        ):
        if src:
            src = utils.Address(src).bytes
        if srcmask:
            srcmask = utils.Mask(srcmask).bytes
        if dst:
            dst = utils.Address(dst).bytes
        if dstmask:
            dstmask = utils.Mask(dstmask).bytes
        if src and (not srcmask):
            srcmask = "\xff"*len(src)
        if dst and (not dstmask):
            dstmask = "\xff"*len(dst)
        if src and (len(src) != len(srcmask)):
            raise ValueError, "Address and mask must be of same type."
        if dst and (len(dst) != len(dstmask)):
            raise ValueError, "Address and mask must be of same type."
        if (dst and src) and (len(dst) != len(src)):
            raise ValueError, "All addresses must be of same type."
        if not (src or dst):
            af = 0
        else:
            if (len(src or dst)) == 4:
                af = AF_INET
            else:
                af = AF_INET6
        return _pf.kill_states(af, interface, src, srcmask, dst, dstmask, srcport, dstport)

    def __repr__(self):
        if self.running():
            r = "enabled"
        else:
            r = "disabled"
        return "PF - %s"%(r)
