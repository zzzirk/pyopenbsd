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
"""
    This module makes a large number of OpenBSD network statistics available
    for use from Python. Most of the information made available here is read
    directly from kernel data structures using the kernel memory interface
    (kvm(3)).
"""
import _netstat
from _global import *

#    TODO:
#        - Per-interface IPv6 statistics. 
#        - ICMPv6 statistics
#        - Route inspection (should this be in "route"?).
#        - Unix domain sockets?
#        - Unit tests probably need to be expanded.

class Netstat:
    def __init__(self):
        _netstat.initialise()

    def close(self):
        _netstat.finalise()

    def ahstats(self):
        """
            See <netinet/ip_ah.h>
        """
        return _netstat.ahstats()

    def espstats(self):
        """
            See <netinet/ip_esp.h>
        """
        return _netstat.espstats()


    def icmpstats(self):
        """
            See <netinet/icmp_var.h>
        """
        return _netstat.icmpstats()

    def ifstats(self):
        """
            A dictionary of interface names, and values. The values are
            dictionaries with the following values:
                See <net/if_var.h>
        """
        return _netstat.ifstats()

    def igmpstats(self):
        """
            See <netinet/igmp_var.h>
        """
        return _netstat.igmpstats()

    def ip6stats(self):
        """
            See <netinet6/ip6_var.h>
        """
        return _netstat.ip6stats()

    def ipcompstats(self):
        """
            See <netinet/ip_ipcomp.h>
        """
        return _netstat.ipcompstats()

    def ipipstats(self):
        """
            See <netinet/ip_ipip.h>
        """
        return _netstat.ipipstats()

    def ipstats(self):
        """
            See <netinet/ip_var.h>
        """
        return _netstat.ipstats()

    def tcpstats(self):
        """
            See <netinet/tcp_var.h>
        """
        return _netstat.tcpstats()

    def udpstats(self):
        """
            See <netinet/udp_var.h>
        """
        return _netstat.udpstats()
