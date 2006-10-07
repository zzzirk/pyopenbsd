/*
	Copyright (c) 2005, 2006 Aldo Cortesi
	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	*   Redistributions of source code must retain the above copyright notice, this
		list of conditions and the following disclaimer.
	*   Redistributions in binary form must reproduce the above copyright notice,
		this list of conditions and the following disclaimer in the documentation
		and/or other materials provided with the distribution.
	*   Neither the name of Nullcube nor the names of its contributors may be used to
		endorse or promote products derived from this software without specific prior
		written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
	DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
	ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
	LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
	ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <sys/event.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <net/if_pflog.h>
#include <netinet/tcp_fsm.h>
#include <pcap.h>
#include <Python.h>

static PyMethodDef PfMethods[] = {
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

void init_sysvar(void){
    PyObject *module;
    module = Py_InitModule("_sysvar", PfMethods);

    /* From <sys/socket.h> */
    PyModule_AddIntConstant(module, "AF_UNSPEC",    (long) AF_UNSPEC);   
    PyModule_AddIntConstant(module, "AF_LOCAL",     (long) AF_LOCAL); 
    PyModule_AddIntConstant(module, "AF_INET",      (long) AF_INET);  
    PyModule_AddIntConstant(module, "AF_APPLETALK", (long) AF_APPLETALK);
    PyModule_AddIntConstant(module, "AF_ROUTE",     (long) AF_ROUTE);      
    PyModule_AddIntConstant(module, "AF_LINK",      (long) AF_LINK);
    PyModule_AddIntConstant(module, "AF_INET6",     (long) AF_INET6);       
    PyModule_AddIntConstant(module, "AF_ENCAP",     (long) AF_ENCAP);       

    /* From <net/if.h> */
    PyModule_AddIntConstant(module, "IFNAMSIZ",                 (long) IFNAMSIZ);       
    PyModule_AddIntConstant(module, "PF_RULESET_NAME_SIZE",     (long) PFLOG_RULESET_NAME_SIZE);       

    /* enc interface packet format flags */
    PyModule_AddIntConstant(module, "ENC_CONF",                 (long) M_CONF);       
    PyModule_AddIntConstant(module, "ENC_AUTH",                 (long) M_AUTH);       
    PyModule_AddIntConstant(module, "ENC_AUTH_AH",              (long) M_AUTH_AH);       

    /* State table entry modes for PF */
    PyModule_AddIntConstant(module, "TCPS_CLOSED",              (long) TCPS_CLOSED);
    PyModule_AddIntConstant(module, "TCPS_LISTEN",              (long) TCPS_LISTEN);
    PyModule_AddIntConstant(module, "TCPS_SYN_SENT",            (long) TCPS_SYN_SENT);
    PyModule_AddIntConstant(module, "TCPS_SYN_RECEIVED ",       (long) TCPS_SYN_RECEIVED );
    PyModule_AddIntConstant(module, "TCPS_ESTABLISHED",         (long) TCPS_ESTABLISHED);
    PyModule_AddIntConstant(module, "TCPS_CLOSE_WAIT",          (long) TCPS_CLOSE_WAIT);
    PyModule_AddIntConstant(module, "TCPS_FIN_WAIT_1",          (long) TCPS_FIN_WAIT_1);
    PyModule_AddIntConstant(module, "TCPS_CLOSING",             (long) TCPS_CLOSING);
    PyModule_AddIntConstant(module, "TCPS_LAST_ACK",            (long) TCPS_LAST_ACK);
    PyModule_AddIntConstant(module, "TCPS_FIN_WAIT_2",          (long) TCPS_FIN_WAIT_2);
    PyModule_AddIntConstant(module, "TCPS_TIME_WAIT",           (long) TCPS_TIME_WAIT);
    PyModule_AddIntConstant(module, "PF_TCPS_PROXY_SRC",        (long) PF_TCPS_PROXY_SRC);
    PyModule_AddIntConstant(module, "PF_TCPS_PROXY_DST",        (long) PF_TCPS_PROXY_DST);

    /* Protocols */
    PyModule_AddIntConstant(module, "IPPROTO_IP",           (long) IPPROTO_IP);
    PyModule_AddIntConstant(module, "IPPROTO_HOPOPTS",      (long) IPPROTO_HOPOPTS);
    PyModule_AddIntConstant(module, "IPPROTO_ICMP",         (long) IPPROTO_ICMP);
    PyModule_AddIntConstant(module, "IPPROTO_IGMP",         (long) IPPROTO_IGMP);
    PyModule_AddIntConstant(module, "IPPROTO_GGP",          (long) IPPROTO_GGP);
    PyModule_AddIntConstant(module, "IPPROTO_IPIP",         (long) IPPROTO_IPIP);
    PyModule_AddIntConstant(module, "IPPROTO_IPV4",         (long) IPPROTO_IPV4);
    PyModule_AddIntConstant(module, "IPPROTO_TCP",          (long) IPPROTO_TCP);
    PyModule_AddIntConstant(module, "IPPROTO_EGP",          (long) IPPROTO_EGP);
    PyModule_AddIntConstant(module, "IPPROTO_PUP",          (long) IPPROTO_PUP);
    PyModule_AddIntConstant(module, "IPPROTO_UDP",          (long) IPPROTO_UDP);
    PyModule_AddIntConstant(module, "IPPROTO_IDP",          (long) IPPROTO_IDP);
    PyModule_AddIntConstant(module, "IPPROTO_TP",           (long) IPPROTO_TP);
    PyModule_AddIntConstant(module, "IPPROTO_IPV6",         (long) IPPROTO_IPV6);
    PyModule_AddIntConstant(module, "IPPROTO_ROUTING",      (long) IPPROTO_ROUTING);
    PyModule_AddIntConstant(module, "IPPROTO_FRAGMENT",     (long) IPPROTO_FRAGMENT);
    PyModule_AddIntConstant(module, "IPPROTO_RSVP",         (long) IPPROTO_RSVP);
    PyModule_AddIntConstant(module, "IPPROTO_GRE",          (long) IPPROTO_GRE);
    PyModule_AddIntConstant(module, "IPPROTO_ESP",          (long) IPPROTO_ESP);
    PyModule_AddIntConstant(module, "IPPROTO_AH",           (long) IPPROTO_AH);
    PyModule_AddIntConstant(module, "IPPROTO_MOBILE",       (long) IPPROTO_MOBILE);
    PyModule_AddIntConstant(module, "IPPROTO_ICMPV6",       (long) IPPROTO_ICMPV6);
    PyModule_AddIntConstant(module, "IPPROTO_NONE",         (long) IPPROTO_NONE);
    PyModule_AddIntConstant(module, "IPPROTO_DSTOPTS",      (long) IPPROTO_DSTOPTS);
    PyModule_AddIntConstant(module, "IPPROTO_EON",          (long) IPPROTO_EON);
    PyModule_AddIntConstant(module, "IPPROTO_ETHERIP",      (long) IPPROTO_ETHERIP);
    PyModule_AddIntConstant(module, "IPPROTO_ENCAP",        (long) IPPROTO_ENCAP);
    PyModule_AddIntConstant(module, "IPPROTO_PIM",          (long) IPPROTO_PIM);
    PyModule_AddIntConstant(module, "IPPROTO_IPCOMP",       (long) IPPROTO_IPCOMP);
    PyModule_AddIntConstant(module, "IPPROTO_CARP",         (long) IPPROTO_CARP);
    PyModule_AddIntConstant(module, "IPPROTO_PFSYNC",       (long) IPPROTO_PFSYNC);
    PyModule_AddIntConstant(module, "IPPROTO_RAW",          (long) IPPROTO_RAW);

    /* From <net/pfvar.h> */
    /* Reasons */
    PyModule_AddIntConstant(module, "PFRES_MATCH",  (long) PFRES_MATCH);       
    PyModule_AddIntConstant(module, "PFRES_BADOFF", (long) PFRES_BADOFF);       
    PyModule_AddIntConstant(module, "PFRES_FRAG",   (long) PFRES_FRAG);       
    PyModule_AddIntConstant(module, "PFRES_SHORT",  (long) PFRES_SHORT);       
    PyModule_AddIntConstant(module, "PFRES_NORM",   (long) PFRES_NORM);       
    PyModule_AddIntConstant(module, "PFRES_MEMORY", (long) PFRES_MEMORY);       
    /* Actions */
    PyModule_AddIntConstant(module, "PFACT_PASS",               (long) PF_PASS);       
    PyModule_AddIntConstant(module, "PFACT_DROP",               (long) PF_DROP);       
    PyModule_AddIntConstant(module, "PFACT_SCRUB",              (long) PF_SCRUB);       
    PyModule_AddIntConstant(module, "PFACT_NAT",                (long) PF_NAT);       
    PyModule_AddIntConstant(module, "PFACT_NONAT",              (long) PF_NONAT);       
    PyModule_AddIntConstant(module, "PFACT_BINAT",              (long) PF_BINAT);       
    PyModule_AddIntConstant(module, "PFACT_NOBINAT",            (long) PF_NOBINAT);       
    PyModule_AddIntConstant(module, "PFACT_RDR",                (long) PF_RDR);       
    PyModule_AddIntConstant(module, "PFACT_NORDR",              (long) PF_NORDR);       
    PyModule_AddIntConstant(module, "PFACT_SYNPROXY_DROP",      (long) PF_SYNPROXY_DROP);       
    /* Directions */
    PyModule_AddIntConstant(module, "PFDIR_INOUT",              (long) PF_INOUT);       
    PyModule_AddIntConstant(module, "PFDIR_IN",                 (long) PF_IN);       
    PyModule_AddIntConstant(module, "PFDIR_OUT",                (long) PF_OUT);       
	/* pfr_table flags */
	PyModule_AddIntConstant(module, "PFR_TFLAG_PERSIST", (long) PFR_TFLAG_PERSIST);
	PyModule_AddIntConstant(module, "PFR_TFLAG_CONST", (long) PFR_TFLAG_CONST);
	PyModule_AddIntConstant(module, "PFR_TFLAG_ACTIVE", (long) PFR_TFLAG_ACTIVE);
	PyModule_AddIntConstant(module, "PFR_TFLAG_INACTIVE", (long) PFR_TFLAG_INACTIVE);
	PyModule_AddIntConstant(module, "PFR_TFLAG_REFERENCED", (long) PFR_TFLAG_REFERENCED);
	PyModule_AddIntConstant(module, "PFR_TFLAG_REFDANCHOR", (long) PFR_TFLAG_REFDANCHOR);
	PyModule_AddIntConstant(module, "PFR_TFLAG_USRMASK", (long) PFR_TFLAG_USRMASK);
	PyModule_AddIntConstant(module, "PFR_TFLAG_SETMASK", (long) PFR_TFLAG_SETMASK);
	PyModule_AddIntConstant(module, "PFR_TFLAG_ALLMASK", (long) PFR_TFLAG_ALLMASK);
	/* pfioc_table flags */
	PyModule_AddIntConstant(module, "PFR_FLAG_ATOMIC", (long) PFR_FLAG_ATOMIC);
	PyModule_AddIntConstant(module, "PFR_FLAG_DUMMY", (long) PFR_FLAG_DUMMY);
	PyModule_AddIntConstant(module, "PFR_FLAG_FEEDBACK", (long) PFR_FLAG_FEEDBACK);
	PyModule_AddIntConstant(module, "PFR_FLAG_CLSTATS", (long) PFR_FLAG_CLSTATS);
	PyModule_AddIntConstant(module, "PFR_FLAG_ADDRSTOO", (long) PFR_FLAG_ADDRSTOO);
	PyModule_AddIntConstant(module, "PFR_FLAG_REPLACE", (long) PFR_FLAG_REPLACE);
	PyModule_AddIntConstant(module, "PFR_FLAG_ALLRSETS", (long) PFR_FLAG_ALLRSETS);
	PyModule_AddIntConstant(module, "PFR_FLAG_ALLMASK", (long) PFR_FLAG_ALLMASK);
    /* BPF Data Link Types */
    PyModule_AddIntConstant(module, "DLT_NULL",         (long) DLT_NULL);
    PyModule_AddIntConstant(module, "DLT_EN10MB",       (long) DLT_EN10MB);
    PyModule_AddIntConstant(module, "DLT_EN3MB",        (long) DLT_EN3MB);
    PyModule_AddIntConstant(module, "DLT_AX25",         (long) DLT_AX25);
    PyModule_AddIntConstant(module, "DLT_PRONET",       (long) DLT_PRONET);
    PyModule_AddIntConstant(module, "DLT_CHAOS",        (long) DLT_CHAOS);
    PyModule_AddIntConstant(module, "DLT_IEEE802",      (long) DLT_IEEE802);
    PyModule_AddIntConstant(module, "DLT_ARCNET",       (long) DLT_ARCNET);
    PyModule_AddIntConstant(module, "DLT_SLIP",         (long) DLT_SLIP);
    PyModule_AddIntConstant(module, "DLT_PPP",          (long) DLT_PPP);
    PyModule_AddIntConstant(module, "DLT_FDDI",         (long) DLT_FDDI);
    PyModule_AddIntConstant(module, "DLT_ATM_RFC1483",  (long) DLT_ATM_RFC1483);
    PyModule_AddIntConstant(module, "DLT_LOOP",         (long) DLT_LOOP);
    PyModule_AddIntConstant(module, "DLT_ENC",          (long) DLT_ENC);
    PyModule_AddIntConstant(module, "DLT_RAW",          (long) DLT_RAW);
    PyModule_AddIntConstant(module, "DLT_SLIP_BSDOS",   (long) DLT_SLIP_BSDOS);
    PyModule_AddIntConstant(module, "DLT_PPP_BSDOS",    (long) DLT_PPP_BSDOS);
    PyModule_AddIntConstant(module, "DLT_OLD_PFLOG",    (long) DLT_OLD_PFLOG);
    PyModule_AddIntConstant(module, "DLT_PFSYNC",       (long) DLT_PFSYNC);
    PyModule_AddIntConstant(module, "DLT_IEEE802_11",   (long) DLT_IEEE802_11);
    PyModule_AddIntConstant(module, "DLT_PFLOG",        (long) DLT_PFLOG);

	/* kqueue */
    /* Filters */
    PyModule_AddIntConstant(module, "EVFILT_READ",              (long) EVFILT_READ);       
    PyModule_AddIntConstant(module, "EVFILT_WRITE",             (long) EVFILT_WRITE);       
    /*PyModule_AddIntConstant(module, "EVFILT_AIO",               (long) EVFILT_AIO);*/
    PyModule_AddIntConstant(module, "EVFILT_VNODE",             (long) EVFILT_VNODE);       
    PyModule_AddIntConstant(module, "EVFILT_PROC",              (long) EVFILT_PROC);       
    PyModule_AddIntConstant(module, "EVFILT_SIGNAL",            (long) EVFILT_SIGNAL);       
    /* Flags */
    PyModule_AddIntConstant(module, "EV_ADD",                   (long) EV_ADD);       
    PyModule_AddIntConstant(module, "EV_ENABLE",                (long) EV_ENABLE);       
    PyModule_AddIntConstant(module, "EV_DISABLE",               (long) EV_DISABLE);       
    PyModule_AddIntConstant(module, "EV_DELETE",                (long) EV_DELETE);       
    PyModule_AddIntConstant(module, "EV_ONESHOT",               (long) EV_ONESHOT);       
    PyModule_AddIntConstant(module, "EV_CLEAR",                 (long) EV_CLEAR);       
    PyModule_AddIntConstant(module, "EV_EOF",                   (long) EV_EOF);       
    PyModule_AddIntConstant(module, "EV_ERROR",                 (long) EV_ERROR);       
    /* Notes */
    PyModule_AddIntConstant(module, "NOTE_LOWAT",               (long) NOTE_LOWAT);       
    PyModule_AddIntConstant(module, "NOTE_EOF",                 (long) NOTE_EOF);       
    PyModule_AddIntConstant(module, "NOTE_DELETE",              (long) NOTE_DELETE);       
    PyModule_AddIntConstant(module, "NOTE_WRITE",               (long) NOTE_WRITE);       
    PyModule_AddIntConstant(module, "NOTE_EXTEND",              (long) NOTE_EXTEND);       
    PyModule_AddIntConstant(module, "NOTE_ATTRIB",              (long) NOTE_ATTRIB);       
    PyModule_AddIntConstant(module, "NOTE_LINK",                (long) NOTE_LINK);       
    PyModule_AddIntConstant(module, "NOTE_RENAME",              (long) NOTE_RENAME);       
    PyModule_AddIntConstant(module, "NOTE_REVOKE",              (long) NOTE_REVOKE);       
    PyModule_AddIntConstant(module, "NOTE_TRUNCATE",            (long) NOTE_TRUNCATE);       
    PyModule_AddIntConstant(module, "NOTE_EXIT",                (long) NOTE_EXIT);       
    PyModule_AddIntConstant(module, "NOTE_FORK",                (long) NOTE_FORK);       
    PyModule_AddIntConstant(module, "NOTE_EXEC",                (long) NOTE_EXEC);       
    PyModule_AddIntConstant(module, "NOTE_PCTRLMASK",           (long) NOTE_PCTRLMASK);       
    PyModule_AddIntConstant(module, "NOTE_PDATAMASK",           (long) NOTE_PDATAMASK);       
    PyModule_AddIntConstant(module, "NOTE_TRACK",               (long) NOTE_TRACK);       
    PyModule_AddIntConstant(module, "NOTE_TRACKERR",            (long) NOTE_TRACKERR);       
    PyModule_AddIntConstant(module, "NOTE_CHILD",               (long) NOTE_CHILD);       

	/* ifconfig */
	PyModule_AddIntConstant(module, "IFF_UP",           (long) IFF_UP);
	PyModule_AddIntConstant(module, "IFF_BROADCAST",    (long) IFF_BROADCAST);
	PyModule_AddIntConstant(module, "IFF_DEBUG",        (long) IFF_DEBUG);
	PyModule_AddIntConstant(module, "IFF_LOOPBACK",     (long) IFF_LOOPBACK);
	PyModule_AddIntConstant(module, "IFF_POINTOPOINT",  (long) IFF_POINTOPOINT);
	PyModule_AddIntConstant(module, "IFF_NOTRAILERS",   (long) IFF_NOTRAILERS);
	PyModule_AddIntConstant(module, "IFF_RUNNING",      (long) IFF_RUNNING);
	PyModule_AddIntConstant(module, "IFF_NOARP",        (long) IFF_NOARP);
	PyModule_AddIntConstant(module, "IFF_PROMISC",      (long) IFF_PROMISC);
	PyModule_AddIntConstant(module, "IFF_ALLMULTI",     (long) IFF_ALLMULTI);
	PyModule_AddIntConstant(module, "IFF_OACTIVE",      (long) IFF_OACTIVE);
	PyModule_AddIntConstant(module, "IFF_SIMPLEX",      (long) IFF_SIMPLEX);
	PyModule_AddIntConstant(module, "IFF_LINK0",        (long) IFF_LINK0);
	PyModule_AddIntConstant(module, "IFF_LINK1",        (long) IFF_LINK1);
	PyModule_AddIntConstant(module, "IFF_LINK2",        (long) IFF_LINK2);
	PyModule_AddIntConstant(module, "IFF_MULTICAST",    (long) IFF_MULTICAST);
}
