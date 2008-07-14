/*
	Copyright (c) 2003, 2006 Aldo Cortesi
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

#include <fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>
#include <sys/timeout.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <netinet/igmp.h>
#include <netinet/igmp_var.h>
#include <netinet/ip_ah.h>
#include <netinet/ip_esp.h>
#include <netinet/ip_ipip.h>
#include <netinet/ip_ipcomp.h>
#include <kvm.h>
#include <Python.h>

#include "_kvm.h"
#include "_cutils.h"

static struct nlist nl[] = {
#define N_IFNET			0
	{ "_ifnet" },
#define N_IPSTAT		1
	{ "_ipstat" },
#define N_TCPSTAT		2
	{ "_tcpstat" },
#define N_UDPSTAT		3
	{ "_udpstat" },
#define N_ICMPSTAT		4
	{ "_icmpstat" },
#define N_IGMPSTAT		5
	{ "_igmpstat" },
#define N_AHSTAT		6
	{ "_ahstat" },
#define N_ESPSTAT		7
	{ "_espstat" },
#define N_IPIPSTAT		8
	{ "_ipipstat" },
#define N_IPCOMPSTAT	9
	{ "_ipcompstat" },
#define N_IP6STAT	    10
	{ "_ip6stat" },
	{ NULL }
};

int addULongLong(PyObject *dict, char *name, unsigned long long val){
	PyObject *uval;

	uval = PyLong_FromUnsignedLongLong(val);
	if (!uval) return 0;
	if (stealingSetItem(dict, name, uval)) return 0;
	return 1;
};


/*
 * See include/netinet/ip_var.h
 */
PyObject *ipstats(PyObject *self, PyObject *args){
	struct ipstat ips;
	PyObject *retdict;
	if (kread(nl[N_IPSTAT].n_value, (char *)&ips, sizeof ips)){
		return NULL;
	}
	retdict = PyDict_New();
	if (retdict == NULL)
		return NULL;
	if (!addULongLong(retdict, "total",		  (unsigned long long)ips.ips_total))		 return NULL;
	if (!addULongLong(retdict, "badsum",	  (unsigned long long)ips.ips_badsum))		 return NULL;
	if (!addULongLong(retdict, "tooshort",	  (unsigned long long)ips.ips_tooshort))	 return NULL;
	if (!addULongLong(retdict, "toosmall",	  (unsigned long long)ips.ips_toosmall))	 return NULL;
	if (!addULongLong(retdict, "badhlen",	  (unsigned long long)ips.ips_badhlen))		 return NULL;
	if (!addULongLong(retdict, "badlen",	  (unsigned long long)ips.ips_badlen))		 return NULL;
	if (!addULongLong(retdict, "fragments",   (unsigned long long)ips.ips_fragments))	 return NULL;
	if (!addULongLong(retdict, "fragdropped", (unsigned long long)ips.ips_fragdropped))  return NULL;
	if (!addULongLong(retdict, "fragtimeout", (unsigned long long)ips.ips_fragtimeout))  return NULL;
	if (!addULongLong(retdict, "forward",	  (unsigned long long)ips.ips_forward))		 return NULL;
	if (!addULongLong(retdict, "cantforward", (unsigned long long)ips.ips_cantforward))  return NULL;
	if (!addULongLong(retdict, "redirectsent",(unsigned long long)ips.ips_redirectsent)) return NULL;
	if (!addULongLong(retdict, "noproto",	  (unsigned long long)ips.ips_noproto))		 return NULL;
	if (!addULongLong(retdict, "delivered",   (unsigned long long)ips.ips_delivered))	 return NULL;
	if (!addULongLong(retdict, "localout",	  (unsigned long long)ips.ips_localout))	 return NULL;
	if (!addULongLong(retdict, "odropped",	  (unsigned long long)ips.ips_odropped))	 return NULL;
	if (!addULongLong(retdict, "reassembled", (unsigned long long)ips.ips_reassembled))  return NULL;
	if (!addULongLong(retdict, "fragmented",  (unsigned long long)ips.ips_fragmented))	 return NULL;
	if (!addULongLong(retdict, "ofragments",  (unsigned long long)ips.ips_ofragments))	 return NULL;
	if (!addULongLong(retdict, "cantfrag",	  (unsigned long long)ips.ips_cantfrag))	 return NULL;
	if (!addULongLong(retdict, "badoptions",  (unsigned long long)ips.ips_badoptions))	 return NULL;
	if (!addULongLong(retdict, "noroute",	  (unsigned long long)ips.ips_noroute))		 return NULL;
	if (!addULongLong(retdict, "badvers",	  (unsigned long long)ips.ips_badvers))		 return NULL;
	if (!addULongLong(retdict, "rawout",	  (unsigned long long)ips.ips_rawout))		 return NULL;
	if (!addULongLong(retdict, "badfrags",	  (unsigned long long)ips.ips_badfrags))	 return NULL;
	if (!addULongLong(retdict, "rcvmemdrop",  (unsigned long long)ips.ips_rcvmemdrop))	 return NULL;
	if (!addULongLong(retdict, "toolong",	  (unsigned long long)ips.ips_toolong))		 return NULL;
	if (!addULongLong(retdict, "nogif",		  (unsigned long long)ips.ips_nogif))		 return NULL;
	if (!addULongLong(retdict, "badaddr",	  (unsigned long long)ips.ips_badaddr))		 return NULL;
	if (!addULongLong(retdict, "inhwcsum",	  (unsigned long long)ips.ips_inhwcsum))	 return NULL;
	if (!addULongLong(retdict, "outhwcsum",   (unsigned long long)ips.ips_outhwcsum))	 return NULL;
	return retdict;
}

/*
 * See include/netinet6/ip6_var.h
 */
PyObject *ip6stats(PyObject *self, PyObject *args){
	struct ip6stat ip6s;
	PyObject *retdict;
	if (kread(nl[N_IP6STAT].n_value, (char *)&ip6s, sizeof ip6s)){
		return NULL;
	}
	retdict = PyDict_New();
	if (retdict == NULL)
		return NULL;
    if (!addULongLong(retdict, "total",         (unsigned long long)ip6s.ip6s_total))           return NULL;
    if (!addULongLong(retdict, "tooshort",      (unsigned long long)ip6s.ip6s_tooshort))        return NULL;
    if (!addULongLong(retdict, "toosmall",      (unsigned long long)ip6s.ip6s_toosmall))        return NULL;
    if (!addULongLong(retdict, "toosmall",      (unsigned long long)ip6s.ip6s_toosmall))        return NULL;
    if (!addULongLong(retdict, "fragments",     (unsigned long long)ip6s.ip6s_fragments))       return NULL;
    if (!addULongLong(retdict, "fragdropped",   (unsigned long long)ip6s.ip6s_fragdropped))     return NULL;
    if (!addULongLong(retdict, "fragtimeout",   (unsigned long long)ip6s.ip6s_fragtimeout))     return NULL;
    if (!addULongLong(retdict, "fragoverflow",  (unsigned long long)ip6s.ip6s_fragoverflow))    return NULL;
    if (!addULongLong(retdict, "forward",       (unsigned long long)ip6s.ip6s_forward))         return NULL;
    if (!addULongLong(retdict, "cantforward",   (unsigned long long)ip6s.ip6s_cantforward))     return NULL;
    if (!addULongLong(retdict, "redirectsent",  (unsigned long long)ip6s.ip6s_redirectsent))    return NULL;
    if (!addULongLong(retdict, "delivered",     (unsigned long long)ip6s.ip6s_delivered))       return NULL;
    if (!addULongLong(retdict, "localout",      (unsigned long long)ip6s.ip6s_localout))        return NULL;
    if (!addULongLong(retdict, "odropped",      (unsigned long long)ip6s.ip6s_odropped))        return NULL;
    if (!addULongLong(retdict, "reassembled",   (unsigned long long)ip6s.ip6s_reassembled))     return NULL;
    if (!addULongLong(retdict, "fragmented",    (unsigned long long)ip6s.ip6s_fragmented))      return NULL;
    if (!addULongLong(retdict, "ofragments",    (unsigned long long)ip6s.ip6s_ofragments))      return NULL;
    if (!addULongLong(retdict, "cantfrag",      (unsigned long long)ip6s.ip6s_cantfrag))        return NULL;
    if (!addULongLong(retdict, "badoptions",    (unsigned long long)ip6s.ip6s_badoptions))      return NULL;
    if (!addULongLong(retdict, "noroute",       (unsigned long long)ip6s.ip6s_noroute))         return NULL;
    if (!addULongLong(retdict, "badvers",       (unsigned long long)ip6s.ip6s_badvers))         return NULL;
    if (!addULongLong(retdict, "rawout",        (unsigned long long)ip6s.ip6s_rawout))          return NULL;
    if (!addULongLong(retdict, "badscope",      (unsigned long long)ip6s.ip6s_badscope))        return NULL;
    if (!addULongLong(retdict, "notmember",     (unsigned long long)ip6s.ip6s_notmember))       return NULL;
    //FIXME: nxthist, an array of 256 long longs. 
    if (!addULongLong(retdict, "m1",            (unsigned long long)ip6s.ip6s_m1))              return NULL;
    //FIXME m2m, an array of 32 long longs. 
    if (!addULongLong(retdict, "mext1",         (unsigned long long)ip6s.ip6s_mext1))           return NULL;
    if (!addULongLong(retdict, "mext2m",        (unsigned long long)ip6s.ip6s_mext2m))          return NULL;
    if (!addULongLong(retdict, "exthdrtoolong", (unsigned long long)ip6s.ip6s_exthdrtoolong))   return NULL;
    if (!addULongLong(retdict, "nogif",         (unsigned long long)ip6s.ip6s_nogif))           return NULL;
    if (!addULongLong(retdict, "toomanyhdr",    (unsigned long long)ip6s.ip6s_toomanyhdr))      return NULL;
	return retdict;
}

/*
 * See include/net/if.h
 */
static PyObject *ifstats(PyObject *self, PyObject *args){
	u_long ifnetaddr;
	struct ifnet_head ifhead;	/* TAILQ_HEAD */
	struct ifnet ifnet;
	char name[IFNAMSIZ];
	char *tstr;
	PyObject *idict, *valdict, *tmp;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	ifnetaddr = nl[N_IFNET].n_value;
	/*
	 * Find the pointer to the first ifnet structure.  Replace
	 * the pointer to the TAILQ_HEAD with the actual pointer
	 * to the first list element.
	 */
	if (kread(ifnetaddr, (char *)&ifhead, sizeof ifhead)){
		return NULL;
	}
	ifnetaddr = (u_long)ifhead.tqh_first;

	idict = PyDict_New();
	if (idict == NULL)
		return NULL;
	while (ifnetaddr) {
		if (kread(ifnetaddr, (char *)&ifnet, sizeof ifnet))
			return NULL;
		bcopy(ifnet.if_xname, name, IFNAMSIZ);
		name[IFNAMSIZ - 1] = '\0';	/* sanity */
		ifnetaddr = (u_long)ifnet.if_list.tqe_next;
		valdict = PyDict_New();

		if (!addULongLong(valdict, "mtu",		(unsigned long long)ifnet.if_data.ifi_mtu))         return NULL;
		if (!addULongLong(valdict, "metric",	(unsigned long long)ifnet.if_data.ifi_metric))	    return NULL;
		if (!addULongLong(valdict, "baudrate",	(unsigned long long)ifnet.if_data.ifi_baudrate))	return NULL;
		if (!addULongLong(valdict, "ipackets",	(unsigned long long)ifnet.if_data.ifi_ipackets))    return NULL;
		if (!addULongLong(valdict, "ierrors",	(unsigned long long)ifnet.if_data.ifi_ierrors))     return NULL;
		if (!addULongLong(valdict, "opackets",	(unsigned long long)ifnet.if_data.ifi_opackets))    return NULL;
		if (!addULongLong(valdict, "oerrors",	(unsigned long long)ifnet.if_data.ifi_oerrors))     return NULL;
		if (!addULongLong(valdict, "collisions",(unsigned long long)ifnet.if_data.ifi_collisions))  return NULL;
		if (!addULongLong(valdict, "ibytes",	(unsigned long long)ifnet.if_data.ifi_ibytes))	    return NULL;
		if (!addULongLong(valdict, "obytes",	(unsigned long long)ifnet.if_data.ifi_obytes))	    return NULL;
		if (!addULongLong(valdict, "imcasts",	(unsigned long long)ifnet.if_data.ifi_imcasts))     return NULL;
		if (!addULongLong(valdict, "omcasts",	(unsigned long long)ifnet.if_data.ifi_omcasts))     return NULL;
		if (!addULongLong(valdict, "iqdrops",	(unsigned long long)ifnet.if_data.ifi_iqdrops))     return NULL;
		if (!addULongLong(valdict, "noproto",	(unsigned long long)ifnet.if_data.ifi_noproto))     return NULL;

		/* Now we extract the list of network names and addresses: */
		switch(ifnet.if_data.ifi_link_state){
			case (LINK_STATE_UNKNOWN):		tstr = "UNKNOWN"; break;
			case (LINK_STATE_DOWN):			tstr = "DOWN"; break;
			case (LINK_STATE_UP):			tstr = "UP"; break;
			case (LINK_STATE_HALF_DUPLEX):	tstr = "HALF DUPLEX"; break;
			case (LINK_STATE_FULL_DUPLEX):	tstr = "FULL DUPLEX"; break;
			default:
				PyErr_SetString(PyExc_ValueError, "Unknown interface link state.");
			    return NULL;
		}
        tmp = PyString_FromString(tstr);
        if (stealingSetItem(valdict, "link_state", tmp)){
            Py_DECREF(tmp);
			return NULL;
        }
        if (stealingSetItem(idict, name, valdict)){
            Py_DECREF(valdict);
			return NULL;
        }
	}
	return idict;
}

/*
 * See include/netinet/tcp_var.h
 */
PyObject *tcpstats(PyObject *self, PyObject *args){
	struct tcpstat tcps;
	PyObject *retdict;
	if (kread(nl[N_TCPSTAT].n_value, (char *)&tcps, sizeof tcps)){
		return NULL;
	}
	retdict = PyDict_New();
	if (retdict == NULL)
		return NULL;
	if (!addULongLong(retdict, "connattempt",	  (unsigned long long)tcps.tcps_connattempt)) return NULL;
	if (!addULongLong(retdict, "accepts",		  (unsigned long long)tcps.tcps_accepts)) return NULL;
	if (!addULongLong(retdict, "connects",		  (unsigned long long)tcps.tcps_connects)) return NULL;
	if (!addULongLong(retdict, "drops",			  (unsigned long long)tcps.tcps_drops)) return NULL;
	if (!addULongLong(retdict, "conndrops",		  (unsigned long long)tcps.tcps_conndrops)) return NULL;
	if (!addULongLong(retdict, "closed",		  (unsigned long long)tcps.tcps_closed)) return NULL;
	if (!addULongLong(retdict, "segstimed",		  (unsigned long long)tcps.tcps_segstimed)) return NULL;
	if (!addULongLong(retdict, "rttupdated",	  (unsigned long long)tcps.tcps_rttupdated)) return NULL;
	if (!addULongLong(retdict, "delack",		  (unsigned long long)tcps.tcps_delack)) return NULL;
	if (!addULongLong(retdict, "timeoutdrop",	  (unsigned long long)tcps.tcps_timeoutdrop)) return NULL;
	if (!addULongLong(retdict, "rexmttimeo",	  (unsigned long long)tcps.tcps_rexmttimeo)) return NULL;
	if (!addULongLong(retdict, "persisttimeo",	  (unsigned long long)tcps.tcps_persisttimeo)) return NULL;
	if (!addULongLong(retdict, "persistdrop",	  (unsigned long long)tcps.tcps_persistdrop)) return NULL;
	if (!addULongLong(retdict, "keeptimeo",		  (unsigned long long)tcps.tcps_keeptimeo)) return NULL;
	if (!addULongLong(retdict, "keepprobe",		  (unsigned long long)tcps.tcps_keepprobe)) return NULL;
	if (!addULongLong(retdict, "keepdrops",		  (unsigned long long)tcps.tcps_keepdrops)) return NULL;
	if (!addULongLong(retdict, "sndtotal",		  (unsigned long long)tcps.tcps_sndtotal)) return NULL;
	if (!addULongLong(retdict, "sndpack",		  (unsigned long long)tcps.tcps_sndpack)) return NULL;
	if (!addULongLong(retdict, "sndbyte",		  (unsigned long long)tcps.tcps_sndbyte)) return NULL;
	if (!addULongLong(retdict, "sndrexmitpack",   (unsigned long long)tcps.tcps_sndrexmitpack)) return NULL;
	if (!addULongLong(retdict, "sndrexmitbyte",   (unsigned long long)tcps.tcps_sndrexmitbyte)) return NULL;
	if (!addULongLong(retdict, "sndrexmitfast",   (unsigned long long)tcps.tcps_sndrexmitfast)) return NULL;
	if (!addULongLong(retdict, "sndacks",		  (unsigned long long)tcps.tcps_sndacks)) return NULL;
	if (!addULongLong(retdict, "sndprobe",		  (unsigned long long)tcps.tcps_sndprobe)) return NULL;
	if (!addULongLong(retdict, "sndurg",		  (unsigned long long)tcps.tcps_sndurg)) return NULL;
	if (!addULongLong(retdict, "sndwinup",		  (unsigned long long)tcps.tcps_sndwinup)) return NULL;
	if (!addULongLong(retdict, "sndctrl",		  (unsigned long long)tcps.tcps_sndctrl)) return NULL;
	if (!addULongLong(retdict, "rcvtotal",		  (unsigned long long)tcps.tcps_rcvtotal)) return NULL;
	if (!addULongLong(retdict, "rcvpack",		  (unsigned long long)tcps.tcps_rcvpack)) return NULL;
	if (!addULongLong(retdict, "rcvbyte",		  (unsigned long long)tcps.tcps_rcvbyte)) return NULL;
	if (!addULongLong(retdict, "rcvbadsum",		  (unsigned long long)tcps.tcps_rcvbadsum)) return NULL;
	if (!addULongLong(retdict, "rcvbadoff",		  (unsigned long long)tcps.tcps_rcvbadoff)) return NULL;
	if (!addULongLong(retdict, "rcvmemdrop",	  (unsigned long long)tcps.tcps_rcvmemdrop)) return NULL;
	if (!addULongLong(retdict, "rcvnosec",		  (unsigned long long)tcps.tcps_rcvnosec)) return NULL;
	if (!addULongLong(retdict, "rcvshort",		  (unsigned long long)tcps.tcps_rcvshort)) return NULL;
	if (!addULongLong(retdict, "rcvduppack",	  (unsigned long long)tcps.tcps_rcvduppack)) return NULL;
	if (!addULongLong(retdict, "rcvdupbyte",	  (unsigned long long)tcps.tcps_rcvdupbyte)) return NULL;
	if (!addULongLong(retdict, "rcvpartduppack",  (unsigned long long)tcps.tcps_rcvpartduppack)) return NULL;
	if (!addULongLong(retdict, "rcvpartdupbyte",  (unsigned long long)tcps.tcps_rcvpartdupbyte)) return NULL;
	if (!addULongLong(retdict, "rcvoopack",		  (unsigned long long)tcps.tcps_rcvoopack)) return NULL;
	if (!addULongLong(retdict, "rcvoobyte",		  (unsigned long long)tcps.tcps_rcvoobyte)) return NULL;
	if (!addULongLong(retdict, "rcvpackafterwin", (unsigned long long)tcps.tcps_rcvpackafterwin)) return NULL;
	if (!addULongLong(retdict, "rcvbyteafterwin", (unsigned long long)tcps.tcps_rcvbyteafterwin)) return NULL;
	if (!addULongLong(retdict, "rcvafterclose",   (unsigned long long)tcps.tcps_rcvafterclose)) return NULL;
	if (!addULongLong(retdict, "rcvwinprobe",	  (unsigned long long)tcps.tcps_rcvwinprobe)) return NULL;
	if (!addULongLong(retdict, "rcvdupack",		  (unsigned long long)tcps.tcps_rcvdupack)) return NULL;
	if (!addULongLong(retdict, "rcvacktoomuch",   (unsigned long long)tcps.tcps_rcvacktoomuch)) return NULL;
	if (!addULongLong(retdict, "rcvackpack",	  (unsigned long long)tcps.tcps_rcvackpack)) return NULL;
	if (!addULongLong(retdict, "rcvackbyte",	  (unsigned long long)tcps.tcps_rcvackbyte)) return NULL;
	if (!addULongLong(retdict, "rcvwinupd",		  (unsigned long long)tcps.tcps_rcvwinupd)) return NULL;
	if (!addULongLong(retdict, "pawsdrop",		  (unsigned long long)tcps.tcps_pawsdrop)) return NULL;
	if (!addULongLong(retdict, "predack",		  (unsigned long long)tcps.tcps_predack)) return NULL;
	if (!addULongLong(retdict, "preddat",		  (unsigned long long)tcps.tcps_preddat)) return NULL;
	if (!addULongLong(retdict, "pcbhashmiss",	  (unsigned long long)tcps.tcps_pcbhashmiss)) return NULL;
	if (!addULongLong(retdict, "noport",		  (unsigned long long)tcps.tcps_noport)) return NULL;
	if (!addULongLong(retdict, "badsyn",		  (unsigned long long)tcps.tcps_badsyn)) return NULL;
	if (!addULongLong(retdict, "rcvbadsig",		  (unsigned long long)tcps.tcps_rcvbadsig)) return NULL;
	if (!addULongLong(retdict, "rcvgoodsig",	  (unsigned long long)tcps.tcps_rcvgoodsig)) return NULL;
	if (!addULongLong(retdict, "inhwcsum",		  (unsigned long long)tcps.tcps_inhwcsum)) return NULL;
	if (!addULongLong(retdict, "outhwcsum",		  (unsigned long long)tcps.tcps_outhwcsum)) return NULL;
	if (!addULongLong(retdict, "ecn_accepts",	  (unsigned long long)tcps.tcps_ecn_accepts)) return NULL;
	if (!addULongLong(retdict, "ecn_rcvece",	  (unsigned long long)tcps.tcps_ecn_rcvece)) return NULL;
	if (!addULongLong(retdict, "ecn_rcvcwr",	  (unsigned long long)tcps.tcps_ecn_rcvcwr)) return NULL;
	if (!addULongLong(retdict, "ecn_rcvce",		  (unsigned long long)tcps.tcps_ecn_rcvce)) return NULL;
	if (!addULongLong(retdict, "ecn_sndect",	  (unsigned long long)tcps.tcps_ecn_sndect)) return NULL;
	if (!addULongLong(retdict, "ecn_sndece",	  (unsigned long long)tcps.tcps_ecn_sndece)) return NULL;
	if (!addULongLong(retdict, "ecn_sndcwr",	  (unsigned long long)tcps.tcps_ecn_sndcwr)) return NULL;
	if (!addULongLong(retdict, "cwr_ecn",		  (unsigned long long)tcps.tcps_cwr_ecn)) return NULL;
	if (!addULongLong(retdict, "cwr_frecovery",   (unsigned long long)tcps.tcps_cwr_frecovery)) return NULL;
	if (!addULongLong(retdict, "cwr_timeout",	  (unsigned long long)tcps.tcps_cwr_timeout)) return NULL;
	return retdict;
}

/*
 * See include/netinet/udp_var.h
 */
PyObject *udpstats(PyObject *self, PyObject *args){
	struct udpstat udps;
	PyObject *retdict;
	if (kread(nl[N_UDPSTAT].n_value, (char *)&udps, sizeof udps)){
		return NULL;
	}
	retdict = PyDict_New();
	if (retdict == NULL)
		return NULL;
	if (!addULongLong(retdict, "ipackets",		(unsigned long long)udps.udps_ipackets)) return NULL;
	if (!addULongLong(retdict, "hdrops",		(unsigned long long)udps.udps_hdrops)) return NULL;
	if (!addULongLong(retdict, "badsum",		(unsigned long long)udps.udps_badsum)) return NULL;
	if (!addULongLong(retdict, "nosum",			(unsigned long long)udps.udps_nosum)) return NULL;
	if (!addULongLong(retdict, "badlen",		(unsigned long long)udps.udps_badlen)) return NULL;
	if (!addULongLong(retdict, "noport",		(unsigned long long)udps.udps_noport)) return NULL;
	if (!addULongLong(retdict, "noportbcast",	(unsigned long long)udps.udps_noportbcast)) return NULL;
	if (!addULongLong(retdict, "nosec",			(unsigned long long)udps.udps_nosec)) return NULL;
	if (!addULongLong(retdict, "fullsock",		(unsigned long long)udps.udps_fullsock)) return NULL;
	if (!addULongLong(retdict, "pcbhashmiss",	(unsigned long long)udps.udps_pcbhashmiss)) return NULL;
	if (!addULongLong(retdict, "inhwcsum",		(unsigned long long)udps.udps_inhwcsum)) return NULL;
	if (!addULongLong(retdict, "opackets",		(unsigned long long)udps.udps_opackets)) return NULL;
	if (!addULongLong(retdict, "outhwcsum",		(unsigned long long)udps.udps_outhwcsum)) return NULL;
	return retdict;
}


/*
 * See include/netinet/ip_icmp.h
 */
#define ICMPNAMES_LEN 41
static	char *icmpnames[] = {
	"echoreply",
	"1",
	"2",
	"unreachable",
	"sourcequench",
	"redirect",
	"6",
	"7",
	"echo",
	"routeradvertisement",
	"routersolicitation",
	"timeexceeded",
	"parameterproblem",
	"timestamp",
	"timestampreply",
	"informationrequest",
	"informationrequestreply",
	"addressmaskrequest",
	"addressmaskreply",
	"#19",
	"#20",
	"#21",
	"#22",
	"#23",
	"#24",
	"#25",
	"#26",
	"#27",
	"#28",
	"#29",
	"traceroute",
	"data conversion error",
	"mobile host redirect",
	"IPv6 where-are-you",
	"IPv6 i-am-here",
	"mobile registration request",
	"mobile registration reply",
	"#37",
	"#38",
	"SKIP",
	"Photuris",
};

/*
 * See include/netinet/icmp_var.h
 */
PyObject *icmpstats(PyObject *self, PyObject *args){
	struct icmpstat icmps;
	int i;
	PyObject *retdict, *outhist, *inhist;
	if (kread(nl[N_ICMPSTAT].n_value, (char *)&icmps, sizeof icmps)){
		return NULL;
	}
	retdict = PyDict_New();
	if (retdict == NULL)
		return NULL;

	if (!addULongLong(retdict, "error",			(unsigned long long)icmps.icps_error)) return NULL;
	if (!addULongLong(retdict, "oldshort",		(unsigned long long)icmps.icps_oldshort)) return NULL;
	if (!addULongLong(retdict, "oldicmp",		(unsigned long long)icmps.icps_oldicmp)) return NULL;
	if (!addULongLong(retdict, "badcode",		(unsigned long long)icmps.icps_badcode)) return NULL;
	if (!addULongLong(retdict, "tooshort",		(unsigned long long)icmps.icps_tooshort)) return NULL;
	if (!addULongLong(retdict, "checksum",		(unsigned long long)icmps.icps_checksum)) return NULL;
	if (!addULongLong(retdict, "badlen",		(unsigned long long)icmps.icps_badlen)) return NULL;
	if (!addULongLong(retdict, "reflect",		(unsigned long long)icmps.icps_reflect)) return NULL;
	if (!addULongLong(retdict, "bmcastecho",	(unsigned long long)icmps.icps_bmcastecho)) return NULL;

	inhist = PyDict_New();
	if (inhist == NULL)
		return NULL;
	for (i = 0; i < ICMPNAMES_LEN; i++){
		if (!addULongLong(inhist, icmpnames[i], (unsigned long long)icmps.icps_inhist[i])) 
			return NULL;
	}
	if (stealingSetItem(retdict, "inhist", inhist)) return NULL;

	outhist = PyDict_New();
	if (outhist == NULL)
		return NULL;
	for (i = 0; i < ICMPNAMES_LEN; i++){
		if (!addULongLong(outhist, icmpnames[i], (unsigned long long)icmps.icps_outhist[i])) 
			return NULL;
	}
	if (stealingSetItem(retdict, "outhist", outhist)) return NULL;
	return retdict;
}


/*
 * See include/netinet/igmp_var.h
 */
PyObject *igmpstats(PyObject *self, PyObject *args){
	struct igmpstat igmps;
	PyObject *retdict;

	if (kread(nl[N_IGMPSTAT].n_value, (char *)&igmps, sizeof igmps)){
		return NULL;
	}

	retdict = PyDict_New();
	if (retdict == NULL)
		return NULL;

	if (!addULongLong(retdict, "rcv_total",			(unsigned long long)igmps.igps_rcv_total)) return NULL;
	if (!addULongLong(retdict, "rcv_tooshort",		(unsigned long long)igmps.igps_rcv_tooshort)) return NULL;
	if (!addULongLong(retdict, "rcv_badsum",		(unsigned long long)igmps.igps_rcv_badsum)) return NULL;
	if (!addULongLong(retdict, "rcv_queries",		(unsigned long long)igmps.igps_rcv_queries)) return NULL;
	if (!addULongLong(retdict, "rcv_badqueries",	(unsigned long long)igmps.igps_rcv_badqueries)) return NULL;
	if (!addULongLong(retdict, "rcv_reports",		(unsigned long long)igmps.igps_rcv_reports)) return NULL;
	if (!addULongLong(retdict, "rcv_badreports",	(unsigned long long)igmps.igps_rcv_badreports)) return NULL;
	if (!addULongLong(retdict, "rcv_ourreports",	(unsigned long long)igmps.igps_rcv_ourreports)) return NULL;
	if (!addULongLong(retdict, "snd_reports",		(unsigned long long)igmps.igps_snd_reports)) return NULL;
	return retdict;
}

/*
 * See include/netinet/ip_ah.h
 */
PyObject *ahstats(PyObject *self, PyObject *args){
	struct ahstat ahs;
	PyObject *retdict;

	if (kread(nl[N_AHSTAT].n_value, (char *)&ahs, sizeof ahs)){
		return NULL;
	}

	retdict = PyDict_New();
	if (retdict == NULL)
		return NULL;

	if (!addULongLong(retdict, "hdrops",		(unsigned long long)ahs.ahs_hdrops)) return NULL;
	if (!addULongLong(retdict, "nopf",			(unsigned long long)ahs.ahs_nopf)) return NULL;
	if (!addULongLong(retdict, "notdb",			(unsigned long long)ahs.ahs_notdb)) return NULL;
	if (!addULongLong(retdict, "badkcr",		(unsigned long long)ahs.ahs_badkcr)) return NULL;
	if (!addULongLong(retdict, "badauth",		(unsigned long long)ahs.ahs_badauth)) return NULL;
	if (!addULongLong(retdict, "noxform",		(unsigned long long)ahs.ahs_noxform)) return NULL;
	if (!addULongLong(retdict, "qfull",			(unsigned long long)ahs.ahs_qfull)) return NULL;
	if (!addULongLong(retdict, "wrap",			(unsigned long long)ahs.ahs_wrap)) return NULL;
	if (!addULongLong(retdict, "replay",		(unsigned long long)ahs.ahs_replay)) return NULL;
	if (!addULongLong(retdict, "badauthl",		(unsigned long long)ahs.ahs_badauthl)) return NULL;
	if (!addULongLong(retdict, "input",			(unsigned long long)ahs.ahs_input)) return NULL;
	if (!addULongLong(retdict, "output",		(unsigned long long)ahs.ahs_output)) return NULL;
	if (!addULongLong(retdict, "invalid",		(unsigned long long)ahs.ahs_invalid)) return NULL;
	if (!addULongLong(retdict, "ibytes",		(unsigned long long)ahs.ahs_ibytes)) return NULL;
	if (!addULongLong(retdict, "obytes",		(unsigned long long)ahs.ahs_obytes)) return NULL;
	if (!addULongLong(retdict, "toobig",		(unsigned long long)ahs.ahs_toobig)) return NULL;
	if (!addULongLong(retdict, "pdrops",		(unsigned long long)ahs.ahs_pdrops)) return NULL;
	if (!addULongLong(retdict, "crypto",		(unsigned long long)ahs.ahs_crypto)) return NULL;
	return retdict;
}

/*
 * See include/netinet/ip_esp.h
 */
PyObject *espstats(PyObject *self, PyObject *args){
	struct espstat esps;
	PyObject *retdict;

	if (kread(nl[N_ESPSTAT].n_value, (char *)&esps, sizeof esps)){
		return NULL;
	}

	retdict = PyDict_New();
	if (retdict == NULL)
		return NULL;

	if (!addULongLong(retdict, "hdrops",		(unsigned long long)esps.esps_hdrops)) return NULL;
	if (!addULongLong(retdict, "nopf",			(unsigned long long)esps.esps_nopf)) return NULL;
	if (!addULongLong(retdict, "notdb",			(unsigned long long)esps.esps_notdb)) return NULL;
	if (!addULongLong(retdict, "badkcr",		(unsigned long long)esps.esps_badkcr)) return NULL;
	if (!addULongLong(retdict, "qfull",			(unsigned long long)esps.esps_qfull)) return NULL;
	if (!addULongLong(retdict, "noxform",		(unsigned long long)esps.esps_noxform)) return NULL;
	if (!addULongLong(retdict, "badilen",		(unsigned long long)esps.esps_badilen)) return NULL;
	if (!addULongLong(retdict, "wrap",			(unsigned long long)esps.esps_wrap)) return NULL;
	if (!addULongLong(retdict, "badenc",		(unsigned long long)esps.esps_badenc)) return NULL;
	if (!addULongLong(retdict, "badauth",		(unsigned long long)esps.esps_badauth)) return NULL;
	if (!addULongLong(retdict, "replay",		(unsigned long long)esps.esps_replay)) return NULL;
	if (!addULongLong(retdict, "input",			(unsigned long long)esps.esps_input)) return NULL;
	if (!addULongLong(retdict, "output",		(unsigned long long)esps.esps_output)) return NULL;
	if (!addULongLong(retdict, "invalid",		(unsigned long long)esps.esps_invalid)) return NULL;
	if (!addULongLong(retdict, "ibytes",		(unsigned long long)esps.esps_ibytes)) return NULL;
	if (!addULongLong(retdict, "obytes",		(unsigned long long)esps.esps_obytes)) return NULL;
	if (!addULongLong(retdict, "toobig",		(unsigned long long)esps.esps_toobig)) return NULL;
	if (!addULongLong(retdict, "pdrops",		(unsigned long long)esps.esps_pdrops)) return NULL;
	if (!addULongLong(retdict, "crypto",		(unsigned long long)esps.esps_crypto)) return NULL;
	return retdict;
}

/*
 * See include/netinet/ip_ipip.h
 */
PyObject *ipipstats(PyObject *self, PyObject *args){
	struct ipipstat ipips;
	PyObject *retdict;

	if (kread(nl[N_IPIPSTAT].n_value, (char *)&ipips, sizeof ipips)){
		return NULL;
	}

	retdict = PyDict_New();
	if (retdict == NULL)
		return NULL;

	if (!addULongLong(retdict, "ipackets",			(unsigned long long)ipips.ipips_ipackets)) return NULL;
	if (!addULongLong(retdict, "opackets",			(unsigned long long)ipips.ipips_opackets)) return NULL;
	if (!addULongLong(retdict, "hdrops",			(unsigned long long)ipips.ipips_hdrops)) return NULL;
	if (!addULongLong(retdict, "qfull",				(unsigned long long)ipips.ipips_qfull)) return NULL;
	if (!addULongLong(retdict, "ibytes",			(unsigned long long)ipips.ipips_ibytes)) return NULL;
	if (!addULongLong(retdict, "obytes",			(unsigned long long)ipips.ipips_obytes)) return NULL;
	if (!addULongLong(retdict, "pdrops",			(unsigned long long)ipips.ipips_pdrops)) return NULL;
	if (!addULongLong(retdict, "spoof",				(unsigned long long)ipips.ipips_spoof)) return NULL;
	if (!addULongLong(retdict, "family",			(unsigned long long)ipips.ipips_family)) return NULL;
	if (!addULongLong(retdict, "unspec",			(unsigned long long)ipips.ipips_unspec)) return NULL;
	return retdict;
}

/*
 * See include/netinet/ip_ipcomp.h
 */
PyObject *ipcompstats(PyObject *self, PyObject *args){
	struct ipcompstat ipcomps;
	PyObject *retdict;

	if (kread(nl[N_IPCOMPSTAT].n_value, (char *)&ipcomps, sizeof ipcomps)){
		return NULL;
	}

	retdict = PyDict_New();
	if (retdict == NULL)
		return NULL;

	if (!addULongLong(retdict, "hdrops",		(unsigned long long)ipcomps.ipcomps_hdrops)) return NULL;
	if (!addULongLong(retdict, "nopf",			(unsigned long long)ipcomps.ipcomps_nopf)) return NULL;
	if (!addULongLong(retdict, "notdb",			(unsigned long long)ipcomps.ipcomps_notdb)) return NULL;
	if (!addULongLong(retdict, "badkcr",		(unsigned long long)ipcomps.ipcomps_badkcr)) return NULL;
	if (!addULongLong(retdict, "qfull",			(unsigned long long)ipcomps.ipcomps_qfull)) return NULL;
	if (!addULongLong(retdict, "noxform",		(unsigned long long)ipcomps.ipcomps_noxform)) return NULL;
	if (!addULongLong(retdict, "wrap",			(unsigned long long)ipcomps.ipcomps_wrap)) return NULL;
	if (!addULongLong(retdict, "input",			(unsigned long long)ipcomps.ipcomps_input)) return NULL;
	if (!addULongLong(retdict, "output",		(unsigned long long)ipcomps.ipcomps_output)) return NULL;
	if (!addULongLong(retdict, "invalid",		(unsigned long long)ipcomps.ipcomps_invalid)) return NULL;
	if (!addULongLong(retdict, "ibytes",		(unsigned long long)ipcomps.ipcomps_ibytes)) return NULL;
	if (!addULongLong(retdict, "obytes",		(unsigned long long)ipcomps.ipcomps_obytes)) return NULL;
	if (!addULongLong(retdict, "toobig",		(unsigned long long)ipcomps.ipcomps_toobig)) return NULL;
	if (!addULongLong(retdict, "pdrops",		(unsigned long long)ipcomps.ipcomps_pdrops)) return NULL;
	if (!addULongLong(retdict, "crypto",		(unsigned long long)ipcomps.ipcomps_crypto)) return NULL;
	if (!addULongLong(retdict, "minlen",		(unsigned long long)ipcomps.ipcomps_minlen)) return NULL;
	return retdict;
}

PyObject *initialise(PyObject *self, PyObject *args){
	if (!PyArg_ParseTuple(args, ""))
		return NULL;
	if (kvm_initialise(nl)){
		return NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *finalise(PyObject *self, PyObject *args){
	if (!PyArg_ParseTuple(args, ""))
		return NULL;
	if (kclose()){
        PyErr_SetString(OException, "kvm_close returned error.");
		return NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static PyMethodDef NetstatMethods[] = {
	{"initialise",			initialise,		METH_VARARGS,	"Initialise the kernel memory reader."},
	{"finalise",			finalise,		METH_VARARGS,	"Close kernel memory reader."},
	{"ifstats",				ifstats,		METH_VARARGS,	"Interface statistics."},
	{"ipstats",				ipstats,		METH_VARARGS,	"IP statistics."},
	{"ip6stats",			ip6stats,		METH_VARARGS,	"IPv6 statistics."},
	{"tcpstats",			tcpstats,		METH_VARARGS,	"TCP statistics."},
	{"udpstats",			udpstats,		METH_VARARGS,	"UDP statistics."},
	{"icmpstats",			icmpstats,		METH_VARARGS,	"ICMP statistics."},
	{"igmpstats",			igmpstats,		METH_VARARGS,	"IGMP statistics."},
	{"ahstats",				ahstats,		METH_VARARGS,	"AH statistics."},
	{"espstats",			espstats,		METH_VARARGS,	"ESP statistics."},
	{"ipipstats",			ipipstats,		METH_VARARGS,	"IPIP statistics."},
	{"ipcompstats",			ipcompstats,	METH_VARARGS,	"IPComp statistics."},
	{NULL, NULL, 0, NULL}		 /* Sentinel */
};

void init_netstat(void){
	PyObject *module, *global;
	module = Py_InitModule("_netstat", NetstatMethods);
	global = PyImport_ImportModule("_global");
	OException = PyObject_GetAttrString(global, "OException");
}
