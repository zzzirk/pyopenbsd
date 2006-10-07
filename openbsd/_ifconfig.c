/*
	Copyright (c) 2005, 2006 Aldo Cortesi
    Copyright (c) 2006, David Harrison

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

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <net/if_media.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <ifaddrs.h>

#include <Python.h>
#include "_cutils.h"

const struct ifmedia_description ifm_type_descriptions[] = IFM_TYPE_DESCRIPTIONS;
const struct ifmedia_description ifm_subtype_descriptions[] = IFM_SUBTYPE_DESCRIPTIONS;
const struct ifmedia_description ifm_option_descriptions[] = IFM_OPTION_DESCRIPTIONS;
static PyObject *OException;

/*
 * Retrieves the interface-level information for a given interface.
 */
PyObject *getifinfo(PyObject *self, PyObject *args){
	struct ifreq ifr;
	int s;
	unsigned short flags;
	u_long metric, mtu;
	char *ifname;
    char ifdescr[IFDESCRSIZE];
	PyObject *ifvals;

	if (!PyArg_ParseTuple(args, "s", &ifname))
		return NULL;

	(void) strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0){
		PyErr_SetFromErrno(OException);
		return NULL;
	}

	if (ioctl(s, SIOCGIFFLAGS, (caddr_t)(&ifr)) < 0)
		goto error;
	flags = (unsigned short)ifr.ifr_flags;

    ifr.ifr_data = (caddr_t)&ifdescr;
  	if (ioctl(s, SIOCGIFDESCR, &ifr) < 0)
  		goto error;

	if (ioctl(s, SIOCGIFMETRIC, (caddr_t)(&ifr)) < 0)
		goto error;
	metric = ifr.ifr_metric;

	if (ioctl(s, SIOCGIFMTU, (caddr_t)(&ifr)) < 0)
		goto error;
	mtu = ifr.ifr_mtu;

	close(s);
	ifvals = Py_BuildValue("{s:h}", "flags", flags);
	stealingSetItem(ifvals, "mtu", PyLong_FromUnsignedLong(mtu));
	stealingSetItem(ifvals, "metric", PyLong_FromUnsignedLong(metric));
  	stealingSetItem(ifvals, "description", PyString_FromString(ifdescr));
	return ifvals;

error:
	close(s);
	PyErr_SetFromErrno(OException);
	return NULL;
}


const char *media_type_str(int mword){
	const struct ifmedia_description *desc;
	for (desc = ifm_type_descriptions; desc->ifmt_string != NULL; desc++) {
		if (IFM_TYPE(mword) == desc->ifmt_word)
			return (desc->ifmt_string);
	}
	return ("<unknown type>");
}


const char * media_subtype_str(int mword){
	const struct ifmedia_description *desc;
	for (desc = ifm_subtype_descriptions; desc->ifmt_string != NULL; desc++) {
		if (IFM_TYPE_MATCH(desc->ifmt_word, mword) &&
		    IFM_SUBTYPE(desc->ifmt_word) == IFM_SUBTYPE(mword))
			return (desc->ifmt_string);
	}
	return ("<unknown subtype>");
}


/*
 * Returns a tuple with the following format: 
 *		(type, subtype, [options])
 *	...where all values are strings.
 */
PyObject *decodeMediaWord(int mw){
	PyObject *optionlist, *rettup, *pystr;
	const struct ifmedia_description *desc;

	if (!(optionlist = PyList_New(0)))
		return NULL;

	for (desc = ifm_option_descriptions; desc->ifmt_string != NULL; desc++) {
		if (IFM_TYPE_MATCH(desc->ifmt_word, mw) && (IFM_OPTIONS(mw) & IFM_OPTIONS(desc->ifmt_word)) != 0) {
			pystr = PyString_FromString(desc->ifmt_string);
			if (PyList_Append(optionlist, pystr) < 0){
				Py_DECREF(optionlist);
				Py_DECREF(pystr);
				return NULL;
			}
			Py_DECREF(pystr);
		}
	}
	rettup = Py_BuildValue("(s, s, O)", media_type_str(mw), media_subtype_str(mw), optionlist);
	Py_DECREF(optionlist);
	return rettup;
}


/*
 * This returns a dictionary:
 *		
 *		{
 *			"current":	currentMedaTuple,
 *			"active":	activeMediaTuple,
 *			"options":	[mediaOptionsTuples]
 *		}
 *
 *		MediaOptionsTuples are of the form (MediaType, [(MediaSubType, [SupportedOptions])])
 */
PyObject *getifmedia(PyObject *self, PyObject *args){
	struct ifmediareq ifmr;
	char *ifname;
	int *media_list;
	int s, i;
	PyObject *retdict, *optionlist, *tmp, *tmp2;


	if (!PyArg_ParseTuple(args, "s", &ifname))
		return NULL;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0){ 
		PyErr_SetFromErrno(OException);
		return NULL;
	}

	bzero(&ifmr, sizeof ifmr);
	(void) strlcpy(ifmr.ifm_name, ifname, sizeof(ifmr.ifm_name));

	/*
	 * The first time we call SIOCGIFMEDIA it will set ifmr.ifm_count to the
	 * number of media types, so we can allocate memory for them. 
	 */
	if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0) 
		goto error;

	media_list = malloc(ifmr.ifm_count * sizeof(int));
	if (media_list == NULL)
		goto error;
	ifmr.ifm_ulist = media_list;
	if (ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) < 0){
		free(media_list);
		goto error;
	}

	if (!(optionlist = PyList_New(0))){
		close(s);
		free(media_list);
		return NULL;
	}

	for (i = 0; i < ifmr.ifm_count; i++) {
		tmp = decodeMediaWord(media_list[i]);
		if (PyList_Append(optionlist, tmp) < 0){
			Py_DECREF(optionlist);
			Py_DECREF(tmp);
			free(media_list);
			close(s);
			return NULL;
		}
		Py_DECREF(tmp);
	}
	free(media_list);

	tmp = decodeMediaWord(ifmr.ifm_current);
	tmp2 = decodeMediaWord(ifmr.ifm_active);
	retdict = Py_BuildValue("{s:O, s:O, s:O}", 
			"current",		tmp, 
			"active",		tmp2,	
			"options",		optionlist
		);
	Py_DECREF(tmp);
	Py_DECREF(tmp2);
	Py_DECREF(optionlist);
	close(s);
	return retdict;

error:
	close(s);
	PyErr_SetFromErrno(OException);
	return NULL;
}


int _setifinfo(char *ifname, int ioc, unsigned short *flags, u_long *mtu, u_long *metric, char *ifdescr) {
	struct ifreq ifr;
	int s;

	bzero((char *)&ifr, sizeof(struct ifreq));
	(void) strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (flags)
		ifr.ifr_flags = *flags;
	if (mtu)
		ifr.ifr_mtu = *mtu;
	if (metric)
		ifr.ifr_metric = *metric;
	if (ifdescr)
        ifr.ifr_data = (caddr_t)ifdescr;
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
        goto error;
    if (ioctl(s, ioc, (caddr_t)&ifr) < 0){
	    close(s);
		goto error;
    }
	close(s);
	return 0;

error:
	PyErr_SetFromErrno(OException);
	return 1;
}


PyObject *setifflags(PyObject *self, PyObject *args){
	unsigned int tmp;
	unsigned short flags;
	char *ifname;

	if (!PyArg_ParseTuple(args, "si", &ifname, &tmp))
		return NULL;

	flags = (unsigned short) tmp;
	if (_setifinfo(ifname, SIOCSIFFLAGS, &flags, NULL, NULL, NULL))
		return NULL;

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *setifdescr(PyObject *self, PyObject *args){
	char *ifname;
    char *ifdescr;

	if (!PyArg_ParseTuple(args, "ss", &ifname, &ifdescr))
		return NULL;

	if (_setifinfo(ifname, SIOCSIFDESCR, NULL, NULL, NULL, ifdescr))
		return NULL;

	Py_INCREF(Py_None);
	return Py_None;
}

PyObject *setifmtu(PyObject *self, PyObject *args){
	u_long mtu;
	char *ifname;

	if (!PyArg_ParseTuple(args, "sl", &ifname, &mtu))
		return NULL;

	if (_setifinfo(ifname, SIOCSIFMTU, NULL, &mtu, NULL, NULL))
		return NULL;

	Py_INCREF(Py_None);
	return Py_None;
}


PyObject *setifmetric(PyObject *self, PyObject *args){
	u_long metric;
	char *ifname;

	if (!PyArg_ParseTuple(args, "sl", &ifname, &metric))
		return NULL;

	if (_setifinfo(ifname, SIOCSIFMETRIC, NULL, NULL, &metric, NULL))
		return NULL;

	Py_INCREF(Py_None);
	return Py_None;
}


PyObject *getSAAddr(struct sockaddr *sa){
    PyObject *addrdict, *addrstr;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
    struct sockaddr_dl *sdl;
    char *tstr;

    if (!(addrdict = PyDict_New()))
		return NULL;

    switch (sa->sa_family){
        case AF_INET:
            sin = (struct sockaddr_in *)sa;
            addrstr = PyString_FromStringAndSize((char*)(&(sin->sin_addr)), 4);
            break;
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *)sa;
            addrstr = PyString_FromStringAndSize((char*)(&(sin6->sin6_addr)), 16);
            break;
        case AF_LINK:
            sdl = (struct sockaddr_dl *)sa;
            if (sdl->sdl_type == IFT_ETHER)
                addrstr = PyString_FromStringAndSize((char*)LLADDR(sdl), 6);
			else {
                addrstr = Py_None;
				Py_INCREF(Py_None);
			}
            switch(sdl->sdl_type){
                // FIXME: Should be moved to a dictionary in Python.
                case (IFT_OTHER):							tstr = "OTHER"; break;
                case (IFT_1822):							tstr = "1822"; break;
                case (IFT_HDH1822):							tstr = "HDH1822"; break;
                case (IFT_X25DDN):							tstr = "X25DDN"; break;
                case (IFT_X25):								tstr = "X25"; break;
                case (IFT_ETHER):							tstr = "ETHER"; break;
                case (IFT_ISO88023):						tstr = "ISO88023"; break;
                case (IFT_ISO88024):						tstr = "ISO88024"; break;
                case (IFT_ISO88025):						tstr = "ISO88025"; break;
                case (IFT_ISO88026):						tstr = "ISO88026"; break;
                case (IFT_STARLAN):							tstr = "STARLAN"; break;
                case (IFT_P10):								tstr = "P10"; break;
                case (IFT_P80):								tstr = "P80"; break;
                case (IFT_HY):								tstr = "HY"; break;
                case (IFT_FDDI):							tstr = "FDDI"; break;
                case (IFT_LAPB):							tstr = "LAPB"; break;
                case (IFT_SDLC):							tstr = "SDLC"; break;
                case (IFT_T1):								tstr = "T1"; break;
                case (IFT_CEPT):							tstr = "CEPT"; break;
                case (IFT_ISDNBASIC):						tstr = "ISDNBASIC"; break;
                case (IFT_ISDNPRIMARY):						tstr = "ISDNPRIMARY"; break;
                case (IFT_PTPSERIAL):						tstr = "PTPSERIAL"; break;
                case (IFT_PPP):								tstr = "PPP"; break;
                case (IFT_LOOP):							tstr = "LOOP"; break;
                case (IFT_EON):								tstr = "EON"; break;
                case (IFT_XETHER):							tstr = "XETHER"; break;
                case (IFT_NSIP):							tstr = "NSIP"; break;
                case (IFT_SLIP):							tstr = "SLIP"; break;
                case (IFT_ULTRA):							tstr = "ULTRA"; break;
                case (IFT_DS3):								tstr = "DS3"; break;
                case (IFT_SIP):								tstr = "SIP"; break;
                case (IFT_FRELAY):							tstr = "FRELAY"; break;
                case (IFT_RS232):							tstr = "RS232"; break;
                case (IFT_PARA):							tstr = "PARA"; break;
                case (IFT_ARCNET):							tstr = "ARCNET"; break;
                case (IFT_ARCNETPLUS):						tstr = "ARCNETPLUS"; break;
                case (IFT_ATM):								tstr = "ATM"; break;
                case (IFT_MIOX25):							tstr = "MIOX25"; break;
                case (IFT_SONET):							tstr = "SONET"; break;
                case (IFT_X25PLE):							tstr = "X25PLE"; break;
                case (IFT_ISO88022LLC):						tstr = "ISO88022LLC"; break;
                case (IFT_LOCALTALK):						tstr = "LOCALTALK"; break;
                case (IFT_SMDSDXI):							tstr = "SMDSDXI"; break;
                case (IFT_FRELAYDCE):						tstr = "FRELAYDCE"; break;
                case (IFT_V35):								tstr = "V35"; break;
                case (IFT_HSSI):							tstr = "HSSI"; break;
                case (IFT_HIPPI):							tstr = "HIPPI"; break;
                case (IFT_MODEM):							tstr = "MODEM"; break;
                case (IFT_AAL5):							tstr = "AAL5"; break;
                case (IFT_SONETPATH):						tstr = "SONETPATH"; break;
                case (IFT_SONETVT):							tstr = "SONETVT"; break;
                case (IFT_SMDSICIP):						tstr = "SMDSICIP"; break;
                case (IFT_PROPVIRTUAL):						tstr = "PROPVIRTUAL"; break;
                case (IFT_PROPMUX):							tstr = "PROPMUX"; break;
                case (IFT_IEEE80212):						tstr = "IEEE80212"; break;
                case (IFT_FIBRECHANNEL):					tstr = "FIBRECHANNEL"; break;
                case (IFT_HIPPIINTERFACE):					tstr = "HIPPIINTERFACE"; break;
                case (IFT_FRAMERELAYINTERCONNECT):			tstr = "FRAMERELAYINTERCONNECT"; break;
                case (IFT_AFLANE8023):						tstr = "AFLANE8023"; break;
                case (IFT_AFLANE8025):						tstr = "AFLANE8025"; break;
                case (IFT_CCTEMUL):							tstr = "CCTEMUL"; break;
                case (IFT_FASTETHER):						tstr = "FASTETHER"; break;
                case (IFT_ISDN):							tstr = "ISDN"; break;
                case (IFT_V11):								tstr = "V11"; break;
                case (IFT_V36):								tstr = "V36"; break;
                case (IFT_G703AT64K):						tstr = "G703AT64K"; break;
                case (IFT_G703AT2MB):						tstr = "G703AT2MB"; break;
                case (IFT_QLLC):							tstr = "QLLC"; break;
                case (IFT_FASTETHERFX):						tstr = "FASTETHERFX"; break;
                case (IFT_CHANNEL):							tstr = "CHANNEL"; break;
                case (IFT_IEEE80211):						tstr = "IEEE80211"; break;
                case (IFT_IBM370PARCHAN):					tstr = "IBM370PARCHAN"; break;
                case (IFT_ESCON):							tstr = "ESCON"; break;
                case (IFT_DLSW):							tstr = "DLSW"; break;
                case (IFT_ISDNS):							tstr = "ISDNS"; break;
                case (IFT_ISDNU):							tstr = "ISDNU"; break;
                case (IFT_LAPD):							tstr = "LAPD"; break;
                case (IFT_IPSWITCH):						tstr = "IPSWITCH"; break;
                case (IFT_RSRB):							tstr = "RSRB"; break;
                case (IFT_ATMLOGICAL):						tstr = "ATMLOGICAL"; break;
                case (IFT_DS0):								tstr = "DS0"; break;
                case (IFT_DS0BUNDLE):						tstr = "DS0BUNDLE"; break;
                case (IFT_BSC):								tstr = "BSC"; break;
                case (IFT_ASYNC):							tstr = "ASYNC"; break;
                case (IFT_CNR):								tstr = "CNR"; break;
                case (IFT_ISO88025DTR):						tstr = "ISO88025DTR"; break;
                case (IFT_EPLRS):							tstr = "EPLRS"; break;
                case (IFT_ARAP):							tstr = "ARAP"; break;
                case (IFT_PROPCNLS):						tstr = "PROPCNLS"; break;
                case (IFT_HOSTPAD):							tstr = "HOSTPAD"; break;
                case (IFT_TERMPAD):							tstr = "TERMPAD"; break;
                case (IFT_FRAMERELAYMPI):					tstr = "FRAMERELAYMPI"; break;
                case (IFT_X213):							tstr = "X213"; break;
                case (IFT_ADSL):							tstr = "ADSL"; break;
                case (IFT_RADSL):							tstr = "RADSL"; break;
                case (IFT_SDSL):							tstr = "SDSL"; break;
                case (IFT_VDSL):							tstr = "VDSL"; break;
                case (IFT_ISO88025CRFPINT):					tstr = "ISO88025CRFPINT"; break;
                case (IFT_MYRINET):							tstr = "MYRINET"; break;
                case (IFT_VOICEEM):							tstr = "VOICEEM"; break;
                case (IFT_VOICEFXO):						tstr = "VOICEFXO"; break;
                case (IFT_VOICEFXS):						tstr = "VOICEFXS"; break;
                case (IFT_VOICEENCAP):						tstr = "VOICEENCAP"; break;
                case (IFT_VOICEOVERIP):						tstr = "VOICEOVERIP"; break;
                case (IFT_ATMDXI):							tstr = "ATMDXI"; break;
                case (IFT_ATMFUNI):							tstr = "ATMFUNI"; break;
                case (IFT_ATMIMA):							tstr = "ATMIMA"; break;
                case (IFT_PPPMULTILINKBUNDLE):				tstr = "PPPMULTILINKBUNDLE"; break;
                case (IFT_IPOVERCDLC):						tstr = "IPOVERCDLC"; break;
                case (IFT_IPOVERCLAW):						tstr = "IPOVERCLAW"; break;
                case (IFT_STACKTOSTACK):					tstr = "STACKTOSTACK"; break;
                case (IFT_VIRTUALIPADDRESS):				tstr = "VIRTUALIPADDRESS"; break;
                case (IFT_MPC):								tstr = "MPC"; break;
                case (IFT_IPOVERATM):						tstr = "IPOVERATM"; break;
                case (IFT_ISO88025FIBER):					tstr = "ISO88025FIBER"; break;
                case (IFT_TDLC):							tstr = "TDLC"; break;
                case (IFT_GIGABITETHERNET):					tstr = "GIGABITETHERNET"; break;
                case (IFT_HDLC):							tstr = "HDLC"; break;
                case (IFT_LAPF):							tstr = "LAPF"; break;
                case (IFT_V37):								tstr = "V37"; break;
                case (IFT_X25MLP):							tstr = "X25MLP"; break;
                case (IFT_X25HUNTGROUP):					tstr = "X25HUNTGROUP"; break;
                case (IFT_TRANSPHDLC):						tstr = "TRANSPHDLC"; break;
                case (IFT_INTERLEAVE):						tstr = "INTERLEAVE"; break;
                case (IFT_FAST):							tstr = "FAST"; break;
                case (IFT_IP):								tstr = "IP"; break;
                case (IFT_DOCSCABLEMACLAYER):				tstr = "DOCSCABLEMACLAYER"; break;
                case (IFT_DOCSCABLEDOWNSTREAM):				tstr = "DOCSCABLEDOWNSTREAM"; break;
                case (IFT_DOCSCABLEUPSTREAM):				tstr = "DOCSCABLEUPSTREAM"; break;
                case (IFT_A12MPPSWITCH):					tstr = "A12MPPSWITCH"; break;
                case (IFT_TUNNEL):							tstr = "TUNNEL"; break;
                case (IFT_COFFEE):							tstr = "COFFEE"; break;
                case (IFT_CES):								tstr = "CES"; break;
                case (IFT_ATMSUBINTERFACE):					tstr = "ATMSUBINTERFACE"; break;
                case (IFT_L2VLAN):							tstr = "L2VLAN"; break;
                case (IFT_L3IPVLAN):						tstr = "L3IPVLAN"; break;
                case (IFT_L3IPXVLAN):						tstr = "L3IPXVLAN"; break;
                case (IFT_DIGITALPOWERLINE):				tstr = "DIGITALPOWERLINE"; break;
                case (IFT_MEDIAMAILOVERIP):					tstr = "MEDIAMAILOVERIP"; break;
                case (IFT_DTM):								tstr = "DTM"; break;
                case (IFT_DCN):								tstr = "DCN"; break;
                case (IFT_IPFORWARD):						tstr = "IPFORWARD"; break;
                case (IFT_MSDSL):							tstr = "MSDSL"; break;
                case (IFT_IEEE1394):						tstr = "IEEE1394"; break;
                case (IFT_IFGSN):							tstr = "IFGSN"; break;
                case (IFT_DVBRCCMACLAYER):					tstr = "DVBRCCMACLAYER"; break;
                case (IFT_DVBRCCDOWNSTREAM):				tstr = "DVBRCCDOWNSTREAM"; break;
                case (IFT_DVBRCCUPSTREAM):					tstr = "DVBRCCUPSTREAM"; break;
                case (IFT_ATMVIRTUAL):						tstr = "ATMVIRTUAL"; break;
                case (IFT_MPLSTUNNEL):						tstr = "MPLSTUNNEL"; break;
                case (IFT_SRP):								tstr = "SRP"; break;
                case (IFT_VOICEOVERATM):					tstr = "VOICEOVERATM"; break;
                case (IFT_VOICEOVERFRAMERELAY):				tstr = "VOICEOVERFRAMERELAY"; break;
                case (IFT_IDSL):							tstr = "IDSL"; break;
                case (IFT_COMPOSITELINK):					tstr = "COMPOSITELINK"; break;
                case (IFT_SS7SIGLINK):						tstr = "SS7SIGLINK"; break;
                case (IFT_PROPWIRELESSP2P):					tstr = "PROPWIRELESSP2P"; break;
                case (IFT_FRFORWARD):						tstr = "FRFORWARD"; break;
                case (IFT_RFC1483):							tstr = "RFC1483"; break;
                case (IFT_USB):								tstr = "USB"; break;
                case (IFT_IEEE8023ADLAG):					tstr = "IEEE8023ADLAG"; break;
                case (IFT_BGPPOLICYACCOUNTING):				tstr = "BGPPOLICYACCOUNTING"; break;
                case (IFT_FRF16MFRBUNDLE):					tstr = "FRF16MFRBUNDLE"; break;
                case (IFT_H323GATEKEEPER):					tstr = "H323GATEKEEPER"; break;
                case (IFT_H323PROXY):						tstr = "H323PROXY"; break;
                case (IFT_MPLS):							tstr = "MPLS"; break;
                case (IFT_MFSIGLINK):						tstr = "MFSIGLINK"; break;
                case (IFT_HDSL2):							tstr = "HDSL2"; break;
                case (IFT_SHDSL):							tstr = "SHDSL"; break;
                case (IFT_DS1FDL):							tstr = "DS1FDL"; break;
                case (IFT_POS):								tstr = "POS"; break;
                case (IFT_DVBASILN):						tstr = "DVBASILN"; break;
                case (IFT_DVBASIOUT):						tstr = "DVBASIOUT"; break;
                case (IFT_PLC):								tstr = "PLC"; break;
                case (IFT_NFAS):							tstr = "NFAS"; break;
                case (IFT_TR008):							tstr = "TR008"; break;
                case (IFT_GR303RDT):						tstr = "GR303RDT"; break;
                case (IFT_GR303IDT):						tstr = "GR303IDT"; break;
                case (IFT_ISUP):							tstr = "ISUP"; break;
                case (IFT_PROPDOCSWIRELESSMACLAYER):		tstr = "PROPDOCSWIRELESSMACLAYER"; break;
                case (IFT_PROPDOCSWIRELESSDOWNSTREAM):		tstr = "PROPDOCSWIRELESSDOWNSTREAM"; break;
                case (IFT_PROPDOCSWIRELESSUPSTREAM):		tstr = "PROPDOCSWIRELESSUPSTREAM"; break;
                case (IFT_HIPERLAN2):						tstr = "HIPERLAN2"; break;
                case (IFT_PROPBWAP2MP):						tstr = "PROPBWAP2MP"; break;
                case (IFT_SONETOVERHEADCHANNEL):			tstr = "SONETOVERHEADCHANNEL"; break;
                case (IFT_DIGITALWRAPPEROVERHEADCHANNEL):	tstr = "DIGITALWRAPPEROVERHEADCHANNEL"; break;
                case (IFT_AAL2):							tstr = "AAL2"; break;
                case (IFT_RADIOMAC):						tstr = "RADIOMAC"; break;
                case (IFT_ATMRADIO):						tstr = "ATMRADIO"; break;
                case (IFT_IMT):								tstr = "IMT"; break;
                case (IFT_MVL):								tstr = "MVL"; break;
                case (IFT_REACHDSL):						tstr = "REACHDSL"; break;
                case (IFT_FRDLCIENDPT):						tstr = "FRDLCIENDPT"; break;
                case (IFT_ATMVCIENDPT):						tstr = "ATMVCIENDPT"; break;
                case (IFT_OPTICALCHANNEL):					tstr = "OPTICALCHANNEL"; break;
                case (IFT_OPTICALTRANSPORT):				tstr = "OPTICALTRANSPORT"; break;
                case (IFT_PROPATM):							tstr = "PROPATM"; break;
                case (IFT_VOICEOVERCABLE):					tstr = "VOICEOVERCABLE"; break;
                case (IFT_INFINIBAND):						tstr = "INFINIBAND"; break;
                case (IFT_TELINK):							tstr = "TELINK"; break;
                case (IFT_Q2931):							tstr = "Q2931"; break;
                case (IFT_VIRTUALTG):						tstr = "VIRTUALTG"; break;
                case (IFT_SIPTG):							tstr = "SIPTG"; break;
                case (IFT_SIPSIG):							tstr = "SIPSIG"; break;
                case (IFT_DOCSCABLEUPSTREAMCHANNEL):		tstr = "DOCSCABLEUPSTREAMCHANNEL"; break;
                case (IFT_ECONET):							tstr = "ECONET"; break;
                case (IFT_PON155):							tstr = "PON155"; break;
                case (IFT_PON622):							tstr = "PON622"; break;
                case (IFT_BRIDGE):							tstr = "BRIDGE"; break;
                case (IFT_LINEGROUP):						tstr = "LINEGROUP"; break;
                case (IFT_VOICEEMFGD):						tstr = "VOICEEMFGD"; break;
                case (IFT_VOICEFGDEANA):					tstr = "VOICEFGDEANA"; break;
                case (IFT_VOICEDID):						tstr = "VOICEDID"; break;
                case (IFT_GIF):								tstr = "GIF"; break;
                case (IFT_DUMMY):							tstr = "DUMMY"; break;
                case (IFT_PVC):								tstr = "PVC"; break;
                case (IFT_FAITH):							tstr = "FAITH"; break;
                case (IFT_ENC):								tstr = "ENC"; break;
                case (IFT_PFLOG):							tstr = "PFLOG"; break;
                case (IFT_PFSYNC):							tstr = "PFSYNC"; break;
                default:
                        tstr = "unknown";
            }
            stealingSetItem(addrdict, "iftype", PyString_FromString(tstr));
            break;
        default:
            addrstr = Py_None;
			Py_INCREF(Py_None);
            break;
    }
    stealingSetItem(addrdict, "address", addrstr);
    stealingSetItem(addrdict, "sa_family", PyLong_FromUnsignedLong((unsigned long)sa->sa_family));
    return addrdict;
}


PyObject *pyGetifaddrs(PyObject *self, PyObject *args){
	struct ifaddrs *ifp, *pfp;
	PyObject *addrlist, *ifvals;
    PyObject *addrobj;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	if (getifaddrs(&ifp) < 0){
		return PyErr_SetFromErrno(OException);
	}

	if (!(addrlist = PyList_New(0))){
		freeifaddrs(ifp);
		return NULL;
	}

	for (pfp = ifp; pfp; pfp = pfp->ifa_next) {
        ifvals = Py_BuildValue(
                "{s:s}", 
				"name",			pfp->ifa_name
			);
        if (pfp->ifa_addr){
            addrobj = getSAAddr(pfp->ifa_addr);
			if (!addrobj){
				Py_DECREF(ifvals);
                goto error;
			}
			if (stealingSetItem(ifvals, "address", addrobj)){
				Py_DECREF(addrobj);
				Py_DECREF(ifvals);
                goto error;
			}
        }
        if (pfp->ifa_netmask){
            addrobj = getSAAddr(pfp->ifa_netmask);
			if (!addrobj){
				Py_DECREF(ifvals);
                goto error;
			}
			if (stealingSetItem(ifvals, "netmask", addrobj)){
				Py_DECREF(ifvals);
				Py_DECREF(addrobj);
                goto error;
			}
        }
        if (pfp->ifa_dstaddr){
            addrobj = getSAAddr(pfp->ifa_dstaddr);
			if (!addrobj){
				Py_DECREF(ifvals);
                goto error;
			}
			if (stealingSetItem(ifvals, "dstaddr", addrobj)){
				Py_DECREF(ifvals);
				Py_DECREF(addrobj);
                goto error;
			}
        }
		if (PyList_Append(addrlist, ifvals) < 0){
			Py_DECREF(ifvals);
            goto error;
		}
		Py_DECREF(ifvals);
	}
    freeifaddrs(ifp);
	return addrlist;

error:
    Py_DECREF(addrlist);
    freeifaddrs(ifp);
	return NULL;
}


PyObject *create(PyObject *self, PyObject *args){
	char *ifname;

	if (!PyArg_ParseTuple(args, "s", &ifname))
		return NULL;

	if (_setifinfo(ifname, SIOCIFCREATE, NULL, NULL, NULL, NULL))
		return NULL;

	Py_INCREF(Py_None);
	return Py_None;
}


PyObject *destroy(PyObject *self, PyObject *args){
	char *ifname;

	if (!PyArg_ParseTuple(args, "s", &ifname))
		return NULL;

	if (_setifinfo(ifname, SIOCIFDESTROY, NULL, NULL, NULL, NULL))
		return NULL;

	Py_INCREF(Py_None);
	return Py_None;
}


/*
 * Add an address to an interface.
 *
 */
PyObject *addaddr(PyObject *self, PyObject *args){
	int s, af, addrlen, masklen;
	char *ifname, *addr, *mask;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
	struct in6_aliasreq	in6_ifra;
    struct in_aliasreq ifra;

	if (!PyArg_ParseTuple(args, "sis#s#", &ifname, &af, &addr, 
											&addrlen, &mask, &masklen))
		return NULL;

	s = socket(af, SOCK_DGRAM, 0);
	if (s < 0){
		PyErr_SetFromErrno(OException);
		return NULL;
	}

    switch (af){
        case AF_INET:
			if ((addrlen != 4) || (masklen != 4)){
                close(s);
				PyErr_SetString(OException, "Invalid address length.");
				return NULL;
			}
			memset(&ifra, 0, sizeof(ifra));
			(void) strlcpy(ifra.ifra_name, ifname, sizeof(ifra.ifra_name));

			sin = (struct sockaddr_in*)(&ifra.ifra_addr);
            sin->sin_len = sizeof(*sin);
			sin->sin_family = af;
            memcpy(&sin->sin_addr, addr, 4);

			sin = (struct sockaddr_in*)(&ifra.ifra_mask);
			sin->sin_family = af;
            sin->sin_len = sizeof(*sin);
			memcpy(&sin->sin_addr, mask, 4);

			if (ioctl(s, SIOCAIFADDR, (caddr_t)&ifra) < 0){
                close(s);
				PyErr_SetFromErrno(OException);
				return NULL;
			}
			break;

        case AF_INET6:
			if ((addrlen != 16) || (masklen != 16)){
                close(s);
				PyErr_SetString(OException, "Invalid address length.");
				return NULL;
			}
			memset(&in6_ifra, 0, sizeof(in6_ifra));
			in6_ifra.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
			in6_ifra.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
			(void) strlcpy(in6_ifra.ifra_name, ifname, sizeof(in6_ifra.ifra_name) - 1);

			sin6 = &in6_ifra.ifra_addr;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_len = sizeof(*sin6);
			memcpy(&sin6->sin6_addr, addr, addrlen);

            /* KAME twiddling */
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) && 
					*(u_int16_t *)&sin6->sin6_addr.s6_addr[2] == 0 && 
						sin6->sin6_scope_id) {
				*(u_int16_t *)&sin6->sin6_addr.s6_addr[2] = 
						htons(sin6->sin6_scope_id & 0xffff);
				sin6->sin6_scope_id = 0;
			}

			sin6 = &in6_ifra.ifra_prefixmask;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_len = sizeof(*sin6);
			memcpy(&sin6->sin6_addr, mask, masklen);

			if (ioctl(s, SIOCAIFADDR_IN6, (caddr_t)&in6_ifra) < 0){
                close(s);
				PyErr_SetFromErrno(OException);
				return NULL;
			}
            break;

		default:
            close(s);
			PyErr_SetString(OException, "Invalid address type.");
            return NULL;
	}
    close(s);
	Py_INCREF(Py_None);
	return Py_None;
}

/*
 * Add an address to an interface.
 *
 */
PyObject *deladdr(PyObject *self, PyObject *args){
	int s, af, addrlen;
	char *ifname, *addr;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
	struct in6_ifreq	ifrq6;
    struct ifreq		ifrq;

	if (!PyArg_ParseTuple(args, "sis#", &ifname, &af, &addr, &addrlen))
		return NULL;

	s = socket(af, SOCK_DGRAM, 0);
	if (s < 0){
		PyErr_SetFromErrno(OException);
		return NULL;
	}

    switch (af){
        case AF_INET:
			if (addrlen != 4){
                close(s);
				PyErr_SetString(OException, "Invalid address length.");
				return NULL;
			}
			memset(&ifrq, 0, sizeof(ifrq));
			(void) strlcpy(ifrq.ifr_name, ifname, sizeof(ifrq.ifr_name));
			sin = (struct sockaddr_in*)(&ifrq.ifr_addr);
            sin->sin_len = sizeof(*sin);
			sin->sin_family = af;
            memcpy(&sin->sin_addr, addr, 4);
			if (ioctl(s, SIOCDIFADDR, (caddr_t)&ifrq) < 0){
                close(s);
				PyErr_SetFromErrno(OException);
				return NULL;
			}
			break;

        case AF_INET6:
			if (addrlen != 16){
                close(s);
				PyErr_SetString(OException, "Invalid address length.");
				return NULL;
			}
			memset(&ifrq6, 0, sizeof(ifrq6));
			(void) strlcpy(ifrq6.ifr_name, ifname, sizeof(ifrq6.ifr_name) - 1);
			sin6 = &ifrq6.ifr_addr;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_len = sizeof(*sin6);
			memcpy(&sin6->sin6_addr, addr, addrlen);
			/* KAME twiddle here? */
			if (ioctl(s, SIOCDIFADDR_IN6, (caddr_t)&ifrq6) < 0){
                close(s);
				PyErr_SetFromErrno(OException);
				return NULL;
			}
            break;

		default:
            close(s);
			PyErr_SetString(OException, "Invalid address type.");
            return NULL;
	}
    close(s);
	Py_INCREF(Py_None);
	return Py_None;
}


PyObject *setifgroup(PyObject *self, PyObject *args) {
    int s;
	char *ifname;
	char *ifgrpname;
    struct ifgroupreq ifgr;

	if (!PyArg_ParseTuple(args, "ss", &ifname, &ifgrpname))
		return NULL;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0){
		PyErr_SetFromErrno(OException);
		return NULL;
	}

    memset(&ifgr, 0, sizeof(ifgr));
    strlcpy(ifgr.ifgr_name, ifname, IFNAMSIZ);
    strlcpy(ifgr.ifgr_group, ifgrpname, IFNAMSIZ);

    if (ifgrpname[0] && isdigit(ifgrpname[strlen(ifgrpname) - 1])) {
        PyErr_SetString(OException, "Group names may not end in a digit");
        return NULL;
    }

    if (strlcpy(ifgr.ifgr_group, ifgrpname, IFNAMSIZ) >= IFNAMSIZ) {
        PyErr_SetFromErrno(OException);
        return NULL;
    }

    if (ioctl(s, SIOCAIFGROUP, (caddr_t)&ifgr) == -1) {
        PyErr_SetFromErrno(OException);
        return NULL;
    }

    close(s);
	Py_INCREF(Py_None);
    return Py_None;
}


PyObject *unsetifgroup(PyObject *self, PyObject *args) {
    int s;
	char *ifname;
	char *ifgrpname;
    struct ifgroupreq ifgr;

	if (!PyArg_ParseTuple(args, "ss", &ifname, &ifgrpname))
		return NULL;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0){
		PyErr_SetFromErrno(OException);
		return NULL;
	}

    memset(&ifgr, 0, sizeof(ifgr));
    strlcpy(ifgr.ifgr_name, ifname, IFNAMSIZ);
    strlcpy(ifgr.ifgr_group, ifgrpname, IFNAMSIZ);

    if (ifgrpname[0] && isdigit(ifgrpname[strlen(ifgrpname) - 1]))
        PyErr_SetString(OException, "Group names may not end in a digit");

    if (strlcpy(ifgr.ifgr_group, ifgrpname, IFNAMSIZ) >= IFNAMSIZ) {
        PyErr_SetFromErrno(OException);
        return NULL;
    }

    if (ioctl(s, SIOCDIFGROUP, (caddr_t)&ifgr) == -1) {
        PyErr_SetFromErrno(OException);
        return NULL;
    }

    close(s);
	Py_INCREF(Py_None);
    return Py_None;
}


PyObject *getifgroups(PyObject *self, PyObject *args) {
    int    len, s;
    struct ifgroupreq   ifgr;
    struct ifg_req      *ifg;
    PyObject *grpList, *tmp;
    char *ifname;

    if (!(grpList = PyList_New(0)))
		return NULL;

    if (!PyArg_ParseTuple(args, "s", &ifname)) {
        Py_DECREF(grpList);
		return NULL;
    }

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0){
        Py_DECREF(grpList);
		PyErr_SetFromErrno(OException);
		return NULL;
	}

    memset(&ifgr, 0, sizeof(ifgr));
    strlcpy(ifgr.ifgr_name, ifname, IFNAMSIZ);

    if (ioctl(s, SIOCGIFGROUP, (caddr_t)&ifgr) == -1) {
        Py_DECREF(grpList);
        PyErr_SetFromErrno(OException);
        return NULL;
    }

    len = ifgr.ifgr_len;
    ifgr.ifgr_groups =
        (struct ifg_req *)calloc(len / sizeof(struct ifg_req),
        sizeof(struct ifg_req));
    if (ifgr.ifgr_groups == NULL) {
        PyErr_SetFromErrno(OException);
        goto error;
    }

    if (ioctl(s, SIOCGIFGROUP, (caddr_t)&ifgr) == -1) {
        PyErr_SetFromErrno(OException);
        goto error;
    }

    for (ifg = ifgr.ifgr_groups; ifg && len >= sizeof(struct ifg_req); ifg++) {
        len -= sizeof(struct ifg_req);
        if (strcmp(ifg->ifgrq_group, "all")) {
            if (!(tmp = PyString_FromString(ifg->ifgrq_group))) {
                goto error;
            }
            if (PyList_Append(grpList, tmp) == -1) {
                Py_DECREF(tmp);
                goto error;
            }
            Py_DECREF(tmp);
        }
    }
    free(ifgr.ifgr_groups);
    return grpList;

error:
    Py_DECREF(grpList);
    free(ifgr.ifgr_groups);
	return NULL;
}


static PyMethodDef IfConfigMethods[] = {
	{"getifgroups",		getifgroups,	METH_VARARGS, "Retrieve groups this interface is assigned to"},
	{"setifgroup",		setifgroup,	    METH_VARARGS, "Assign this interface to a group"},
	{"unsetifgroup",	unsetifgroup,	METH_VARARGS, "Unassign this interface from a group"},
	{"getifaddrs",		pyGetifaddrs,	METH_VARARGS, "Retrieve an interface list."},
	{"getifinfo",		getifinfo,		METH_VARARGS, "Retrieve info on a given interface."},
	{"setifdescr",		setifdescr,		METH_VARARGS, "Set interface description."},
	{"setifflags",		setifflags,		METH_VARARGS, "Set interface flags."},
	{"setifmtu",		setifmtu,		METH_VARARGS, "Set interface MTU."},
	{"setifmetric",		setifmetric,	METH_VARARGS, "Set interface metric."},
	{"getifmedia",		getifmedia,		METH_VARARGS, "Get interface media information."},
	{"create",			create,			METH_VARARGS, "Create a new interface."},
	{"destroy",			destroy,		METH_VARARGS, "Destroy an interface."},
	{"addaddr",			addaddr,		METH_VARARGS, "Add an address to an interface."},
	{"deladdr",			deladdr,		METH_VARARGS, "Delete an address from an interface."},
	{NULL, NULL, 0, NULL}		 /* Sentinel */
};


void init_ifconfig(void){
	PyObject *module, *global;
	module = Py_InitModule("_ifconfig", IfConfigMethods);
	global = PyImport_ImportModule("_global");
    OException = PyObject_GetAttrString(global, "OException");
}
