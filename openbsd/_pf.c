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

#include <Python.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>
#include <crypto/md5.h>
#include <err.h>
#include <stdlib.h>

#include "_cutils.h"

#define FCNT_NAMES { \
	"searches", \
	"inserts", \
	"removals", \
	NULL \
}

PyObject *OException;

static int dev;


PyObject *_noargsioctl(PyObject *self, PyObject *args, int ioc){
	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	if (ioctl(dev, ioc) < 0){
		PyErr_SetFromErrno(OException);
		return NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}


PyObject *start(PyObject *self, PyObject *args){
	return _noargsioctl(self, args, DIOCSTART);
}


PyObject *stop(PyObject *self, PyObject *args){
	return _noargsioctl(self, args, DIOCSTOP);
}


PyObject *start_altq(PyObject *self, PyObject *args){
	return _noargsioctl(self, args, DIOCSTARTALTQ);
}


PyObject *stop_altq(PyObject *self, PyObject *args){
	return _noargsioctl(self, args, DIOCSTOPALTQ);
}


PyObject *add_table(PyObject *self, PyObject *args){
	struct pfr_table	table;
	struct pfioc_table	io;
	int tflags, iflags;
	char *anchor, *name;

	if (!PyArg_ParseTuple(args, "ssii", &name, &anchor, &tflags, &iflags))
		return NULL;

	bzero(&table, sizeof(table));
	bzero(&io, sizeof io);

	strlcpy(table.pfrt_name, name, sizeof(table.pfrt_name));
	if (anchor)
		strlcpy(table.pfrt_anchor, anchor, sizeof(table.pfrt_anchor));
	table.pfrt_flags = tflags;

	io.pfrio_flags = iflags;
	io.pfrio_buffer = &table;
	io.pfrio_esize = sizeof(table);
	io.pfrio_size = 1;

	if (ioctl(dev, DIOCRADDTABLES, &io)){
		PyErr_SetFromErrno(OException);
		return NULL;
	}
	return PyInt_FromLong((long) io.pfrio_nadd);
}


PyObject *delete_table(PyObject *self, PyObject *args){
	struct pfr_table	table;
	struct pfioc_table	io;
	int tflags, iflags;
	char *anchor, *name;

	if (!PyArg_ParseTuple(args, "ssii", &name, &anchor, &tflags, &iflags))
		return NULL;

	bzero(&table, sizeof(table));
	bzero(&io, sizeof io);

	strlcpy(table.pfrt_name, name, PF_TABLE_NAME_SIZE);
	if (anchor)
		strlcpy(table.pfrt_anchor, anchor, sizeof(table.pfrt_anchor));
	table.pfrt_flags = tflags;

	io.pfrio_flags = iflags;
	io.pfrio_buffer = &table;
	io.pfrio_esize = sizeof(table);
	io.pfrio_size = 1;

	if (ioctl(dev, DIOCRDELTABLES, &io)){
		PyErr_SetFromErrno(OException);
		return NULL;
	}
	return PyInt_FromLong((long) io.pfrio_ndel);
}


PyObject *clear_tables(PyObject *self, PyObject *args){
	struct pfr_table	table;
	struct pfioc_table	io;
	int iflags;
	char *anchor;

	if (!PyArg_ParseTuple(args, "si", &anchor, &iflags))
		return NULL;

	bzero(&table, sizeof(table));
	bzero(&io, sizeof io);

	strlcpy(table.pfrt_anchor, anchor, sizeof(table.pfrt_anchor));

	io.pfrio_flags = iflags;
	io.pfrio_table = table;

	if (ioctl(dev, DIOCRCLRTABLES, &io)){
		PyErr_SetFromErrno(OException);
		return NULL;
	}

	return PyInt_FromLong((long) io.pfrio_ndel);
}


PyObject *add_address(PyObject *self, PyObject *args){
	struct pfr_table	table;
	struct pfioc_table	io;
	struct pfr_addr paddr;
	int iflags, af, addrlen;
	unsigned int netmask;
	char *anchor, *address, *name;

	if (!PyArg_ParseTuple(args, "sss#iIi", &anchor, &name, &address, &addrlen, &af, &netmask, &iflags))
		return NULL;

	bzero(&table, sizeof(table));
	bzero(&io, sizeof io);
	bzero(&paddr, sizeof paddr);

	strlcpy(table.pfrt_anchor, anchor, sizeof(table.pfrt_anchor));
	strlcpy(table.pfrt_name, name, sizeof(table.pfrt_name));

	io.pfrio_flags = iflags;
	io.pfrio_table = table;

	io.pfrio_esize = sizeof(paddr);
	io.pfrio_size = 1;
	io.pfrio_buffer = &paddr;

	paddr.pfra_af = af;
	paddr.pfra_net = netmask;
	if (af == AF_INET){
		if (addrlen != 4){
			PyErr_SetString(OException, "Invalid address specification.");
			return NULL;
		}
		memcpy(&paddr.pfra_ip4addr.s_addr, address, addrlen);
	} else if (af == AF_INET6){
		if (addrlen != 16){
			PyErr_SetString(OException, "Invalid address specification.");
			return NULL;
		}
		memcpy(&paddr.pfra_ip6addr.s6_addr, address, addrlen);
	} else {
		PyErr_SetString(OException, "Invalid address specification.");
		return NULL;
	}

	if (ioctl(dev, DIOCRADDADDRS, &io)){
		PyErr_SetFromErrno(OException);
		return NULL;
	}
	return PyInt_FromLong((long) io.pfrio_nadd);
}


PyObject *delete_address(PyObject *self, PyObject *args){
	struct pfr_table	table;
	struct pfioc_table	io;
	struct pfr_addr paddr;
	int iflags, af, addrlen;
	unsigned int netmask;
	char *anchor, *address, *name;

	if (!PyArg_ParseTuple(args, "sss#iIi", &anchor, &name, &address, &addrlen, &af, &netmask, &iflags))
		return NULL;

	bzero(&table, sizeof(table));
	bzero(&io, sizeof io);
	bzero(&paddr, sizeof paddr);

	strlcpy(table.pfrt_anchor, anchor, sizeof(table.pfrt_anchor));
	strlcpy(table.pfrt_name, name, sizeof(table.pfrt_name));

	io.pfrio_flags = iflags;
	io.pfrio_table = table;

	io.pfrio_esize = sizeof(paddr);
	io.pfrio_size = 1;
	io.pfrio_buffer = &paddr;

	paddr.pfra_af = af;
	paddr.pfra_net = netmask;
	if (af == AF_INET){
		if (addrlen != 4){
			PyErr_SetString(OException, "Invalid address specification.");
			return NULL;
		}
		memcpy(&paddr.pfra_ip4addr.s_addr, address, addrlen);
	} else if (af == AF_INET6){
		if (addrlen != 16){
			PyErr_SetString(OException, "Invalid address specification.");
			return NULL;
		}
		memcpy(&paddr.pfra_ip6addr.s6_addr, address, addrlen);
	} else {
		PyErr_SetString(OException, "Invalid address specification.");
		return NULL;
	}

	if (ioctl(dev, DIOCRDELADDRS, &io)){
		PyErr_SetFromErrno(OException);
		return NULL;
	}
	return PyInt_FromLong((long) io.pfrio_ndel);
}


PyObject *get_addresses(PyObject *self, PyObject *args){
	struct pfr_table	table;
	struct pfr_addr	*buf;
	struct pfioc_table	io;
	PyObject *lst, *dct;
	int i;
    int len = 0;
	char *anchor, *name;

	if (!PyArg_ParseTuple(args, "ss", &anchor, &name))
		return NULL;

	bzero(&table, sizeof(table));
	bzero(&io, sizeof io);

	strlcpy(table.pfrt_anchor, anchor, sizeof(table.pfrt_anchor));
	strlcpy(table.pfrt_name, name, sizeof(table.pfrt_name));
	io.pfrio_table = table;

	io.pfrio_esize = sizeof(struct pfr_addr);

    for (;;){
        if (io.pfrio_size){
            if (io.pfrio_buffer)
                free(io.pfrio_buffer);
            io.pfrio_buffer = calloc(io.pfrio_size, sizeof(struct pfr_addr));
            if (io.pfrio_buffer == NULL){
                PyErr_SetFromErrno(OException);
                return NULL;
            }
        }
	    if (ioctl(dev, DIOCRGETADDRS, &io)){
            if (io.pfrio_buffer)
                free(io.pfrio_buffer);
            PyErr_SetFromErrno(OException);
            return NULL;
        }
        if (len == io.pfrio_size || io.pfrio_size == 0)
                break;
        len = io.pfrio_size;
    }

    buf = (struct pfr_addr*) io.pfrio_buffer;
	if (!(dct = PyDict_New())){
		free(buf);
		return NULL;
	}

	if (!(lst = PyList_New(0)))
		return NULL;
	for (i = 0; i < io.pfrio_size; i++){
		if (!(dct = PyDict_New())){
			Py_DECREF(lst);
			free(buf);
			return NULL;
		}
		stealingSetItem(dct, "af", PyLong_FromLong((long) buf[i].pfra_af));
		stealingSetItem(dct, "mask", PyLong_FromLong((long) buf[i].pfra_net));
		if (buf[i].pfra_af == AF_INET){
			stealingSetItem(dct, "address", PyString_FromStringAndSize((char*)(&buf[i].pfra_ip4addr.s_addr), 4));
		} else if (buf[i].pfra_af == AF_INET6) {
			stealingSetItem(dct, "address", PyString_FromStringAndSize((char*)(&buf[i].pfra_ip6addr.s6_addr), 16));
		} else {
			Py_DECREF(dct);
			Py_DECREF(lst);
			free(buf);
			PyErr_SetString(OException, "Could not add address.");
			return NULL;
		}
		if (PyList_Append(lst, dct) < 0){
			Py_DECREF(dct);
			Py_DECREF(lst);
			free(buf);
			return NULL;
		}
	}
	free(buf);
	return lst;
}


PyObject *get_tables(PyObject *self, PyObject *args){
	struct pfr_table	filter;
	struct pfr_table	*buf;
	struct pfioc_table	io;
	PyObject *dct;
	int i;
    int len = 0;
	char *anchor;

	if (!PyArg_ParseTuple(args, "s", &anchor))
		return NULL;

	bzero(&io, sizeof io);
	bzero(&filter, sizeof filter);
	strlcpy(filter.pfrt_anchor, anchor, sizeof(filter.pfrt_anchor));
	io.pfrio_table = filter;
	io.pfrio_esize = sizeof(struct pfr_table);

    for (;;){
        if (io.pfrio_size){
            if (io.pfrio_buffer)
                free(io.pfrio_buffer);
            io.pfrio_buffer = calloc(io.pfrio_size, sizeof(struct pfr_table));
            if (io.pfrio_buffer == NULL){
                PyErr_SetFromErrno(OException);
                return NULL;
            }
        }
	    if (ioctl(dev, DIOCRGETTABLES, &io)){
            if (io.pfrio_buffer)
                free(io.pfrio_buffer);
            PyErr_SetFromErrno(OException);
            return NULL;
        }
        if (len == io.pfrio_size || io.pfrio_size == 0)
                break;
        len = io.pfrio_size;
    }

	if (!io.pfrio_size)
			return PyDict_New();
	buf = (struct pfr_table*)io.pfrio_buffer;
	if (!(dct = PyDict_New())){
		free(buf);
		return NULL;
	}
	for (i = 0; i < io.pfrio_size; i++){
		stealingSetItem(dct, buf[i].pfrt_name, PyLong_FromLong((long) buf[i].pfrt_flags));
	}
	free(buf);
	return dct;
}


PyObject *get_anchors(PyObject *self, PyObject *args){
	PyObject *anchors, *rulename;
	struct pfioc_ruleset rs;
	char *path;
	int num, i;
	
	if (!PyArg_ParseTuple(args, "s", &path))
		return NULL;

	bzero(&rs, sizeof(rs));
	strlcpy(rs.path, path, sizeof(rs.path));

	if (ioctl(dev, DIOCGETRULESETS, &rs)){
		PyErr_SetFromErrno(OException);
		return NULL;
	}

	if (!(anchors = PyList_New(0)))
		return NULL;

	num = rs.nr;
	for (i = 0; i < num; ++i) {
		rs.nr = i;
		if (ioctl(dev, DIOCGETRULESET, &rs)){
			Py_DECREF(anchors);
			PyErr_SetFromErrno(OException);
			return NULL;
		}
		rulename = PyString_FromString(rs.name);
		if (PyList_Append(anchors, rulename) < 0){
			Py_DECREF(anchors);
			Py_DECREF(rulename);
			return NULL;
		}
		Py_DECREF(rulename);
	}
	return anchors;
}


PyObject *get_ifaces(PyObject *self, PyObject *args){
	PyObject *dct, *info, *lst;
	struct pfioc_iface io;
	struct pfi_kif *ptr;
	int i, j, af, dir, act;
    int len = 0;
	
	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	bzero(&io, sizeof(io));
	io.pfiio_esize = sizeof(struct pfi_kif);
    
    for (;;){
        if (io.pfiio_size){
            if (io.pfiio_buffer)
                free(io.pfiio_buffer);
            io.pfiio_buffer = calloc(io.pfiio_size, sizeof(struct pfi_kif));
            if (io.pfiio_buffer == NULL){
                PyErr_SetFromErrno(OException);
                return NULL;
            }
        }
        if (ioctl(dev, DIOCIGETIFACES, &io)){
            if (io.pfiio_buffer)
                free(io.pfiio_buffer);
            PyErr_SetFromErrno(OException);
            return NULL;
        }
        if (len == io.pfiio_size || io.pfiio_size == 0)
                break;
        len = io.pfiio_size;
    }

	if (!(dct = PyDict_New()))
		return NULL;
	for (i = 0; i < io.pfiio_size; i++){
		if (!(info = PyDict_New()))
			goto error;
		ptr = io.pfiio_buffer;
		stealingSetItem(info, "tzero", PyLong_FromLong((long) ptr[i].pfik_tzero)); 
		stealingSetItem(info, "rules", PyLong_FromLong((long) ptr[i].pfik_rules)); 
		stealingSetItem(info, "states", PyLong_FromLong((long) ptr[i].pfik_states)); 
		stealingSetItem(info, "flags", PyLong_FromLong((long) ptr[i].pfik_flags)); 
		if (!(lst = PyList_New(0))){
			Py_DECREF(info);
			goto error;
		}
        /* Elaborate way to do a depth-first traversal. */
		for (j = 0; j < 8; j++) {
			af = (j>>2) & 1;
			dir = (j>>1) &1;
			act = j & 1;
			if (PyList_Append(lst, PyLong_FromLong((long) ptr[i].pfik_packets[af][dir][act])) < 0){
				Py_DECREF(lst);
				Py_DECREF(info);
				goto error;
			}
			if (PyList_Append(lst, PyLong_FromLong((long) ptr[i].pfik_bytes[af][dir][act])) < 0){
				Py_DECREF(lst);
				Py_DECREF(info);
				goto error;
			}
		}
		stealingSetItem(info, "trafinfo", lst); 
		stealingSetItem(dct, ptr[i].pfik_name, info);
	}
	return dct;
error:
	free(io.pfiio_buffer);
	Py_DECREF(dct);
	return NULL;
}


PyObject *set_log_iface(PyObject *self, PyObject *args){
	struct pfioc_if iface;
	char *name;
	
	if (!PyArg_ParseTuple(args, "z", &name))
		return NULL;
        
	bzero(&iface, sizeof(iface));
    if (name)
        strlcpy(iface.ifname, name, sizeof(iface.ifname));

	if (ioctl(dev, DIOCSETSTATUSIF, &iface)){
		PyErr_SetFromErrno(OException);
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}


PyObject *clear_stats(PyObject *self, PyObject *args){
	return _noargsioctl(self, args, DIOCCLRSTATUS);
}


const char	*pf_reasons[PFRES_MAX+1] = PFRES_NAMES;
const char	*pf_lcounters[LCNT_MAX+1] = LCNT_NAMES;
const char	*pf_fcounters[FCNT_MAX+1] = FCNT_NAMES;
const char	*pf_scounters[FCNT_MAX+1] = FCNT_NAMES;

PyObject *get_stats(PyObject *self, PyObject *args){
    PyObject *dct, *lst, *subdct;
    int i, j, k;
	struct pf_status pfstat;
	
	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	bzero(&pfstat, sizeof(pfstat));

	if (ioctl(dev, DIOCGETSTATUS, &pfstat)){
		PyErr_SetFromErrno(OException);
		return NULL;
	}

	if (!(dct = PyDict_New()))
		return NULL;
	stealingSetItem(dct, "running", PyLong_FromLong((long) pfstat.running)); 
	stealingSetItem(dct, "states", PyLong_FromLong((long) pfstat.states)); 
	stealingSetItem(dct, "src_nodes", PyLong_FromLong((long) pfstat.src_nodes)); 
	stealingSetItem(dct, "since", PyLong_FromLong((long) pfstat.since)); 
	stealingSetItem(dct, "debug", PyLong_FromLong((long) pfstat.debug)); 
	stealingSetItem(dct, "hostid", PyLong_FromLong((long) pfstat.hostid)); 
	stealingSetItem(dct, "ifname", PyString_FromString(pfstat.ifname)); 
	stealingSetItem(dct, "checksum", PyString_FromStringAndSize(pfstat.pf_chksum, MD5_DIGEST_LENGTH)); 

	if (!(subdct = PyDict_New()))
        goto error;
    for (i = 0; i < PFRES_MAX; i++) {
	    stealingSetItem(subdct, (char*)pf_reasons[i], PyLong_FromLong((long) pfstat.counters[i])); 
    }
	stealingSetItem(dct, "counters", subdct); 

	if (!(subdct = PyDict_New()))
        goto error;
    for (i = 0; i < LCNT_MAX; i++) {
	    stealingSetItem(subdct, (char*)pf_lcounters[i], PyLong_FromLong((long) pfstat.lcounters[i])); 
    }
	stealingSetItem(dct, "limits", subdct); 

	if (!(subdct = PyDict_New()))
        goto error;
    for (i = 0; i < FCNT_MAX; i++) {
	    stealingSetItem(subdct, (char*)pf_fcounters[i], PyLong_FromLong((long) pfstat.fcounters[i])); 
    }
	stealingSetItem(dct, "state_table", subdct); 

	if (!(subdct = PyDict_New()))
        goto error;
    for (i = 0; i < SCNT_MAX; i++) {
	    stealingSetItem(subdct, (char*)pf_scounters[i], PyLong_FromLong((long) pfstat.scounters[i])); 
    }
	stealingSetItem(dct, "source_tracking_table", subdct); 

	if (!(lst = PyList_New(0)))
        goto error;
    for (i = 0; i < 2; i++){
        for (j = 0; j < 2; j++){
            for (k = 0; k < 3; k++){
                PyList_Append(lst, PyLong_FromLong((long) pfstat.pcounters[i][j][k]));
            }
        }
    }
	stealingSetItem(dct, "packets", lst); 

	if (!(lst = PyList_New(0)))
        goto error;
    for (i = 0; i < 2; i++){
        for (j = 0; j < 2; j++){
            PyList_Append(lst, PyLong_FromLong((long) pfstat.bcounters[i][j]));
        }
    }
	stealingSetItem(dct, "bytes", lst); 

	return dct;

error:
	Py_DECREF(dct);
	return NULL;
}


PyObject *get_states(PyObject *self, PyObject *args){
    PyObject *lst, *dct, *src, *dst, *lan, *gwy, *ext;
	struct pfioc_states ps;
    struct pfsync_state *p;
    int i;
    int len = 0;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	bzero(&ps, sizeof ps);
    for (;;){
        if (ps.ps_len){
            if (ps.ps_buf)
                free(ps.ps_buf);
            ps.ps_buf = malloc(ps.ps_len);
            if (ps.ps_buf == NULL){
                PyErr_SetFromErrno(OException);
                return NULL;
            }
        }
	    if (ioctl(dev, DIOCGETSTATES, &ps)){
            if (ps.ps_buf)
                free(ps.ps_buf);
            PyErr_SetFromErrno(OException);
            return NULL;
        }
        if (len == ps.ps_len || ps.ps_len == 0)
                break;
        len = ps.ps_len;
    }

	if (!(lst = PyList_New(0)))
		return NULL;

	p = ps.ps_states;
	for (i = 0; i < ps.ps_len; i += sizeof(*p), p++) {
		if (!(dct = PyDict_New())){
			Py_DECREF(lst);
			free(ps.ps_buf);
			return NULL;
		}

		stealingSetItem(dct, "proto", PyLong_FromLong((long) p->proto)); 
		stealingSetItem(dct, "af", PyLong_FromLong((long) p->af)); 
		stealingSetItem(dct, "direction", PyLong_FromLong((long) p->direction)); 
		stealingSetItem(dct, "log", PyLong_FromLong((long) p->log)); 
		stealingSetItem(dct, "timeout", PyLong_FromLong((long) p->timeout)); 
		stealingSetItem(dct, "sync_flags", PyLong_FromLong((long) p->sync_flags)); 
		stealingSetItem(dct, "allow_opts", PyLong_FromLong((long) p->allow_opts)); 
		stealingSetItem(dct, "creation", PyLong_FromLong((long) p->creation)); 
		stealingSetItem(dct, "expire", PyLong_FromLong((long) p->expire)); 
		stealingSetItem(dct, "ifname", PyString_FromString(p->ifname)); 
        stealingSetItem(dct, "packets", 
                PyTuple_Pack(
                        2,
                        PyLong_FromLong((long) p->packets[0]),
                        PyLong_FromLong((long) p->packets[1])
                    )
        );
        stealingSetItem(dct, "bytes", 
                PyTuple_Pack(
                        2,
                        PyLong_FromLong((long) p->bytes[0]),
                        PyLong_FromLong((long) p->bytes[1])
                    )
        );

		if (!(src = PyDict_New())){
			Py_DECREF(lst);
			Py_DECREF(dct);
			free(ps.ps_buf);
			return NULL;
		}
		stealingSetItem(src, "state",      PyLong_FromLong((long)p->src.state)); 
		stealingSetItem(src, "wscale",     PyLong_FromLong((long)p->src.wscale)); 
        stealingSetItem(dct, "src", src);

		if (!(dst = PyDict_New())){
			Py_DECREF(lst);
			Py_DECREF(dct);
			free(ps.ps_buf);
			return NULL;
		}
		stealingSetItem(dst, "state",      PyLong_FromLong((long)p->dst.state)); 
		stealingSetItem(dst, "wscale",     PyLong_FromLong((long)p->dst.wscale)); 
        stealingSetItem(dct, "dst", dst);

		if (!(lan = PyDict_New()) || !(gwy = PyDict_New()) || !(ext = PyDict_New())){
			Py_DECREF(lst);
			Py_DECREF(dct);
			free(ps.ps_buf);
			return NULL;
		}
		if (p->af == AF_INET){
			stealingSetItem(lan, "address", PyString_FromStringAndSize((char*)(&p->lan.addr.v4.s_addr), 4));
			stealingSetItem(gwy, "address", PyString_FromStringAndSize((char*)(&p->gwy.addr.v4.s_addr), 4));
			stealingSetItem(ext, "address", PyString_FromStringAndSize((char*)(&p->ext.addr.v4.s_addr), 4));
		} else if (p->af == AF_INET6) {
			stealingSetItem(lan, "address", PyString_FromStringAndSize((char*)(&p->lan.addr.v6.s6_addr), 16));
			stealingSetItem(gwy, "address", PyString_FromStringAndSize((char*)(&p->gwy.addr.v6.s6_addr), 16));
			stealingSetItem(ext, "address", PyString_FromStringAndSize((char*)(&p->ext.addr.v6.s6_addr), 16));
		} 
		stealingSetItem(lan, "port", PyLong_FromLong((long) ntohs(p->lan.port)));
		stealingSetItem(gwy, "port", PyLong_FromLong((long) ntohs(p->gwy.port)));
		stealingSetItem(ext, "port", PyLong_FromLong((long) ntohs(p->ext.port)));
        stealingSetItem(dct, "lan", lan);
        stealingSetItem(dct, "gwy", gwy);
        stealingSetItem(dct, "ext", ext);


		if (PyList_Append(lst, dct) < 0){
			Py_DECREF(dct);
			Py_DECREF(lst);
			free(ps.ps_buf);
			return NULL;
		}
	}
	free(ps.ps_buf);
	return lst;
}


PyObject *clear_states(PyObject *self, PyObject *args){
	char *name;
	struct pfioc_state_kill psk;
	
	if (!PyArg_ParseTuple(args, "z", &name))
		return NULL;
        
	bzero(&psk, sizeof(psk));
    if (name)
        strlcpy(psk.psk_ifname, name, sizeof(psk.psk_ifname));

	if (ioctl(dev, DIOCCLRSTATES, &psk)){
		PyErr_SetFromErrno(OException);
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}


PyObject *kill_states(PyObject *self, PyObject *args){
	char *name, *src, *dst, *srcmask, *dstmask;
    int af, srclen, dstlen, srcmasklen, dstmasklen;
    unsigned int srcport, dstport;
	struct pfioc_state_kill psk;
	
    if (!PyArg_ParseTuple(args, "izz#z#z#z#II", 
                &af,
                &name, 
                &src,
                &srclen,
                &srcmask,
                &srcmasklen,
                &dst,
                &dstlen,
                &dstmask,
                &dstmasklen,
                &srcport,
                &dstport)
            )
		return NULL;
        
	bzero(&psk, sizeof(psk));
    if (name)
        strlcpy(psk.psk_ifname, name, sizeof(psk.psk_ifname));

    psk.psk_af = af;
    if (af == AF_INET){
        if (src != NULL){
            memcpy(&psk.psk_src.addr.v.a.addr.v4, src, srclen);
            memcpy(&psk.psk_src.addr.v.a.mask.v4, srcmask, srcmasklen);
        }
        if (dst != NULL){
            memcpy(&psk.psk_dst.addr.v.a.addr.v4, dst, dstlen);
            memcpy(&psk.psk_dst.addr.v.a.mask.v4, dstmask, dstmasklen);
        }
    } else if (af == AF_INET6){
        if (src != NULL){
            memcpy(&psk.psk_src.addr.v.a.addr.v6, src, srclen);
            memcpy(&psk.psk_src.addr.v.a.mask.v6, srcmask, srcmasklen);
        }
        if (dst != NULL){
            memcpy(&psk.psk_dst.addr.v.a.addr.v6, dst, dstlen);
            memcpy(&psk.psk_dst.addr.v.a.mask.v6, dstmask, dstmasklen);
        }
    }

    if (srcport != 0){
        psk.psk_src.port[0] = htons(srcport);
        psk.psk_src.port_op = PF_OP_EQ;
    }

    if (dstport != 0){
        psk.psk_dst.port[0] = htons(dstport);
        psk.psk_dst.port_op = PF_OP_EQ;
    }

	if (ioctl(dev, DIOCKILLSTATES, &psk)){
		PyErr_SetFromErrno(OException);
		return NULL;
	}
    return PyLong_FromLong((long) psk.psk_af);
}


PyObject *init(PyObject *self, PyObject *args){
	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	if (dev)
		close(dev);

	// FIXME: Parameterize this? 
	dev = open("/dev/pf", O_RDWR);
	if (dev == -1){
		PyErr_SetFromErrno(OException);
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}


static PyMethodDef PFMethods[] = {
	{"_init",				init,			    METH_VARARGS,	"Initialise the module."},
	{"start",				start,			    METH_VARARGS,	"Start the packet filter."},
	{"stop",				stop,               METH_VARARGS,	"Stop the packet filter."},
	{"start_altq",			start_altq,         METH_VARARGS,	"Start ALTQ."},
	{"stop_altq",			stop_altq,          METH_VARARGS,	"Stop ALTQ."},
	{"add_table",			add_table,          METH_VARARGS,	"Add a table."},
	{"delete_table",		delete_table,       METH_VARARGS,	"Delete a table."},
	{"get_anchors",			get_anchors,        METH_VARARGS,	"Get anchors under a specified path."},
	{"clear_tables",		clear_tables,       METH_VARARGS,	"Clear tables under a specified path."},
	{"get_tables",			get_tables,         METH_VARARGS,	"Retrieve the list of tables under a specified path."},
	{"add_address",			add_address,	    METH_VARARGS,	"Add an address or network to a table."},
	{"delete_address",		delete_address,	    METH_VARARGS,	"Delete an address or network from a table."},
	{"get_addresses",		get_addresses,	    METH_VARARGS,	"Get a list of addresses in a table."},
	{"get_ifaces",			get_ifaces,		    METH_VARARGS,	"Get a list of interfaces and associated stats."},
	{"set_log_iface",		set_log_iface,	    METH_VARARGS,	"Set the logging interface. Data retrieved with get_stats"},
	{"clear_stats",	        clear_stats,	    METH_VARARGS,	"Clear PF statistics."},
	{"get_stats",		    get_stats,          METH_VARARGS,	"Get PF statistics."},
	{"get_states",		    get_states,         METH_VARARGS,	"Get state table entries."},
	{"clear_states",		clear_states,       METH_VARARGS,	"Clear state table entries."},
	{"kill_states",		    kill_states,        METH_VARARGS,	"Kill specified state table entries."},
	{NULL, NULL, 0, NULL}        /* Sentinel */
};


void init_pf(void){
	PyObject *module, *global;
	module = Py_InitModule("_pf", PFMethods);
	global = PyImport_ImportModule("_global");
	OException = PyObject_GetAttrString(global, "OException");
}
