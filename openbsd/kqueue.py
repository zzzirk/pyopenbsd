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
import os, _kqueue
from _sysvar import *
from _global import *

EV_ADD      = EV_ADD
EV_ENABLE   = EV_ENABLE
EV_DISABLE  = EV_DISABLE
EV_DELETE   = EV_DELETE
EV_ONESHOT  = EV_ONESHOT
EV_CLEAR    = EV_CLEAR
EV_EOF      = EV_EOF
EV_ERROR    = EV_ERROR


class _Event:
    """
        Event base class.
    """
    _flags = {
        EV_ADD:         "ADD",
        EV_ENABLE:      "ENABLE",
        EV_DISABLE:     "DISABLE",
        EV_DELETE:      "DELETE",
        EV_ONESHOT:     "ONESHOT",
        EV_CLEAR:       "CLEAR",
        EV_EOF:         "EOF",
        EV_ERROR:       "ERROR"
    }
    def __init__(self, ident, flags=0, fflags=0, udata=None):
        """
            The parameter names to this function were chosen to correspond with
            the attributes of struct kevent. Please see kqueue(2) for more information.

                ident  - Identifier for this event
                flags  - Action flags 
                fflags - Filter flags
                udata  - Opaque user data
        """
        self.ident = ident
        self.flags = flags
        self.fflags = fflags
        self.udata = udata
        self.data = 0

    def _getFlagStr(self, val, fdict):
        flist = []
        for i in fdict:
            if val & i:
                flist.append(fdict[i])
        return "|".join(flist)

    def __repr__(self):
        flags = self._getFlagStr(self.flags, self._flags)
        fflags = self._getFlagStr(self.fflags, self._fflags)
        return "%s(ident=%s, flags=%s, fflags=%s)"%(self.NAME, self.ident, flags, fflags)


class _FileEvent(_Event):
    def __init__(self, *args, **kwargs):
        """
            Takes either an integer representing an open file, or a Python file
            object.
        """
        _Event.__init__(self, *args, **kwargs)
        try:
            self.ident = int(self.ident)
        except TypeError:
            self.ident = self.ident.fileno()


class ERead(_FileEvent):
    NAME = "Read"
    NOTE_LOWAT      = NOTE_LOWAT
    NOTE_EOF        = NOTE_EOF
    _filter         = EVFILT_READ
    _fflags = {
        NOTE_LOWAT:     "LOWAT",
        NOTE_EOF:       "EOF"
    }


class EWrite(_FileEvent):
    NAME = "Write"
    _filter         = EVFILT_WRITE


class EVNode(_FileEvent):
    NAME = "VNode"
    NOTE_DELETE     = NOTE_DELETE
    NOTE_WRITE      = NOTE_WRITE
    NOTE_EXTEND     = NOTE_EXTEND
    NOTE_TRUNCATE   = NOTE_TRUNCATE
    NOTE_ATTRIB     = NOTE_ATTRIB
    NOTE_LINK       = NOTE_LINK
    NOTE_RENAME     = NOTE_RENAME
    NOTE_REVOKE     = NOTE_REVOKE
    _filter         = EVFILT_VNODE
    _fflags = {
        NOTE_DELETE:    "DELETE",
        NOTE_WRITE:     "WRITE",
        NOTE_EXTEND:    "EXTEND",
        NOTE_TRUNCATE:  "TRUNCATE",
        NOTE_ATTRIB:    "ATTRIB",
        NOTE_LINK:      "LINK",
        NOTE_RENAME:    "RENAME",
        NOTE_REVOKE:    "REVOKE"
    }


class EProc(_Event):
    NAME = "Proc"
    NOTE_EXIT       = NOTE_EXIT
    NOTE_FORK       = NOTE_FORK
    NOTE_EXEC       = NOTE_EXEC
    NOTE_TRACK      = NOTE_TRACK
    NOTE_TRACKERR   = NOTE_TRACKERR
    NOTE_CHILD      = NOTE_CHILD
    _filter         = EVFILT_PROC
    _fflags = {
        NOTE_EXIT:      "EXIT",
        NOTE_FORK:      "FORK",
        NOTE_EXEC:      "EXEC",
        NOTE_TRACK:     "TRACK",
        NOTE_TRACKERR:  "TRACKERR",
        NOTE_CHILD:     "CHILD",
    }


class ESignal(_Event):
    NAME = "Signal"
    _filter         = EVFILT_SIGNAL


class KQueue:
    _EventDict = {
        EVFILT_SIGNAL:  ESignal,
        EVFILT_PROC:    EProc,
        EVFILT_READ:    ERead,
        EVFILT_WRITE:   EWrite,
        EVFILT_VNODE:   EVNode
    }
    def __init__(self):
        self._kq    = _kqueue.kqueue()

    def kevent(self, changelist=None, nevents=0, timeout=None):
        """
            changelist  - A list of event objects. May be None for no changes.
            nevents     - Number of events to retrieve.
            timeout     - Timeout in seconds (may be fracitonal). None to wait
                          indefinitely.
        """
        if not timeout is None:
            seconds, fraction = divmod(timeout, 1)
            # Convert to (seconds, nanoseconds)
            timeout = (seconds, fraction * 10000)
        retval = _kqueue.kevent(self._kq, changelist, nevents, timeout)
        if retval:
            retlst = []
            for i in retval:
                event = self._EventDict[i[0]](*i[1:5])
                event.data = i[5]
                retlst.append(event)
            return retlst
        else:
            return retval

    def __del__(self):
        os.close(self._kq)
