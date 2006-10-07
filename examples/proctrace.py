#!/usr/bin/env python
import sys
from openbsd.kqueue import *
"""
    This simple example illustrates the use of the KEvent module. The program
    takes a process ID as an argument, and traces the program through forks and
    execs. 
"""

def main():
    if len(sys.argv) != 2:
        print "Usage: ptrace.py pid"
        sys.exit(1)
    kq = KQueue()
    ev = EProc( ident=int(sys.argv[1]),
                flags=EV_ADD,
                fflags=EProc.NOTE_FORK|EProc.NOTE_EXEC|EProc.NOTE_TRACK|EProc.NOTE_EXIT)
    kq.kevent(changelist=[ev])

    while 1:
        evs = kq.kevent(nevents=10)
        for i in evs:
            if (i.fflags & EProc.NOTE_CHILD):
                print "Process %s forked %s"%(i.data, i.ident)
            if (i.fflags & EProc.NOTE_FORK):
                print "Process %s called fork()"%(i.ident)
            if (i.fflags & EProc.NOTE_EXEC):
                print "Process %s called exec()"%(i.ident)
            if (i.fflags & EProc.NOTE_EXIT):
                print "Process %s exited"%(i.ident)
            if (i.fflags & EProc.NOTE_TRACKERR):
                print "Could not attach to child of %s"%(i.ident)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
