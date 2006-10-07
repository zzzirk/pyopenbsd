#!/usr/bin/env python
"""
    pdump is a rudimentary tcpdump implementation based on PyOpenBSD.
"""
import sys, signal, optparse
import openbsd.pcap


def main():
    parser = optparse.OptionParser(usage="pdump.py [-i interface] [-r filename] [expression]")
    parser.add_option("-i", None,   dest="interface", help="Interface to monitor.")
    parser.add_option("-r", None,   dest="filename", help="PCap dump file.")
    parser.add_option("-e", None,   action="append", dest="expression",
                                    help="Python expression for data extraction.")

    options, args = parser.parse_args()

    doneOnEmpty = None
    if options.interface:
        feed = openbsd.pcap.Live(options.interface)
    elif options.filename:
        feed = openbsd.pcap.Offline(options.filename)
        doneOnEmpty = 1
    else:
        feed = openbsd.pcap.Live()
    feed.filter(" ".join(args))
    try:
        while 1:
            x = feed.next(interpret=1)
            if x:
                if options.expression:
                    values = []
                    for i in options.expression:
                        values.append(eval(i, {}, {"p": x[0]}))
                    print " ".join([str(i) for i in values])
                else:
                    print x[1].strftime("%b %d %H:%M:%S"), x[0]
            elif doneOnEmpty:
                return
    except KeyboardInterrupt:
        pass
    if hasattr(feed, "stats"):
        print "\n%(ps_recv)s packets recieved by filter.\n%(ps_drop)s packets dropped by kernel."%feed.stats()


if __name__ == "__main__":
    try:
        main()
    except openbsd.pcap.PcapError, val:
        print >> sys.stderr, "pdump.py:", val
        sys.exit(1)
