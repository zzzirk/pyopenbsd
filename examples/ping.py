#!/usr/bin/env python
"""
    ping.py is a minimal implementation of ping in Python.
"""
import select, socket, time, sys, os, signal, errno, optparse
import openbsd.utils
from openbsd.packet import *

TSTAMP_PRECISION = 1000000

class ICMPPing:
    def __init__(self, dst, wait, count, dontfrag, ttl, size):
        self.dst, self.wait, self.count, self.size = dst, wait, count, size
        self.identifier = os.getpid()
        self.dst = socket.gethostbyname(dst)
        if size > 8:
            self.rttMin, self.rttMax, self.rttAvg = 0, 0, 0
            self.calculateRTT = 1
        else:
            self.calculateRTT = 0
        self.numSent, self.numRecv = 0, 0
        self.seq = 0
        # Create our template packet
        self.ppack = createPacket(IP, ICMPEchoRequest)
        self.ppack["ip"].dst = self.dst
        self.ppack["ip"].ttl = ttl
        if dontfrag:
            self.ppack["ip"].flags = "df"
        self.ppack["icmp"].identifier = self.identifier

        self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        signal.signal(signal.SIGALRM, self)
        print "PING: %s (%s) 56 data bytes"%(self.dst, self.dst)
        self(0, 0)

    def loop(self):
        while 1:
            try:
                reply = self.s.recvfrom(2000)[0]
            except socket.error, val:
                if val[0] == errno.EINTR:
                    continue
                else:
                    raise
            except KeyboardInterrupt:
                print "\n--- %s ping statistics ---"%(self.dst)
                args = (self.numSent, self.numRecv, round(((self.numSent-self.numRecv)/self.numSent)*100))
                print "%d packets transmitted, %d packets received, %2.2f%% packet loss"%args
                if self.calculateRTT:
                    print "round-trip min/avg/max = %.3f / %.3f / %.3f ms"%(
                                                                                self.rttMin,
                                                                                self.rttAvg/self.numRecv,
                                                                                self.rttMax
                                                                            )
                sys.exit(1)

            now = long(time.time()*TSTAMP_PRECISION)
            p = Packet(IP, reply)
            if p.has_key("icmpechoreply"):
                if p["icmpechoreply"].identifier == self.identifier:
                    self.numRecv += 1
                    print len(p.getRaw()) - p["icmp"].offset,
                    print "bytes from %s:"%p["ip"].src,
                    print "icmp_seq=%s"%p["icmp"].seq_num,
                    print "ttl=%s"%p["ip"].ttl,
                    if self.calculateRTT:
                        elapsed = float(now - openbsd.utils.multiord(p["icmp"].payload[:8]))
                        elapsed = elapsed/(TSTAMP_PRECISION)*1000
                        self.rttAvg += elapsed
                        if elapsed > self.rttMax:
                            self.rttMax = elapsed
                        if elapsed < self.rttMin:
                            self.rttMin = elapsed
                        print "time=%.4f ms"%elapsed,
                    print

            if not (self.count < 0):
                if self.count == 1:
                    sys.exit(1)
                else:
                    self.count -= 1

    def _generatePayload(self):
        if (self.size - 8 < 0):
            return "a" * (self.size-8)
        return openbsd.utils.multichar(long(time.time() * TSTAMP_PRECISION), 8) + "a"*(self.size - 8)

    def __call__(self, sig, sf):
        """
            Sends a ping packet, and schedules another alarm for one second
            from now.
        """
        self.ppack["icmp"].seq_num = self.seq
        self.ppack["icmp"].payload = self._generatePayload()
        self.ppack.finalise()
        self.s.sendto(self.ppack.getRaw(), (self.dst, 0))
        self.numSent += 1
        self.seq += 1
        signal.alarm(self.wait)


def main():
    parser = optparse.OptionParser(usage="ping.py [options] host")
    parser.add_option("-D", None,   action="store_true", dest="dontfrag", default=False,
                                    help="Set the \"don't fragment\" flag on outbound packets.")
    parser.add_option("-c", None,   dest="count", default=-1, type="int", metavar="N",
                                    help="Send N packets, then quit.")
    parser.add_option("-w", None,   dest="wait", default=1, type="int", metavar="N",
                                    help="Wait N seconds between packets (default 1).")
    parser.add_option("-t", None,   dest="ttl", default=255, type="int", metavar="N",
                                    help="Set TTL (default 255).")
    parser.add_option("-s", None,   dest="size", default=48, type="int", metavar="N",
                                    help="Set the length of the payload (default 48).")
    o, args = parser.parse_args()

    if (len(args) != 1):
        usage()
        sys.exit(2)

    i = ICMPPing(args[0], o.wait, o.count, o.dontfrag, o.ttl, o.size)
    i.loop()


if __name__ == "__main__":
    main()
