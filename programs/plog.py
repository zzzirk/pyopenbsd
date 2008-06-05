#!/usr/bin/env python
import optparse, time, datetime, gzip, sys, os, errno
import packet.pcap
from openbsd.kqueue import *
"""
    PLog is a unified log reading program. Its features include:
        
        - The ability to fold logs into chronological order.
        - Ability to read and display pcap dump files, including pf log files.
        - Native reading of zipped log files (but not zipped pf log files).
        - Simultaneously following multiple log files in a similar way to "tail
          -f".
        - Monitoring of network devices, a la tcpdump. 
        - Audible warning when new information arrives.
"""

"""
    TODO:
        - Zipped pflog files
        - Add other log types (eg. httpd)
        - Regular expressions and pcap filters
        - Allow users to specify a year that logs should be assumed to
          originate from.
        - Date and time filters?
"""
TIMEFMT = "%b %d %H:%M:%S"

class RLogError(Exception): pass


def getTimeval(logline):
    """
        Parses a log line, and returns a datetime timestamp.

        NOTE: We use the current year as the year value in the returned
        timestamp.
    """
    parts = logline.split()
    logline = " ".join(parts[:3])
    dtime = time.strptime(logline, TIMEFMT)
    return datetime.datetime(datetime.datetime.today().year, *dtime[1:6])


class _LogBase:
    def __init__(self, name, lines, kq):
        """
            name    - name of the file.
            lines   - number of lines from the end of the file to start from.
        """
        self.name, self.lines, self.kq = name, lines, kq
        self.fd = None
        # Has the file been closed at least once?
        self._closed = None 
        self.reopen()

    def __cmp__(self, other):
        # Files with no output are always larger than files with output.
        if self.nextTimestamp is None:
            return 1
        elif other.nextTimestamp is None:
            return -1
        else:
            return cmp(self.nextTimestamp, other.nextTimestamp)

    def __repr__(self):
        return "Logfile: %s"%self.name

    def _close(self):
        self.fd.close()
        self.fd = None
        self._closed = 1

    def _printCurrent(self, names, padding):
        if names:
            print "%*s: "%(padding, self.name),
        print self.nextLine,

    def reopen(self):
        """
            Close and re-open the file if needed.
        """
        if not self.fd:
            self.fd = self._open()
            if self._closed:
                print >> sys.stderr, "%s has been replaced or truncated; reopening."%self.name
            elif not (self.lines is None):
                self._last(self.lines)
                self.lines = None
            self._next()
            if self.kq:
                self._follow(self.kq)
            return 1
        else:
            return 0

    def close(self):
        self.fd.close()


class PCapDump(_LogBase):
    def __init__(self, *args, **kwargs):
        self._linecache = None
        _LogBase.__init__(self, *args, **kwargs)

    def _printCurrent(self, names, padding):
        if names:
            print "%*s: "%(padding, self.name),
        print self.nextTimestamp.strftime(TIMEFMT),
        print self.nextLine

    def _last(self, num):
        """
            In order to view the last N captured packets, we keep a rolling
            buffer of N lines, until we hit the end of the file. Our _next
            method knows about this buffer, and will deliver packets from it
            rather than the file if it has any content.
        """
        self._linecache = []
        while 1:
            x = self.fd.next()
            if not x:
                break
            if num:
                if len(self._linecache) == num:
                    self._linecache.pop()
                self._linecache.append(x)

    def _next(self):
        x = None
        if self._linecache:
            x = self._linecache.pop()
        else:
            x = self.fd.next(1)
        if x:
            self.nextLine, self.nextTimestamp, _ = x
        else:
            self.nextLine, self.nextTimestamp = None, None

    def _follow(self, kq):
        # We can't follow a PCap dump file...
        print >> sys.stderr, "Ignoring -f directive for pcap dump file..."

    def _open(self):
        try:
            return packet.pcap.Offline(self.name)
        except IOError:
            raise RLogError, val


class _SeekableFile(_LogBase):
    def _backup(self, num):
        """
            Move the file position to one corresponding to "num" lines before
            the current file position. If there are fewer lines than "num"
            leave the position at the beginning of the file.
        """
        # We ignore the last character of the file (it may be a newline).
        pos = self.fd.tell() - 1
        while num:
            try:
                self.fd.seek(pos)
            except IOError:
                self.fd.seek(0)
                break
            c = self.fd.read(1)
            if (c == "\n"):
                num -= 1
            pos -= 1

    def _next(self):
        self.nextLine = self.fd.readline()
        if self.nextLine:
            try:
                self.nextTimestamp = getTimeval(self.nextLine)
            except ValueError:
                self.nextTimestamp = datetime.datetime.now()
        else:
            self.nextTimestamp = None
            self.nextLine = None

    def _follow(self, kq):
        r = ERead(self.fd, EV_ENABLE|EV_ADD|EV_CLEAR, udata=self)
        kq.kevent([r])
        c = EVNode(
                        self.fd, EV_ENABLE|EV_ADD|EV_CLEAR,
                        EVNode.NOTE_DELETE|EVNode.NOTE_RENAME|EVNode.NOTE_TRUNCATE,
                        udata=self
                )
        kq.kevent([c])


class SysLog(_SeekableFile):
    """
        A standard syslog file.
    """
    def _last(self, num):
        self.fd.seek(0, 2)
        self._backup(num)

    def _open(self):
        try:
            return open(self.name, "r")
        except IOError, val:
            raise RLogError, val


class ZippedSysLog(_SeekableFile):
    """
        A Zipped Syslog file.
    """
    def _last(self, num):
        # We go to the end of the file the slow way...
        self.fd.read(-1)
        self._backup(num)

    def _open(self):
        try:
            return gzip.open(self.name, "r")
        except IOError, val:
            raise RLogError, val

    def _follow(self, kq):
        # We can't follow a zipped file...
        print >> sys.stderr, "Ignoring -f directive for zipped file..."


def LogFactory(name, *args):
    if name.endswith(".gz"):
        return ZippedSysLog(name, *args)
    elif packet.pcap.isPCapFile(name):
        return PCapDump(name, *args)
    else:
        return SysLog(name, *args)


class PCapDevice:
    def __init__(self, name):
        self.name = name
        try:
            self._dev = packet.pcap.Live(self.name, timeout=1)
        except IOError:
            raise RLogError, val

    def printCurrent(self, names, padding):
        """
            Print new packets, if there are any. Returns true if data was
            printed.
        """
        wasprinted = 0
        while 1:
            x = self._dev.next()
            if x:
                wasprinted = 1
                packet, timestamp, _ = x
                if names:
                    print "%*s: "%(padding, self.name),
                print timestamp.strftime(TIMEFMT),
                print packet
            else:
                break
        return wasprinted


class Displayer:
    def __init__(self, follow, lines, printnames, bell, belltime, fnames, devices):
        self.printnames, self.bell = printnames, bell
        self.belltime = datetime.timedelta(seconds=belltime)
        self._lastBell = None
        self.lfiles = []
        if follow:
            self.kq = KQueue()
        else:
            self.kq = None
        for i in fnames:
            l = LogFactory(i, lines, self.kq)
            self.lfiles.append(l)
        self.devices = []
        for i in devices:
            d = PCapDevice(i)
            self.devices.append(d)
        self.maxNameLen = max([len(i) for i in fnames + devices])

    def _readSorted(self):
        self.lfiles.sort()
        while not (self.lfiles[0].nextTimestamp is None):
            self.lfiles[0]._printCurrent(self.printnames, self.maxNameLen)
            self.lfiles[0]._next()
            if len(self.lfiles) > 1:
                if self.lfiles[0] > self.lfiles[1]:
                    self.lfiles.sort()

    def doBell(self):
        """
            Sound a bell if new data is recieved.
        """
        if self.bell:
            now = datetime.datetime.now()
            if self._lastBell:
                if not (now - self._lastBell) > self.belltime:
                    return
            sys.stdout.write("\x07")
            self._lastBell = now

    def display(self):
        """
            Display our files.
        """
        if self.lfiles:
            self._readSorted()
        if self.kq:
            while 1:
                events = self.kq.kevent(nevents=len(self.lfiles), timeout=1)
                for i in self.devices:
                    if (i.printCurrent(self.printnames, self.maxNameLen)):
                        self.doBell()
                if events:
                    for i in events:
                        if isinstance(i, ERead):
                            i.udata._next()
                            i.udata._printCurrent(self.printnames, self.maxNameLen)
                            self.doBell()
                        elif isinstance(i, EVNode):
                            # File has been moved or deleted...
                            i.udata._close()
                for i in self.lfiles:
                    try:
                        if i.reopen():
                            self._readSorted()
                    except RLogError, val:
                        pass

    def close(self):
        for i in self.lfiles:
            i.close()


def main():
    parser = optparse.OptionParser(usage="plog [options] file ...")
    parser.add_option("-f", None, action="store_true", dest="follow",
                                    help="Follow logs.")
    parser.add_option("-n", None, type="int", dest="lines", default=None, metavar="N",
                                    help="Show last n lines of each file.")
    parser.add_option("-o", None, action="store_true", dest="printnames", default=False,
                                    help="Print the originating file name at the beginning of each line.")
    parser.add_option("-d", None,   action="append", dest="device", default=[],
                                    help="Monitor a network device.")
    parser.add_option("-b", None,   action="store_true", dest="bell",
                                    help="Sound a bell if new information is recieved.")
    parser.add_option("-t", None,   type="int", dest="belltime", default=10, metavar="N",
                                    help="Specify the bell timeout period in seconds. Default 10.")

    options, args = parser.parse_args()
    if not args and not options.device:
        parser.error("Please specify at least one file or device.")

    try:
        d = Displayer(
                        options.follow,
                        options.lines,
                        options.printnames,
                        options.bell,
                        options.belltime,
                        args,
                        options.device
                    )
        d.display()
    except RLogError, val:
        print >> sys.stderr, "plog:", val
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except IOError, val:
        if not val.errno == errno.EPIPE:
            raise
    d.close()
    

if __name__ == "__main__":
    main()
