from kqueue import *

def followFile(fname, timeout=None):
    """
        This generator follows a file, returning appended lines a la "tail -f".
        This is most useful for tracking additions to log files.
    """
    kq = None
    rolled = None
    while 1:
        if not kq:
            fd = open(fname)
            if not rolled:
                fd.read() # Discard current contents of file
            kq = KQueue()
            r = ERead(fd, EV_ENABLE|EV_ADD|EV_CLEAR)
            kq.kevent([r])
            c = EVNode(
                            fd, EV_ENABLE|EV_ADD|EV_CLEAR,
                            EVNode.NOTE_DELETE|EVNode.NOTE_RENAME|EVNode.NOTE_TRUNCATE,
                    )
            kq.kevent([c])
        events = kq.kevent(nevents=10, timeout=timeout)
        if events:
            for i in events:
                if isinstance(i, ERead):
                    while 1:
                        x = fd.readline()
                        if x:
                            yield x
                        else:
                            break
                elif isinstance(i, EVNode):
                    fd.close()
                    kq = None
                    rolled = 1
                    break
        else:
            return
