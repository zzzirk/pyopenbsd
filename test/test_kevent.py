import unittest, sys, tempfile, os

from openbsd.kqueue import *

class uKEvent(unittest.TestCase):
    def setUp(self):
        self.k = KQueue()

    def test_repr(self):
        tf = tempfile.mkstemp()[1]
        f = file(tf, "w")
        ev = EVNode(f, flags=EV_ADD, fflags=EVNode.NOTE_DELETE, udata="test")
        repr(ev)
        f.close()
        os.remove(tf)

    def test_addevent(self):
        ev = ERead(sys.stdout)
        ev.flags = EV_ADD
        self.k.kevent([ev], 0, 0)

    def test_kevent_error(self):
        ev = ERead(sys.stdout)
        ev.flags = EV_ADD
        ev.ident = "adsfsadf"
        self.failUnlessRaises(OException, self.k.kevent, [ev], 0)

    def test_kevent_ret(self):
        # Create a tempfile
        tf = tempfile.mkstemp()[1]
        f = file(tf, "w")
        f.write("test")
        f.close()

        f = file(tf, "r")
        ev = EVNode(f, flags=EV_ADD, fflags=EVNode.NOTE_DELETE, udata="test")
        self.k.kevent([ev])

        os.remove(tf)
        ev = self.k.kevent(nevents=1, timeout=None)[0]
        self.failUnless(isinstance(ev, EVNode))
        self.failUnlessEqual(ev.flags, EV_ADD)
        self.failUnlessEqual(ev.fflags, EVNode.NOTE_DELETE)
        self.failUnlessEqual(ev.udata, "test")

    def test_del(self):
        k2 = KQueue()
        del k2
