import os
import libpry
import openbsd.system
import openbsd._system


class uSystem(libpry.AutoTree):
    HOSTNAME = "testhostname"       

    def setUp(self):
        self.s = openbsd.system.System()

    def test_gethostname(self):
        assert not self.s.hostname is None


    if os.geteuid() == 0:

        def test_sethostname(self):
            # set the hostname, then change it back
            h = self.s.hostname
            assert not h is None
            self.s.hostname = self.HOSTNAME
            assert self.s.hostname == self.HOSTNAME
            self.s.hostname = h
            assert self.s.hostname == h


tests = [
    uSystem(),
]
