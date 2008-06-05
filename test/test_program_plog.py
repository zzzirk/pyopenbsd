import tempfile, os, datetime
import libpry

try:
    from programs.plog import *
except ImportError:
    # We probably don't have packetpy
    pass
else:
    class uSysLog(libpry.AutoTree):
        def setUp(self):
            self.tf = tempfile.mkstemp()[1]
            self.f = file(self.tf, "w")
            self.f.write("one\ntwo\nthree\nfour")
            self.f.close()
            self.kq = KQueue()

        def tearDown(self):
            os.remove(self.tf)

        def test_open(self):
            l = SysLog(self.tf, 0, self.kq)
            l._close()

        def test_last(self):
            l = SysLog(self.tf, 0, self.kq)
            l._last(0)
            assert l.fd.readlines() == []
            l._last(1)
            assert l.fd.readlines() == ["four"]
            l._last(2)
            assert l.fd.readlines() == ["three\n", "four"]
            l._last(4)
            assert l.fd.readlines() == ["one\n", "two\n", "three\n", "four"]
            l._close()


    class uGetTimeval(libpry.AutoTree):
        def test_parse(self):
            line = "Feb 1 01:02:03 host programname[1]:   one\n"
            tv = getTimeval(line)
            assert tv.year == datetime.datetime.today().year
            assert tv.month == 2
            assert tv.day == 1
            assert tv.hour == 1
            assert tv.minute == 2
            assert tv.second == 3


    class uDisplayer(libpry.AutoTree):
        def setUp(self):
            self.tf = tempfile.mkstemp()[1]
            self.f = file(self.tf, "w")
            self.f.write("Feb 1 01:00:00 host programname[1]:   one\n")
            self.f.write("Feb 1 01:01:00 host programname[1]:   two")
            self.f.close()

            self.tf2 = tempfile.mkstemp()[1]
            self.f2 = file(self.tf2, "w")
            self.f2.write("Feb 2 01:00:00 host programname[1]:   one\n")
            self.f2.write("Feb 2 01:01:00 host programname[1]:   two")
            self.f2.close()

            self.tf3 = tempfile.mkstemp()[1]
            self.f3 = file(self.tf3, "w")
            self.f3.write("")
            self.f3.close()

            def myprint(self, names, padding):
                pass
            self._printCurrent = SysLog._printCurrent
            SysLog._printCurrent = myprint

        def tearDown(self):
            os.remove(self.tf)
            os.remove(self.tf2)
            os.remove(self.tf3)
            SysLog._printCurrent = self._printCurrent

        def test_read(self):
            d = Displayer(0, 1, 0, 0, 0, [self.tf3, self.tf2, self.tf], [])
            d.lfiles.sort()
            assert d.lfiles[0].nextTimestamp.day == 1
            assert d.lfiles[1].nextTimestamp.day == 2
            assert d.lfiles[2].nextTimestamp == None

        def test_display(self):
            d = Displayer(0, 1, 0, 0, 0, [self.tf2, self.tf], [])
            d.display()


    tests = [
        uSysLog(),
        uGetTimeval(),
        uDisplayer(),
    ]


