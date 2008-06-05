import libpry
import openbsd.arc4random as arc4random

class uArc4Random(libpry.AutoTree):
    def test_getbytes(self):
        assert len(arc4random.getbytes(1)) == 1
        assert len(arc4random.getbytes(8)) == 8
        assert len(arc4random.getbytes(9)) == 9
        assert len(arc4random.getbytes(10)) == 10
        assert len(arc4random.getbytes(11)) == 11
        assert len(arc4random.getbytes(12)) == 12

    def test_getbytesPathology(self):
        libpry.raises(ValueError, arc4random.getbytes, -1)


tests = [
    uArc4Random()
]
