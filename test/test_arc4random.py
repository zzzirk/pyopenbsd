import unittest
import openbsd.arc4random as arc4random

class uArc4Random(unittest.TestCase):
    def test_getbytes(self):
        self.failUnlessEqual(len(arc4random.getbytes(1)), 1)
        self.failUnlessEqual(len(arc4random.getbytes(8)), 8)
        self.failUnlessEqual(len(arc4random.getbytes(9)), 9)
        self.failUnlessEqual(len(arc4random.getbytes(10)), 10)
        self.failUnlessEqual(len(arc4random.getbytes(11)), 11)
        self.failUnlessEqual(len(arc4random.getbytes(12)), 12)

    def test_getbytesPathology(self):
        self.failUnlessRaises(ValueError, arc4random.getbytes, -1)
