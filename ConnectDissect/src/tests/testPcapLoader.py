'''
Created on Jul 5, 2012

@author: moz
'''
import unittest


class Test(unittest.TestCase):


    def testReadFromPcap(self):
        PL = PcapLoader( HtmlPcapDataFile )
        self.assertEqual( HtmlPcapPacketCount, PL.GetPacket() )
        pass


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testReadFromPcap']
    unittest.main()