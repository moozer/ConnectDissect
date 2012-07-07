'''
Created on Jul 5, 2012

@author: moz
'''
import unittest
from ConnReaders.HttpReader import HttpReader
from DataProvider.PcapLoader import PcapLoader
from DataProvider.ConnInfo import ConnInfo
from ConnReaders.DnsReader import DnsReader

HtmlPcapDataFile = "data/HttpWireshark2.pcap"
HtmlPcapFrameCount = 664

HeaderOnlyEventCount = 354
DnsEntriesInPcap = 18

class TestConstruction(unittest.TestCase):

    def testReadFromPcap(self):
        PL = PcapLoader( HtmlPcapDataFile )
        self.assertEqual( HtmlPcapFrameCount, PL.GetFrameCount() )
        pass


class Test(unittest.TestCase):
    def setUp(self):
        self._PL = PcapLoader( HtmlPcapDataFile )
        
    def testHeaderOnlyEventCount(self):
        ''' HeaderOnly is default '''
        eventcount = 0
        for event in self._PL: #@UnusedVariable
            if event:
                eventcount += 1
        self.assertEqual( HeaderOnlyEventCount, eventcount )
        pass
    
    def testInstallReader(self):
        DR = DnsReader()
        CI = ConnInfo( proto = 'UDP', dport=53)
        self._PL.setReader( DR, CI )
        for event in self._PL: #@UnusedVariable
            pass
        self.assertEqual( len(DR.GetDnsEntries()), DnsEntriesInPcap )


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testReadFromPcap']
    unittest.main()