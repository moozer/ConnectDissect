'''
Created on Jul 5, 2012

@author: moz
'''
import unittest
from ConnReaders.HttpReader import HttpReader
from DataProvider.PcapLoader import PcapLoader
from DataProvider.ConnInfo import ConnInfo
from ConnReaders.DnsReader import DnsReader
from ConnReaders.StreamReader import StreamReader

HtmlPcapDataFile = "data/HttpWireshark2.pcap"
HtmlPcapFrameCount = 664

HeaderOnlyEventCount = 354
DnsEntriesInPcap = 18
DialogueInConnection = 7
HttpDialogueCount = 2

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
        self._PL.ClearReaderList()
        self._PL.setReader( DR, CI )
        for event in self._PL: #@UnusedVariable
            pass
        self.assertEqual( len(DR.GetDnsEntries()), DnsEntriesInPcap )

    def testStreamReader(self):
        SR = StreamReader()
        CI = ConnInfo( proto = 'TCP', dip = '69.4.231.52', dport=80)
        self._PL.ClearReaderList()
        self._PL.setReader( SR, CI )
        for event in self._PL: #@UnusedVariable
            #print event
            pass
        self.assertEqual( len(SR.GetDialogue()), DialogueInConnection )

    @unittest.skip("for now")
    def testHttpReader(self):
        HR = HttpReader()
        CI = ConnInfo( proto = 'TCP', dip = '69.4.231.52', dport=80)
        self._PL.ClearReaderList()
        self._PL.setReader( HR, CI )
        for event in self._PL: #@UnusedVariable
            #print event
            pass
        self.assertEqual( len(HR.GetDialogue()), HttpDialogueCount )


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testReadFromPcap']
    unittest.main()