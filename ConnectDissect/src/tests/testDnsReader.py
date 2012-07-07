'''
Created on Jul 7, 2012

@author: moz
'''
import unittest
from scapy.all import * #@UnusedWildImport
from ConnReaders.DnsReader import DnsReader

DnsRequestPacket =      IP(dst="192.168.5.1")/UDP()/DNS(rd=1,qd=DNSQR(qname="www.slashdot.org")) #@UndefinedVariable
DnsResponsePacket =     IP(dst="192.168.5.1")/UDP()/DNS(rd=1,qd=DNSQR(qname="www.slashdot.org"), an = DNSRR(rrname = "www.slashdot.org", rdata = "31.33.7.31", type='A')) #@UndefinedVariable
ResponseEventText = ('DNS', "www.slashdot.org\t31.33.7.31")
DnsEntries = [('www.slashdot.org', '31.33.7.31')]

class Test(unittest.TestCase):
    def testQueryPkg(self):
        DR = DnsReader()
        Event = DR.ProcessPkg(DnsRequestPacket )
        self.assertEqual( Event, None )
        self.assertEqual( DR.GetDnsEntries(), [])

    def testRespPkg(self):
        DR = DnsReader()
        Event = DR.ProcessPkg(DnsResponsePacket )
        self.assertEqual( Event, ResponseEventText )
        self.assertEqual( DR.GetDnsEntries(), DnsEntries)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()