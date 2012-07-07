'''
Created on Jul 6, 2012

@author: moz
'''

import unittest
from scapy.all import * #@UnusedWildImport

from DataProvider.ConnInfo import ConnInfo

TcpFrame = IP( src='127.0.0.1', dst='192.168.1.1')/TCP( dport=80, sport=1120) #@UndefinedVariable
TcpFrameSource = ('127.0.0.1', 1120 )
TcpFrameDestination = ('192.168.1.1', 80 )
TcpFrameProtocol = 'TCP'

TcpFrameReply = IP( dst='127.0.0.1', src='192.168.1.1')/TCP( sport=80, dport=1120) #@UndefinedVariable
TcpFrameNotEqual = IP( dst='10.0.0.1', src='192.168.1.1')/TCP( sport=80, dport=1120) #@UndefinedVariable

DnsResponsePacket = IP(dst="192.168.5.1")/UDP(dport=1234)/DNS(rd=1,qd=DNSQR(qname="www.slashdot.org"), an = DNSRR(rrname = "www.slashdot.org", rdata = "31.33.7.31", type='A')) #@UndefinedVariable


class Test(unittest.TestCase):
    def testConnInfoConstructor(self):
        CI = ConnInfo( TcpFrame )
        self.assertEqual( CI.src,TcpFrameSource )
        self.assertEqual( CI.dst,TcpFrameDestination )
        self.assertEqual( CI.proto,TcpFrameProtocol )
        pass

    def testEqual(self):
        CI = ConnInfo( TcpFrame )
        self.assertEqual( CI, CI)
        
    def testReplyEqual(self):
        CI = ConnInfo( TcpFrame )
        CI_reply = ConnInfo( TcpFrameReply )
        self.assertEqual( CI, CI_reply)

    def testNotEqual(self):
        CI = ConnInfo( TcpFrame )
        CI_reply = ConnInfo( TcpFrameNotEqual )
        self.assertNotEqual( CI, CI_reply)

    def testReplyStrictEqual(self):
        CI = ConnInfo( TcpFrame )
        CI_reply = ConnInfo( TcpFrameReply )
        self.assertNotEqual( CI.all, CI_reply.all)     

    def testConstructFromParams(self):
        CI = ConnInfo( TcpFrame )
        CI2 = ConnInfo( None, '127.0.0.1', 1120, '192.168.1.1', 80, 'TCP' )
        self.assertEqual( CI, CI2)
        
    def testConstainsWild(self):
        CI2 = ConnInfo( None, '127.0.0.1', 1120, '192.168.1.1', 80, 'TCP' )
        self.assertFalse( CI2.ContainsWildcards )

    def testConstainsWildTrue(self):
        CI2 = ConnInfo( None, '*', '*', '*', 80, 'TCP' )
        self.assertTrue( CI2.ContainsWildcards )

    def testCompareWild(self):
        CI = ConnInfo( TcpFrame )
        CI2 = ConnInfo( None, '*', '*', '*', 80, 'TCP' )
        self.assertEqual( CI, CI2)
        self.assertEqual( CI2, CI)

    def testDnsResponse(self):
        CI = ConnInfo( DnsResponsePacket )
        CI2 = ConnInfo( None, '*', '*', '*', 53, 'UDP' )
        self.assertEqual( CI, CI2, "%s != %s"%(CI, CI2))
        self.assertEqual( CI2, CI, "%s != %s"%(CI2, CI))

        