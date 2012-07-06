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
        
        
        