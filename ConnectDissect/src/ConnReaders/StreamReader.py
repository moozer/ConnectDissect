from DataProvider.ConnInfo import ConnInfo
import copy

class StreamReader(object):
    ''' NB. always return the previous package'''
    def __init__(self):
        self._LastConnectionInfo = None
        self._Payload = ""    
        self._entries = []
    
    def ProcessPkg(self, Frame ):
        ''' 
        @param ConnectionInfo: IpA, PortA, IpB, HostB, Query (if true then A->B,otherwise B->A)
        @return ConnectionInfo
        '''
        # group data in the same stream
        ConnectionInfo = ConnInfo(Frame)
        
        if not self._LastConnectionInfo or ConnectionInfo.all == self._LastConnectionInfo.all:
            if 'Raw' in Frame:
                self._Payload += Frame[ConnectionInfo.proto].payload.load
            
            self._LastConnectionInfo = ConnectionInfo
            return None

        # TODO: Something should be improved, since we are always behind and might be loosing payload count...
        RetVal = ("Stream", "%s\tData: %d bytes"%(ConnectionInfo, len(self._Payload)))
        self._LastConnectionInfo = ConnectionInfo
        if 'Raw' in Frame:
            self._Payload = Frame[ConnectionInfo.proto].payload.load
        else:
            self._Payload = ""

        self._entries.append( (copy.copy(ConnectionInfo), self._Payload))
            
        return RetVal

    def GetDialogue(self):
        return self._entries
