from DataProvider.ConnInfo import ConnInfo
import copy

class StreamReader(object):
    ''' NB. always returning the previous package'''
    def __init__(self, Logname = 'Stream'):
        self._LastConnectionInfo = None
        self._Payload = ""    
        self._entries = []
        self._Logname = Logname
    
    def ProcessPkg(self, Frame ):
        ''' 
        @param ConnectionInfo: IpA, PortA, IpB, HostB, Query (if true then A->B,otherwise B->A)
        @return ConnectionInfo
        '''
        # group data in the same stream
        ConnectionInfo = ConnInfo(Frame)
        
        if not  self._LastConnectionInfo or \
                ConnectionInfo.all == self._LastConnectionInfo.all:
            if 'Raw' in Frame:
                self._Payload += Frame[ConnectionInfo.proto].payload.load
            
            self._LastConnectionInfo = ConnectionInfo
            return None
        
        # save the current data, before erasing
        RetVal = (self._Logname, ConnectionInfo, "Data: %d bytes"%len(self._Payload))
        self._entries.append( (copy.copy(ConnectionInfo), self._Payload))

        # TODO: Something should be improved, since we are always behind and might be loosing payload count...
        self._LastConnectionInfo = ConnectionInfo
        if 'Raw' in Frame:
            self._Payload = Frame[ConnectionInfo.proto].payload.load
        else:
            self._Payload = ""
            
        return RetVal

    def GetDialogue(self):
        return self._entries
