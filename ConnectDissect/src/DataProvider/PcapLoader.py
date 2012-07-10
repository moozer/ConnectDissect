from scapy.all import * #@UnusedWildImport

from ConnInfo import ConnInfo

class ConnectionInfoPrinter():
    ''' NB. always return the previous package'''
    def __init__(self):
        self._LastConnectionInfo = None
        self._Payload = ""    
    
    def ProcessPkg(self, Frame ):
        ''' 
        @param ConnectionInfo: IpA, PortA, IpB, HostB, Query (if true then A->B,otherwise B->A)
        @return ConnectionInfo
        '''
        # group data in the same stream
        ConnectionInfo= ConnInfo(Frame)
        
        if not self._LastConnectionInfo or ConnectionInfo.all == self._LastConnectionInfo.all:
            if 'Raw' in Frame:
                self._Payload += Frame[ConnectionInfo.proto].payload.load
            
            self._LastConnectionInfo = ConnectionInfo
            return None

        # TODO: Something should be improved, since we are always behind and might be loosing payload count...
        RetVal = ("Print", "%s. Data: %d bytes"%(ConnectionInfo, len(self._Payload)))
        self._LastConnectionInfo = ConnectionInfo
        if 'Raw' in Frame:
            self._Payload = Frame[ConnectionInfo.proto].payload.load
        else:
            self._Payload = ""
            
        return RetVal
        
        

class PcapLoader():


    def __init__(self, PcapFilename ):
        self._Filename = PcapFilename
        self._Data = rdpcap( PcapFilename )
        self._DefaultConnectionHandler = ConnectionInfoPrinter()
        self._ReaderList = []

    def GetFrameCount(self):
        return len(self._Data)
    
    # -- iteration stuff
    def __iter__(self):
        return self.ReadPkgs()
    
    def ReadPkgs(self):

        
        while( True ):
            
            if( not len( self._Data )):
                raise StopIteration

            Frame = self._Data.pop(0)

            # skip frames without IP info
            if not 'IP' in Frame:
                continue
            
            if not 'UDP' in Frame and not 'TCP':
                continue
                        
            ConnectionInfo = ConnInfo(Frame)

            if len( self._ReaderList ) < 1:
                yield self._DefaultConnectionHandler.ProcessPkg( Frame )
                continue
            
            # else loop through all handlers
            for ReaderConnInfo, Reader in self._ReaderList:
                if ReaderConnInfo == ConnectionInfo:
                    Event = Reader.ProcessPkg( Frame )
                    if Event:
                        yield Event
            
            # if unhandled, then skip

        # flush using a bogus frame
        # else loop through all handlers
        BogusFrame = IP(src="0.0.0.0")/TCP(dport=100, sport=100)/"SomeRandomData"
        for ReaderConnInfo, Reader in self._ReaderList:
            if ReaderConnInfo == ConnectionInfo:
                Event = Reader.ProcessPkg( BogusFrame )
                if Event:
                    yield Event
            
            
        # the end.
        #raise StopIteration
    
    def setReader(self, Reader, ConnInfo):
        self._ReaderList.append( (ConnInfo, Reader ) )
        pass

    
    def ClearReaderList(self):
        self._ReaderList = []
    
    
    
    
