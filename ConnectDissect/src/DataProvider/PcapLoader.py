from scapy.all import * #@UnusedWildImport

from ConnInfo import ConnInfo

class ConnectionInfoPrinter():
    ''' NB. always return the previous package'''
    _LastConnectionInfo = None
    _Payload = ""    
    
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
    _DefaultConnectionHandler = ConnectionInfoPrinter()
    _ReaderList = []

    def __init__(self, PcapFilename ):
        self._Filename = PcapFilename
        self._Data = rdpcap( PcapFilename )

    def GetFrameCount(self):
        return len(self._Data)
    
    # -- iteration stuff
    def __iter__(self):
        return self.ReadPkgs()
    
    def ReadPkgs(self):

        
        while( True ):
            
            if( not len( self._Data )):
                raise StopIteration

            Frame = self._Data.pop()

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


            
            # else return processed data
            
        # the end.
        #raise StopIteration
    
    def setReader(self, Reader, ConnInfo):
        self._ReaderList.append( (ConnInfo, Reader ) )
        pass

    
    def ClearReaderList(self):
        self._ReaderList = []
    
    
    
    
