from scapy.all import *

class ConnectionInfoPrinter():
    def Process(self, ConnectionInfo, Payload ):
        ''' 
        @param ConnectionInfo: IpA, PortA, IpB, HostB, Query (if true then A->B,otherwise B->A)
        @return A string being the event
        '''
        return ("%s:%d -> %s:%d, %s, %s"%ConnectionInfo)
        
        

class PcapLoader():
    _DefaultConnectionHandler = ConnectionInfoPrinter()
    
    def __init__(self, PcapFilename ):
        self._Filename = PcapFilename
        self._Data = rdpcap( PcapFilename )
        pass

    def GetFrameCount(self):
        return len(self._Data)
    
    # -- iteration stuff
    def __iter__(self):
        return self


    def _BuiltConnectionInfo(self, pkg):
        ''' only handles IP traffic '''
        ip1 = pkg['IP'].src
        ip2 = pkg['IP'].dst
        if 'TCP' in pkg:
            port1 = pkg['TCP'].sport
            port2 = pkg['TCP'].dport
            TransportProtocol = 'TCP'
        elif 'UDP' in pkg:
            port1 = pkg['UDP'].sport
            port2 = pkg['UDP'].dport
            TransportProtocol = 'UDP'
        else:
            raise ValueError('Package must contain IP and TCP/UDP')

        if ip1 > ip2:
            return (ip2, port2, ip1, port1, TransportProtocol, True)
                        
        if ip1 < ip2:
            return (ip1, port1, ip2, port2, TransportProtocol, False)

        if ip1 == ip2:
            if port1 > port2:
                return (ip1, port1, ip2, port2, TransportProtocol, True)
            
            return (ip2, port2, ip1, port1, TransportProtocol, True)
        
    
    
    def next(self):
        LastConnectionInfo = ()
        Payload = ""
        
        while( True ):
            
            if( not len( self._Data )):
                raise StopIteration

            Frame = self._Data.pop()

            # skip frames without IP info
            if not 'IP' in Frame:
                continue
            
            if not 'UDP' in Frame and not 'TCP':
                continue
                        
            ConnectionInfo = self._BuiltConnectionInfo(Frame)
            
            if ConnectionInfo == LastConnectionInfo:
                if 'raw' in Frame:
                    Payload += Frame['raw']
                    
                continue
            
            # else return processed data
            return self._DefaultConnectionHandler.Process( ConnectionInfo, Payload )
            
        # the end.
        raise Iter