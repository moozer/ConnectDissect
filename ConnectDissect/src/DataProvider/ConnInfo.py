class ConnInfo():
    _dip = ''
    _sip = ''
    _dprot = 0
    _sport = 0
    _TransportProtocol = ''
       
    def __init__(self, TcpFrame=None, sip='*', sport='*', dip='*', dport='', proto='*'):
        
        if TcpFrame:
            self._BuiltConnectionInfo( TcpFrame )
        else:
            self._sip = sip
            self._sport = sport
            self._dip = dip
            self._dport = dport
            self._TransportProtocol = proto

        self.__dict__['src'] = (self._sip, self._sport)
        self.__dict__['dst'] = (self._dip, self._dport)
        self.__dict__['proto'] = self._TransportProtocol
        self.__dict__['all'] = (self._sip, self._sport, self._dip, self._dport, self._TransportProtocol)
        pass

# TODO: implement something like this
#    def __setattr__(self, name, value):
#        raise ValueError("It's read only!")
        
    def _BuiltConnectionInfo(self, pkg):
        ''' only handles IP traffic '''
        self._sip = pkg['IP'].src
        self._dip = pkg['IP'].dst

        if 'TCP' in pkg:
            self._sport = pkg['TCP'].sport
            self._dport = pkg['TCP'].dport
            self._TransportProtocol = 'TCP'
        elif 'UDP' in pkg:
            self._sport = pkg['UDP'].sport
            self._dport = pkg['UDP'].dport
            self._TransportProtocol = 'UDP'
        else:
            raise ValueError('Package must contain IP and TCP/UDP')

    def __eq__(self, other):
        # check protocols.
        if not self.proto == '*' and not other.proto =='*':
            if not self.proto == other.proto:
                return False
            
        # easy part
        if self.src == other.src and self.dst == other.dst:
            return True
        
        if self.dst == other.src and self.src == other.dst:
            return True
        
        # SRC part
        # * in src[0]
        if self.src[0] == '*' and other.src[0] != '*':
            # substitute with value from other to do the wildcard comparison
            if ConnInfo( None, other.src[0], self.src[1], self.dst[0], self.dst[1], self.proto) == other:
                return True
            if ConnInfo( None, other.dst[0], self.src[1], self.dst[0], self.dst[1], self.proto) == other:
                return True
        elif self.src[0] != '*' and other.src[0] == '*':
            # substitute with value from other to do the wildcard comparison
            if self ==  ConnInfo( None, self.src[0], other.src[1], other.dst[0], other.dst[1], other.proto):
                return True
            if self == ConnInfo( None, self.dst[0], other.src[1], other.dst[0], other.dst[1], other.proto):
                return True
        # case of * and * will be handled recursively
        # case of Ip and  IP will be handled or caugt by default false
        
        # * in src[1]
        if self.src[1] == '*' and other.src[1] != '*':
            # substitute with value from other to do the wildcard comparison
            if ConnInfo( None, self.src[0], other.src[1], self.dst[0], self.dst[1], self.proto) == other:
                return True
            if ConnInfo( None, self.dst[0], other.src[1], self.dst[0], self.dst[1], self.proto) == other:
                return True
        elif self.src[1] != '*' and other.src[1] == '*':
            # substitute with value from other to do the wildcard comparison
            if self ==  ConnInfo( None, other.src[0], self.src[1], other.dst[0], other.dst[1], other.proto):
                return True
            if self == ConnInfo( None, other.dst[0], self.src[1], other.dst[0], other.dst[1], other.proto):
                return True
        # case of * and * will be handled recursively
        # case of Ip and  IP will be handled or caugt by default false
        
        # DST part
        # * in dst[0]
        if self.dst[0] == '*' and other.dst[0] != '*':
            # substitute with value from other to do the wildcard comparison
            if ConnInfo( None, self.src[0], self.src[1], other.src[0], self.dst[1], self.proto) == other:
                return True
            if ConnInfo( None, self.src[0], self.src[1], other.dst[0], self.dst[1], self.proto) == other:
                return True
        elif self.dst[0] != '*' and other.dst[0] == '*':
            # substitute with value from other to do the wildcard comparison
            if self ==  ConnInfo( None, other.src[0], other.src[1], self.src[0], other.dst[1], other.proto):
                return True
            if self == ConnInfo( None, other.src[0], other.src[1], self.dst[0], other.dst[1], other.proto):
                return True
        # case of * and * will be handled recursively
        # case of Ip and  IP will be handled or caugt by default false
        
        # * in src[1]
        if self.dst[1] == '*' and other.dst[1] != '*':
            # substitute with value from other to do the wildcard comparison
            if ConnInfo( None, self.src[0], self.src[1], self.dst[0], other.src[1], self.proto) == other:
                return True
            if ConnInfo( None, self.src[0], self.src[1], self.dst[0], other.dst[1], self.proto) == other:
                return True
        elif self.dst[1] != '*' and other.dst[1] == '*':
            # substitute with value from other to do the wildcard comparison
            if self ==  ConnInfo( None, other.src[0], other.src[1], other.dst[0], self.src[1], other.proto):
                return True
            if self == ConnInfo( None, other.src[0], other.src[1], other.dst[0], self.dst[1], other.proto):
                return True
        # case of * and * will be handled recursively
        # case of Ip and  IP will be handled or caugt by default false
        
        
        return False
    
    def __str__(self):
        return "%s:%s -> %s:%s, %s"%(self._sip, self._sport, self._dip, self._dport, self._TransportProtocol)