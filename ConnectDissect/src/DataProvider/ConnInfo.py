class ConnInfo():
    _dip = ''
    _sip = ''
    _dprot = 0
    _sport = 0
    _TransportProtocol = ''
       
    def __init__(self, TcpFrame):
        self._BuiltConnectionInfo( TcpFrame )

        self.__dict__['src'] = (self._sip, self._sport)
        self.__dict__['dst'] = (self._dip, self._dport)
        self.__dict__['proto'] = self._TransportProtocol
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
        if not self.proto == other.proto:
            return False
        
        if self.src == other.src and self.dst == other.dst:
            return True
        
        if self.dst == other.src and self.src == other.dst:
            return True
        
        return False