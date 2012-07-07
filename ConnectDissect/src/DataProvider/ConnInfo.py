class ConnInfo():
    _dip = ''
    _sip = ''
    _dprot = 0
    _sport = 0
    _TransportProtocol = ''
    _ContainsWildcards = False
       
    def __init__(self, TcpFrame=None, sip='*', sport='*', dip='*', dport='', proto='*'):
        
        if TcpFrame:
            self._BuiltConnectionInfo( TcpFrame )
            self._ContainsWildcards = False
        else:
            self._sip = sip
            self._sport = sport
            self._dip = dip
            self._dport = dport
            self._TransportProtocol = proto
            if sip == '*' or dip == '*' or sport == '*' or dport == '*' or proto == '*':
                self._ContainsWildcards = True
            else: 
                self._ContainsWildcards = False

        self.__dict__['src'] = (self._sip, self._sport)
        self.__dict__['dst'] = (self._dip, self._dport)
        self.__dict__['proto'] = self._TransportProtocol
        self.__dict__['all'] = (self._sip, self._sport, self._dip, self._dport, self._TransportProtocol)
        self.__dict__['ContainsWildcards'] = self._ContainsWildcards
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
        
        if not self.ContainsWildcards and not other.ContainsWildcards:
            return False
        
        # combinations to test...
        ssip =   {'self': self.src[0], 'other_src': other.src[0], 'other_dst': other.dst[0] }
        ssport = {'self': self.src[1], 'other_src': other.src[1], 'other_dst': other.dst[1] }
        sdip =   {'self': self.dst[0], 'other_src': other.src[0], 'other_dst': other.dst[0] }
        sdport = {'self': self.dst[1], 'other_src': other.src[1], 'other_dst': other.dst[1] }

        osip =   {'self_src': self.src[0], 'self_dst': self.dst[0], 'other': other.src[0] }
        osport = {'self_src': self.src[1], 'self_dst': self.dst[1], 'other': other.src[1] }
        odip =   {'self_src': self.src[0], 'self_dst': self.dst[0], 'other': other.dst[0] }
        odport = {'self_src': self.src[1], 'self_dst': self.dst[1], 'other': other.dst[1] }

        # handle simple wildcard - self
        if self.src[0] != '*':
            del ssip['other_src']
            del ssip['other_dst']            
        else:
            del ssip['self']
        if self.src[1] != '*':
            del ssport['other_src']
            del ssport['other_dst']    
        else:
            del ssport['self']
        if self.dst[0] != '*':
            del sdip['other_src']
            del sdip['other_dst']    
        else:
            del sdip['self']
        if self.dst[1] != '*':
            del sdport['other_src']
            del sdport['other_dst']    
        else:
            del sdport['self']
        # handle simple wildcard - other
        if other.src[0] != '*':
            del osip['self_src']
            del osip['self_dst']            
        else:
            del osip['other']
            
        if other.src[1] != '*':
            del osport['self_src']
            del osport['self_dst']            
        else:
            del osport['other']
            
        if other.dst[0] != '*':
            del odip['self_src']
            del odip['self_dst']            
        else:
            del odip['other']

        if other.dst[1] != '*':
            del odport['self_src']
            del odport['self_dst']            
        else:
            del odport['other']
            
        # permutate all
        for ssrc0 in ssip.values():
            for ssrc1 in ssport.values():
                for sdst0 in sdip.values():
                    for sdst1 in sdport.values():
                        for osrc0 in osip.values():
                            for osrc1 in osport.values():
                                for odst0 in odip.values():
                                    for odst1 in odport.values():
                                        if ConnInfo( None, ssrc0, ssrc1, sdst0, sdst1, self.proto) \
                                        == \
                                        ConnInfo( None, osrc0, osrc1, odst0, odst1, self.proto):
                                            return True
   
#
#        
#        # SRC part
#        # * in src[0]
#        if self.src[0] == '*' and other.src[0] != '*':
#            # substitute with value from other to do the wildcard comparison
#            if ConnInfo( None, other.src[0], self.src[1], self.dst[0], self.dst[1], self.proto) == other:
#                return True
#            if ConnInfo( None, other.dst[0], self.src[1], self.dst[0], self.dst[1], self.proto) == other:
#                return True
#        elif self.src[0] != '*' and other.src[0] == '*':
#            # substitute with value from other to do the wildcard comparison
#            if self ==  ConnInfo( None, self.src[0], other.src[1], other.dst[0], other.dst[1], other.proto):
#                return True
#            if self == ConnInfo( None, self.dst[0], other.src[1], other.dst[0], other.dst[1], other.proto):
#                return True
#        # case of * and * will be handled recursively
#        # case of Ip and  IP will be handled or caugt by default false
#        
#        # * in src[1]
#        if self.src[1] == '*' and other.src[1] != '*':
#            # substitute with value from other to do the wildcard comparison
#            if ConnInfo( None, self.src[0], other.src[1], self.dst[0], self.dst[1], self.proto) == other:
#                return True
#            if ConnInfo( None, self.dst[0], other.src[1], self.dst[0], self.dst[1], self.proto) == other:
#                return True
#        elif self.src[1] != '*' and other.src[1] == '*':
#            # substitute with value from other to do the wildcard comparison
#            if self ==  ConnInfo( None, other.src[0], self.src[1], other.dst[0], other.dst[1], other.proto):
#                return True
#            if self == ConnInfo( None, other.dst[0], self.src[1], other.dst[0], other.dst[1], other.proto):
#                return True
#        # case of * and * will be handled recursively
#        # case of Ip and  IP will be handled or caugt by default false
#        
#        # DST part
#        # * in dst[0]
#        if self.dst[0] == '*' and other.dst[0] != '*':
#            # substitute with value from other to do the wildcard comparison
#            if ConnInfo( None, self.src[0], self.src[1], other.src[0], self.dst[1], self.proto) == other:
#                return True
#            if ConnInfo( None, self.src[0], self.src[1], other.dst[0], self.dst[1], self.proto) == other:
#                return True
#        elif self.dst[0] != '*' and other.dst[0] == '*':
#            # substitute with value from other to do the wildcard comparison
#            if self ==  ConnInfo( None, other.src[0], other.src[1], self.src[0], other.dst[1], other.proto):
#                return True
#            if self == ConnInfo( None, other.src[0], other.src[1], self.dst[0], other.dst[1], other.proto):
#                return True
#        # case of * and * will be handled recursively
#        # case of Ip and  IP will be handled or caugt by default false
#        
#        # * in src[1]
#        if self.dst[1] == '*' and other.dst[1] != '*':
#            # substitute with value from other to do the wildcard comparison
#            if ConnInfo( None, self.src[0], self.src[1], self.dst[0], other.src[1], self.proto) == other:
#                return True
#            if ConnInfo( None, self.src[0], self.src[1], self.dst[0], other.dst[1], self.proto) == other:
#                return True
#        elif self.dst[1] != '*' and other.dst[1] == '*':
#            # substitute with value from other to do the wildcard comparison
#            if self ==  ConnInfo( None, other.src[0], other.src[1], other.dst[0], self.src[1], other.proto):
#                return True
#            if self == ConnInfo( None, other.src[0], other.src[1], other.dst[0], self.dst[1], other.proto):
#                return True
#        # case of * and * will be handled recursively
#        # case of Ip and  IP will be handled or caugt by default false
#        
#        
        return False
    
    def __str__(self):
        return "%s:%s -> %s:%s, %s"%(self._sip, self._sport, self._dip, self._dport, self._TransportProtocol)