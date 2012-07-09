from DataProvider.ConnInfo import ConnInfo

class DnsReader():
    _Entries = []
    
    def __init__(self, Logname = "DNS"):
        self._Logname = Logname

    def ProcessPkg(self, DnsPkg):
        ''' no memory in this reader. '''
        if not 'DNS' in DnsPkg:
            return None
        
        if not DnsPkg['DNS'].an:
            return None

        self._Entries.append( (DnsPkg['DNS'].an.rrname,  DnsPkg['DNS'].an.rdata) )
        return (self._Logname, ConnInfo(DnsPkg), "%s\t%s"%(DnsPkg['DNS'].an.rrname,  DnsPkg['DNS'].an.rdata) )

    
    def GetDnsEntries(self):
        return self._Entries
    
    
    
    



