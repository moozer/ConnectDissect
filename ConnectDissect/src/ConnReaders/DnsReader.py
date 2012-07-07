class DnsReader():

    def ProcessPkg(self, DnsPkg):
        ''' no memory in this reader. '''
        if not 'DNS' in DnsPkg:
            return None
        
        if not DnsPkg['DNS'].an:
            return None
        
        return "DNS\t%s\t%s"%(DnsPkg['DNS'].an.rrname,  DnsPkg['DNS'].an.rdata)
    
    



