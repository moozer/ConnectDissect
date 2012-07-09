from ConnReaders.StreamReader import StreamReader

class HttpReader(StreamReader):

    def __init__(self, Logname = 'Http'):
        super(HttpReader, self).__init__(Logname)
        self._HtmlEntries = []
        self._Logname = Logname
            
    def ProcessPkg(self, pkg):
        Data = super(HttpReader, self).ProcessPkg(pkg)
        
        if not Data:
            return None
        
        # payload of lastest entry
        if len( self._entries[-1][1] ) == 0:
            return None
        
        self._HtmlEntries.append( self._entries[-1] )
        
        RetVal = (self._Logname, self._entries[-1][0], "%s"%self._HtmlEntries[-1][1].split('\n')[0].strip())
        return RetVal
        
    def GetDialogue(self):
        return self._HtmlEntries