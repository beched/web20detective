'''
********************
* WEB2.0 Detective *
********************

@file fuzzbackup.py
@description Search for backup of source code of the script
@author BECHED <admin@Ahack.Ru>
@link http://ahack.ru/
@license http://www.gnu.org/licenses/gpl-2.0.html
'''

from classes.common import *
from urllib.parse import urlparse

class FuzzBackup( Module ):
    def __init__( self ):
        self.allowed_params += [ 'url' ]
        self.name = 'Backup Fuzzer'
        self.makeparams()

        if 'url' not in self.args:
            self.help()
            exit()

        parsedurl = urlparse( self.args[ 'url' ] )
        path = '/'.join( parsedurl.path.split( '/' )[ :-1 ] )
        filename = parsedurl.path.split( '/' )[ -1 ]
        parsedurl = '%s://%s%s/' %(parsedurl.scheme, parsedurl.hostname, ':' + str( parsedurl.port ) if parsedurl.port != None else '')

        parts = filename.split( '.' )

        self.chkpath( parsedurl, [ '%s%s.bak' %(path, '.'.join( parts[ :-1 ] ) if len( parts ) > 2 else parts[ 0 ]), '%s%s.bak' %(path, filename), '%s%s.old' %(path, filename) ], 'generic backups' )

        self.chkpath( parsedurl, [ '%s%s.swp' %(path, filename), '%s%s.swo' %(path, filename), '%s.%s.swp' %(path, filename) ], 'Vim swap files' )

        self.chkpath( parsedurl, [ '%s%s~' %(path, filename) ], 'Vim, Gedit temporary file' )

        self.chkpath( parsedurl, [ '%sCopy%%20of%%20%s' %(path, filename), '%s%s%%20copy%s' %(path, '.'.join( parts[ :-1 ] ) if len( parts ) > 2 else parts[ 0 ], '.' + parts[ -1 ] if len( parts ) > 1 else '') ], 'Windows or MacOS copies of the file' )

        self.chkpath( parsedurl, [ '%s%%23%s%%23' %(path, filename) ], 'Emacs temporary file' )

        self.chkpath( parsedurl, [ '%s%s.save' %(path, filename), '%s%s.save.1' %(path, filename) ], 'GNU Nano temporary files' )
        
        self.chkpath( parsedurl, [ '%s.%%23%s' %(path, filename) ], 'MCEdit temporary files' )

        print( '==========\n%s requests made' %self.cnt_reqs )

if __name__ == "__main__":
    module = FuzzBackup()
