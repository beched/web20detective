'''
********************
* WEB2.0 Detective *
********************

@file argsfind.py
@description Fuzzing the application to find parameters, which it accepts
@author BECHED <admin@Ahack.Ru>
@link http://ahack.ru/
@license http://www.gnu.org/licenses/gpl-2.0.html
'''

from classes.common import *
from os.path import abspath, dirname
from urllib.parse import urlencode

class ArgsFind( Module ):
    found = []
    def __init__( self ):
        self.allowed_params += [ 'url', 'mode', 'fill', 'base' ]
        self.name = 'Arguments Finder'
        self.makeparams()

        if 'url' not in self.args:
            self.help()
            exit()
        base = [ x.strip() for x in  open( self.args.get( 'base', dirname( abspath( __file__ ) ) + '/bases/argsbase.txt'  ) ) ]
        self.fill = self.args.get('fill', '1')
        self.mode = self.args.get( 'mode', 'g' )

        print( '%s items loaded from the base\nDetecting the default page length and HTTP-code...' % len( base ))
        html, self.HTTP_1CODE, _ = self.gpcreq()
        self.HTTP_1SIZE = len( html )
        print( 'Starting dichotomy...\n==========' )
        self.args_dichotomy( base )
        print( '\n==========\nFound parameters: %s' % ','.join( self.found ) )

    def gpcreq( self, query = '' ):
        if self.mode == 'g': resp = self.makereq( self.args[ 'url' ] + ('?' if '?' not in self.args[ 'url' ] else '&') + query, headers = add_headers )
        elif self.mode == 'p': resp = self.makereq( self.args[ 'url' ], query.encode( 'utf8' ), add_headers )
        elif self.mode == 'c':
            tmp_headers = add_headers.copy()
            tmp_headers[ 'Cookie' ] = query.replace( '&', ';' )
            resp = self.makereq( self.args[ 'url' ], headers = tmp_headers )
        return resp

    def args_dichotomy( self, base ):
        sys.stdout.write( '.' )
        params = dict( [ (x, self.fill )  for x in base ] )
        query = urlencode( params )
        l = len( base )
        html, code, _ = self.gpcreq( query )
        if html is None: pass
        if code == 414 or (code == 400 and self.mode =='c'):
            print( 'Too big base, splitting...' )
            self.args_dichotomy( base[ : int( l / 2 ) ] )
            self.args_dichotomy( base[ int( l / 2 ) : l ] )
            return
        if len( html ) != self.HTTP_1SIZE or code != self.HTTP_1CODE:
            sys.stdout.write( '*SMTH*' )
            if l == 1: self.found += params
            else:
                self.args_dichotomy( base[ : int( l / 2 ) ] )
                self.args_dichotomy( base[ int( l / 2 ) : l ] )

if __name__ == "__main__":
    module = ArgsFind()
