'''
********************
* WEB2.0 Detective *
********************

@file common.py
@description Common class, modules information, parsing parameters, making url requests
@author BECHED <admin@Ahack.Ru>
@link http://ahack.ru/
@license http://www.gnu.org/licenses/gpl-2.0.html
'''

from config import *
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from http.client import BadStatusLine
from re import sub, search
from time import sleep
import sys, getopt

class Module:
    allowed_params = [ 'ajax', 'cut', 'sleep' ]
    name = 'Common'
    cnt_reqs = 0
    foundurls = []

    def __del__( self ):
        print( '==========\n%s requests made' %self.cnt_reqs )

    def help( self ):
        print( "==========\nWEB2.0 Detective\n==========\nThis is %s module and it accepts parameters %s. See docs for explanation.\nExample of usage: python %s --param value" % (self.name, self.allowed_params, sys.argv[ 0 ]) )

    def makeparams( self ):
        print( '==========\nStarting module %s...\n==========' % self.name )
        try:
            opts = getopt.getopt( sys.argv[ 1: ], '', [ x + '=' for x in self.allowed_params ] )
        except getopt.GetoptError:
            self.help()
            exit()

        self.args = dict( [ (k[ 2: ], v) for k,v in opts[ 0 ] ] )
        if 'ajax' in self.args:
            add_headers[ 'X-Requested-With' ] = 'XMLHttpRequest'
            print( 'AJAX mode on...' )
        self.sleep = float( self.args.get( 'sleep', 0 ) )
        self.cut = self.args.get( 'cut', '' ).encode()

    def makereq( self, url, query = None, headers = add_headers ):
        sleep( self.sleep )
        self.cnt_reqs += 1
        try:
            resp = urlopen( Request( url, query, headers ) )
            return ( sub( self.cut, b'', resp.read() ), resp.getcode(), resp.info() )
        except HTTPError as e:
            print( 'Got %s error...' % e.code )
            return ( sub( self.cut, b'', e.read() ), e.code, e.hdrs )
        except BadStatusLine:
            return ('', None, None)
        except URLError as e:
            print( e.reason )
            exit()

    def chkpath( self, url, paths, comment=None ):
        for path in paths:
            print( 'Checking for %s...' % ('/'+path if comment is None else comment) )
            if self.makereq( url + path )[ 1 ] != 404:
                print( 'Possibly found at %s%s' % (url, path) )
                self.foundurls.append( path )
