'''
********************
* WEB2.0 Detective *
********************

@file softdetect.py
@description Detection of server software, real application name, searching for several server configuration flaws
@author BECHED <admin@Ahack.Ru>
@link http://ahack.ru/
@license http://www.gnu.org/licenses/gpl-2.0.html
'''

from classes.common import *
from urllib.parse import urlparse

class SoftDetect( Module ):
    def __init__( self ):
        self.allowed_params += [ 'url', 'args' ]
        self.name = 'Software Detector'
        self.makeparams()

        if 'url' not in self.args:
            self.help()
            exit()

        self.html, self.code, self.hdrs = self.makereq( self.args[ 'url' ] )
        self.parsedurl = urlparse( self.args[ 'url' ] )
        self.path = '/'.join( self.parsedurl.path.split( '/' )[ :-1 ] + [ '' ] )[ :-1 ]
        self.parsedurl = '%s://%s%s/' %(self.parsedurl.scheme, self.parsedurl.hostname, ':' + str( self.parsedurl.port ) if self.parsedurl.port != None else '')

        print( 'Response code: %s\nDetected server: %s\nPowered by: %s\nHeaders influencing Caching: %s\n%s==========' %(self.code, self.hdrs[ 'Server' ], self.hdrs[ 'X-Powered-By' ], self.hdrs[ 'Vary' ], '' if self.hdrs[ 'X-Powered-CMS' ] is None else 'Powered by CMS: ' + self.hdrs[ 'X-Powered-CMS' ] + '\n') )
        self.chkpath( self.parsedurl, [ 'sitemap.xml', 'robots.txt' ] )

        try:
            if 'Apache' in self.hdrs[ 'Server' ]: self.apachetest()
            elif 'nginx' in self.hdrs[ 'Server' ]: self.nginxtest()
            elif 'IIS' in self.hdrs[ 'Server' ]: self.iistest()
        except TypeError: pass

        if search( '(\.php[^\w]?)', self.args[ 'url' ].lower() ) != None or 'PHP' in self.hdrs.get( 'X-Powered-By', '' ) or 'PHP' in self.hdrs.get( 'Set-Cookie', '' ):
            self.phptest()
        elif search( '(\.aspx?[^\w]?)', self.args[ 'url' ].lower() ) != None or 'ASP.NET' in self.hdrs.get( 'X-Powered-By', '' ) or (self.html != None and b'__VIEWSTATE' in self.html):
            self.aspnettest()
        elif search( '(\.jsp[^\w]?)', self.args[ 'url' ].lower() ) != None or 'JSESSIONID' in self.hdrs.get( 'Set-Cookie', '' ) or search( '(Servlet)|(JSP)', self.hdrs.get( 'X-Powered-By', '' ) ) != None:
            self.javatest()
        elif self.html != None and b'csrfmiddlewaretoken' in self.html:
            self.pythontest()
        elif 'mod_rails' in self.hdrs.get( 'X-Powered-By', '' ) or self.hdrs[ 'X-Runtime' ] != None or self.hdrs[ 'X-Rack-Cache' ] != None or self.makereq( self.args[ 'url' ] + '?a=a&a[]=a' )[ 1 ] == 500:
            self.rubytest()

    def apachetest( self ):
        print( '==========\nTesting for specific Apache issues' )
        try:
            if( self.hdrs[ 'Vary' ] != None and search( '(negotiate)', self.hdrs[ 'Vary' ].lower() ) != None ):
                print( 'mod_negotiation possibly detected. Trying to get filename suggestions...' )
                tmp_headers = add_headers.copy()
                tmp_headers[ 'Negotiate' ] = 'trans'
                tmp_headers[ 'Accept' ] = 'justfortest/justfortest'
                tmp_headers[ 'Accept-Encoding' ] = 'justfortest'
                tmp_headers[ 'Accept-Language' ] = 'justfortest'
                print( 'Revealed names: %s' % self.makereq( self.args[ 'url' ], headers = tmp_headers )[ 2 ][ 'Alternates' ] )
        except ValueError: pass
        print( 'Trying to get real application name via invalid request...' )
        tmp_headers = add_headers.copy()
        tmp_headers[ 'Content-Length' ] = 'x'
        html, code, _ = self.makereq( self.args[ 'url' ], b'', tmp_headers )
        try:
            if code == 413: print( 'Found real path: %s' % search( b'resource<br />(.*)<br />', html ).group( 1 ).decode() )
            else: print( 'Failed' )
        except: print( 'Failed' )
        self.chkpath( self.parsedurl, [ 'server-status' ], 'server status application' )
        self.phpcgipathtest()

    def nginxtest( self ):
        print( '==========\nTesting for specific NginX issues' )
        self.phpcgipathtest()

    def iistest( self ):
        print( '==========\nTesting for specific Microsoft-IIS issues' )
        self.chkpath( self.parsedurl, [ 'WEB-INF', 'META-INF', '_vti_bin' ] )
        print( 'Testing for IIS+PHP/ASP auth bypass through NTFS' )
        if self.makereq( self.parsedurl + self.path + '::$INDEX_ALLOCATION' )[ 1 ] != 404:
            print( 'Possibly vulnerable or blocked. Check at %s' % self.parsedurl + self.path + '::$INDEX_ALLOCATION' )
        if self.makereq( self.parsedurl + self.path + ':$i30:$INDEX_ALLOCATION' )[ 1 ] != 404:
            print( 'Possibly vulnerable or blocked. Check at %s' % self.parsedurl + self.path + ':$i30:$INDEX_ALLOCATION' )
        self.phpcgipathtest()

    def phptest( self ):
        print( '==========\nTesting for specific PHP issues\nTesting for CVE-2012-1823...' )
        html, code, hdrs = self.makereq( self.args[ 'url' ] + '?-s+%3d' )
        if( html.startswith( b'<code><span' ) and html != self.html ): print( 'Possibly vulnerable to RCE. Check at %s?-s+%%3d' % self.args[ 'url' ])
        else: print( 'Not vulnerable' )
        print( 'Trying to get an error sending invalid session id...' )
        tmp_headers = add_headers.copy()
        tmp_headers[ 'Cookie' ] += ';PHPSESSID=(.)(.)'
        html, _, _ = self.makereq( self.args[ 'url' ], headers = tmp_headers )
        path = search( b'in <b>(.*)</b> on line', html )
        if( path != None ): print( 'Found server application path: %s' % path.group( 1 ).decode() )
        else:
            print( 'Failed' )
            print( 'Trying to get a max_execution_time error by sending a file with long name...\nIt can take time, wait...' )
            tmp_headers = add_headers.copy()
            tmp_headers[ 'Content-Type' ] = 'multipart/form-data; boundary=---------------------------31133713371337'
            file = '---------------------------31133713371337\r\n\
Content-Disposition: form-data; name=file31337; filename=\r\njustfortest%s.txt\r\n\
Content-Type: text/plain\r\n\r\n\
justfortest\r\n\
---------------------------31133713371337\r\n' % '0' * 100500
            tmp_headers[ 'Content-Length' ] = len( file )
            html, code, hdrs = self.makereq( self.args[ 'url' ], file.encode( 'utf-8' ), tmp_headers )
            path = search( b'in <b>(.*)</b> on line', html )
            if( path != None ): print( 'Found server application path: %s' % path.group( 1 ).decode() )
            else:
                print( 'Failed' )
                if 'args' not in self.args:
                    print( 'I need to know script parameters in order to provoke the next PHP errors.\n\
Specify them by the --args foo,bar\n\
You can use Arguments Finder module to search for the script parameters.')
                    return
                else: fuzz_args = self.args[ 'args' ].split( ',' )
                print( 'Trying to get a type error or a max_execution_time error by exceeding memory_limit...\nConsidering max_input_nesting_level = 64...\nIt can take time, wait...' )
                query = '=1&'.join( [x+'[]'*64 for x in fuzz_args] )
                tmp_headers = add_headers.copy()
                tmp_headers[ 'Cookie' ] = query.replace( '&', ';' )
                html, code, hdrs = self.makereq( '%s?%s' % (self.args[ 'url' ], query), query.encode( 'utf-8' ), tmp_headers )
                path = search( b'in <b>(.*)</b> on line', html )
                if( path != None ): print( 'Found server application path: %s' % path.group( 1 ).decode() )
                else: print( 'Failed' )

    def phpcgipathtest( self ):
        print( 'Testing for common PHP-(Fast)CGI+NginX|IIS|Apache|LightHTTPD|(.*?) configuration vulnerability...' )
        if len( self.foundurls ) == 0:
            html, code, hdrs = self.makereq( self.parsedurl + '/index.html' )
            if( code != 404 ): self.foundurls.append( 'index.html' )
            else: html, code, hdrs = self.makereq( self.parsedurl + '/favicon.ico' )
            if( code != 404 ): self.foundurls.append( 'favicon.ico' )
        if len( self.foundurls ) != 0:
            page = '%s/%s' %(self.parsedurl, self.foundurls[ 0 ])
            test = self.makereq( page )
            test1 = self.makereq( page + '/.php' )
            if test[ 1 ] != 404 and len( test[ 0 ] ) == len( test1[ 0 ] ):
                print( 'Possibly vulnerable. Check it out at %s/.php' %page )
                return
            test2 = self.makereq( page + '%00.php' )
            if test[ 1 ] != 404 and len( test[ 0 ] ) == len( test2[ 0 ] ):
                print( 'Possibly vulnerable. Check it out at %s%00.php' %page )
            else: print( 'Not vulnerable' )
        else: print( 'No files found to check' )

    def aspnettest( self ):
        print( '==========\nTesting for specific ASP.NET issues' )
        if self.hdrs[ 'X-AspNet-Version' ] != None: print( 'ASP.NET version: %s' % self.hdrs[ 'X-AspNet-Version' ] )
        self.chkpath( self.parsedurl, [ 'Trace.axd', 'elmah.axd', 'ScriptResource.axd?d=A', 'WebResource.axd?d=A' ] )

    def javatest( self ):
        print( '==========\nJava detected' )

    def rubytest( self ):
        print( '==========\nRuby on Rails framework possibly detected' )
        if self.hdrs[ 'Set-Cookie' ] != None:
            try:
                print( 'RoR project name: %s' % search( '_(.*)_sess', self.hdrs[ 'Set-Cookie' ] ).group( 1 ).decode() )
            except: pass

    def pythontest( self ):
        print( '==========\nPython with Django framework possibly detected' )

if __name__ == "__main__":
    module = SoftDetect()
