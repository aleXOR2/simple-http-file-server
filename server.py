#!/usr/bin/env python3
''' Copyright (C) 2017  Povilas Kanapickas <povilas@radix.lt>, Alex M Sokolov <aleksoros@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

from http.server import SimpleHTTPRequestHandler, HTTPServer
import os
import sys
import base64
import json
import socket

class SimpleUploadHandler(SimpleHTTPRequestHandler):

    def do_PUT(self):
        print(self.headers)
        path = self.translate_path(self.path)
        if os.path.isdir(path):
            self.send_error(405)
            return
        try:
            parent_dir = os.path.dirname(path)
            if not os.path.exists(parent_dir):
                os.makedirs(parent_dir)

            length = int(self.headers.get('Content-Length'))
            fout = open(path, 'wb')

            while length > 0:
                bufsize = 102400
                if length < bufsize:
                    bufsize = length
                length -= bufsize

                fout.write(self.rfile.read(bufsize))
            fout.close()
        except Exception as e:
            print(e)
            self.send_error(405)
            return

        self.send_response(200)
        self.end_headers()

def encode_http_auth_password(user, psw):
    txt = user + ':' + psw
    txt = base64.b64encode(txt.encode('UTF-8')).decode('UTF-8')
    return txt

def decode_http_auth_password(txt):
    txt = base64.b64decode(txt.encode('UTF-8')).decode('UTF-8')
    items = txt.split(':')
    if len(items) != 2:
        return None
    return (items[0], items[1])

class PathConfig:
    def __init__(self, filename):
        if '/' in filename:
            raise Exception()
        self.filename = filename
        self.perms = {}
        self.children = {}

class AuthConfig:

    def __init__(self):
        self.root = PathConfig('')
        self.users = {}

    def add_path_config(self, path, user, perms):
        path_items = [ p for p in path.split('/') if p not in [ '', '.', '..' ] ]

        p = self.root
        for i in path_items:
            if i not in p.children:
                p.children[i] = PathConfig(i)
            p = p.children[i]

        p.perms[user] = perms

    def load_config(self, config_file_path):
        try:
            config = json.load(open(config_file_path, 'r'))
            config_paths = config['paths']
            for config_path in config_paths:
                path = config_path['path']
                user = config_path['user']
                perms = config_path['perms']
                self.add_path_config(path, user, perms)

            config_users = config['users']
            for config_user in config_users:
                user = config_user['user']
                psw = config_user['psw']
                self.users[user] = psw

        except Exception as e:
            print("Error reading config file " + config_file_path)
            print(e)

    def check_perm(self, perms, user, perm)->bool:
        if user in perms:
            if perm in perms[user]:
                return True

        if '*' in perms:
            if perm in perms['*']:
                return True
        return False

    def combine_perm(self, prev, next):
        if next == None:
            return prev
        return next

    def check_path_for_perm(self, path, perm, user, psw):
        if user not in self.users:
            user = '*'
        elif self.users[user] != psw:
            return False

        p = self.root
        items = path.split('/')

        result = any([False, self.check_perm(p.perms, user, perm)])

        for i in items:
            if i not in p.children:
                return result
            p = p.children[i]

            result = any([result, self.check_perm(p.perms, user, perm)])

        return result

class AuthUploadHandler(SimpleUploadHandler):
    from datetime import datetime
    _realmName ="Python 3 File Server # "+datetime.now().isoformat()

    def do_AUTHHEAD(self):
        print("Authenticating client:")
        print(self.headers)

        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"'+self._realmName+'\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'Not authenticated\n')

    def check_auth_impl(self, perm):
        try:
            path = self.translate_path(self.path)
            path = os.path.relpath(path)
            path=path.replace("\\","/")#fix for windows path

            if path.startswith('..'):
                return False

            auth_header = self.headers.get('Authorization')
            if auth_header == None:
                (user, psw) = ('*', None)
            else:
                if not auth_header.startswith('Basic '):
                    return False
                decode_result = decode_http_auth_password(auth_header[6:].strip())
                if decode_result == None:
                    return False
                (user, psw) = decode_result
            return self.server.auth_config.check_path_for_perm(path, perm, user, psw)

        except Exception as e:
            errorMessage="Error serving " + self.path
            print(errorMessage)
            print(str(e))
            self.wfile.write(errorMessage)
            return False

    def check_auth(self, perm):
        if not self.check_auth_impl(perm):
            self.do_AUTHHEAD()
            return False
        return True

    def do_HEAD(self):
        if self.check_auth('r'):
             SimpleHTTPRequestHandler.do_HEAD(self)

    def do_GET(self):
        if self.check_auth('r'):
             SimpleHTTPRequestHandler.do_GET(self)

    def do_PUT(self):
        if self.check_auth('w'):
             SimpleUploadHandler.do_PUT(self)

def main():
    from argparse import ArgumentParser, RawTextHelpFormatter
    import os

    absoluteConfigPath : str

    requestHandlerClass: SimpleUploadHandler

    argsParser=ArgumentParser(
        description="HTTP/HTTPS file server with upload functionality and configurable permission control",
        usage="Usage: %(prog)s --port [port] [--https] [pem file location] [--config] [config file]",
        epilog="""Usage Example:       
        Startw a https file server with permission control with access to C:\Temp (server is available at https://localhost:4443)-
        %(prog)s 4443 "C:\Temp" --https ".\cert\server.pem" --config permissions.json
        
        Startw a http server without permission control on default port -
        %(prog)s""",formatter_class=RawTextHelpFormatter)
    argsParser.add_argument("-p","--port",help="Optional. TCP/IP Port to access server on. It defaults to 8081", type=int,default=8081)
    argsParser.add_argument("-d","--dir",help="Optional. Root dir for file server. It defaults to the script location",default=os.getcwd())
    argsParser.add_argument("--https", help="Optional. Adds TLS (transport layer secure). Pem file location should be specified as second argument for this option.")
    argsParser.add_argument("--config",help="Optional. Permissions config json file")

    options=argsParser.parse_args()

    if options.config:
        requestHandlerClass=AuthUploadHandler
        absoluteConfigPath=os.path.realpath(options.config)
    else:
        requestHandlerClass=SimpleUploadHandler

    if options.dir!=os.getcwd():
        print("Changing root dir to {cd}".format(cd=options.dir))
        os.chdir(options.dir)

    server = HTTPServer(('', options.port), requestHandlerClass)

    if options.config:
        print("Access restrictions enabled and loaded from " + absoluteConfigPath)
        auth_config = AuthConfig()
        auth_config.load_config(absoluteConfigPath)
        server.auth_config = auth_config

    if options.https:
        print("HTTPS enabled")
        import ssl
        server.socket = ssl.wrap_socket(server.socket, certfile=options.https, server_side=True)

    print('listening on %s://localhost:%d' % (
        "https" if options.https else "http",
        options.port
    ))
    server.serve_forever()

if __name__ == '__main__':
    main()
