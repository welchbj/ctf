#!/usr/bin/env python

from __future__ import print_function

"""
Generate a usable PEM certificate with:

openssl req -new -x509 -nodes -out server.crt -keyout server.key
cat server.{crt,key} > server.pem && rm server.{crt,key}
"""

import os
import ssl
import sys

from argparse import (
    ArgumentParser,
    RawTextHelpFormatter)
from datetime import (
    datetime)
from functools import (
    partial)
from io import (
    BytesIO)
from http.server import (
    BaseHTTPRequestHandler,
    HTTPServer,
    SimpleHTTPRequestHandler)

try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

print_info = partial(print, '[*] ', sep='')
print_err = partial(print, '[!] ', sep='')


class FileRequestHandler(SimpleHTTPRequestHandler):
    """File-serving without index file-listing."""

    def list_directory(self, path):
        self.send_error(404, 'tried to request index')
        return None


class CustomRequestHandler(BaseHTTPRequestHandler):

    def log_request(self, code):
        tmpl = '%d - %s from %s to %s'
        msg = tmpl % (code,
                      self.command,
                      self.address_string(),
                      self.path)
        self.log_message(msg)
    
    def version_string(self):
        return 'Apache/2.4.39 (Ubuntu)'

    def do_GET(self):       
        content = b''
        content += b'Thanks for GET-ting this server!\n'
        content += b'Nothing more to see here.\n'
        self.wfile.write(content)

        self.send_response(200)
        self.send_header('Content-Type', 'plain/text; charset=utf-8')
        self.send_header('Content-Length', len(content))
        self.end_headers()


def get_parsed_args():
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument(
        '-a', '--addr',
        action='store',
        default='0.0.0.0',
        help='bind address')
    parser.add_argument(
        '-p', '--port',
        action='store',
        default=443,
        type=int,
        help='server port')
    parser.add_argument(
        '-m', '--mode',
        action='store',
        choices=('files', 'custom',),
        default='files',
        help='server run mode')
    parser.add_argument(
        '-c', '--cert-file',
        action='store',
        required=True,
        help='path to cetificate file')

    return parser.parse_args()


def main():
    opts = get_parsed_args()

    if opts.mode == 'files':
        handler_cls = FileRequestHandler
    else:
        handler_cls = CustomRequestHandler

    abs_cert_file_path = os.path.abspath(opts.cert_file)
    try:
        server = HTTPServer((opts.addr, opts.port), handler_cls)
        server.socket = ssl.wrap_socket(server.socket,
                                        certfile=abs_cert_file_path,
                                        server_side=True)
    except FileNotFoundError:
        print_err('Unable to load certificate file at ', abs_cert_file_path)
        sys.exit(1)


    print_info('Using certificate at ', abs_cert_file_path)
    print_info('Running HTTPS server on ', opts.addr, ':', opts.port)
    if opts.mode == 'files':
        print_info('Serving files from root directory ', os.getcwd())

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print_info('Ctrl-C received. Quitting!')
        sys.exit(0)


if __name__ == '__main__':
    main()
