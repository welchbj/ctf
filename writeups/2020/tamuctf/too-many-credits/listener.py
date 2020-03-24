#!/usr/bin/env python3

import base64
import sys

from http.server import BaseHTTPRequestHandler, HTTPServer


class ExfilHandler(BaseHTTPRequestHandler):

    def log_request(self, code):
        tmpl = '%d - %s from %s to %s'
        msg = tmpl % (code,
                      self.command,
                      self.address_string(),
                      self.path)

        try:
            exfil_data = base64.b64decode(self.path[1:]).decode()
            print(exfil_data)
        except:
            print('Unable to decode data:')
            print(self.path)

        self.log_message(msg)


def main():
    server = HTTPServer(('127.0.0.1', 8888), ExfilHandler)
    try:
        print('Listening...')
        server.serve_forever()
    except KeyboardInterrupt:
        print('Ctrl-C! Quitting.')
        sys.exit(0)


if __name__ == '__main__':
    main()
