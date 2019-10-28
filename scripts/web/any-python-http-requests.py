#!/usr/bin/env python

from __future__ import print_function

import os
import requests
import shutil
import uuid

from functools import partial
from tempfile import gettempdir

print_info = partial(print, '[*] ', sep='')


def download_file(url, out_path=None, session=None):
    """Download a file; will make a temp file if out_path is None."""
    if out_path is None:
        out_fname = str(uuid.uuid4())
        out_path = os.path.join(gettempdir(), out_fname)

    get_func = session.get if session is not None else requests.get
    get_func = partial(get_func, stream=True, verify=False)

    with get_func(url) as r:
        r.raise_for_status()
        with open(out_path, 'wb') as f:
            shutil.copyfileobj(r.raw, f)

    return out_path


def dump_headers(r):
    """Print headers from a request-like object."""
    print('\n'.join('%s: %s' % (key, val) for
                    key, val in r.headers.items()))


def dump_response(resp, show_request=False):
    """Print out some information from an HTTP request/response."""
    if show_request:
        req = resp.request
        print_info('Request: ', req.method, ' to ', req.url)
        print_info('Request headers: ')
        dump_headers(req)
        print_info('Raw request body:')
        print(req.body)
    print_info('Status code: ', resp.status_code)
    print_info('Response encoding: ', resp.encoding)
    print_info('Response headers:')
    dump_headers(resp)
    print_info('Response content:')
    print(resp.content)
    print_info('JSON response:')
    print(resp.json())


# constants for below examples
URL = 'http://localhost'
USER_AGENT = """\
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) \
AppleWebKit/537.36 (KHTML, like Gecko) \
Chrome/35.0.1916.47 \
Safari/537.36"""

# set authentication, no SSL verification, other headers on a session
s = requests.Session()
s.auth = ('username', 'password',)
s.verify = False
s.headers.update({
    'User-Agent': USER_AGENT,
    'X-Forwarded-For': '127.0.0.1',
})
s.post('%s/post-endpoint' % URL, data={'key': 'value'})  # POST parameters
s.post('%s/post-endpoint' % URL, json={'key': 'value'})  # JSON

# pulling data out of a response
r = s.get('%s/get-endpoint' % URL)
dump_response(r, show_request=True)

# download a file with our session
out_file = download_file('%s/some-file' % URL)
print_info('File downloaded to ', out_file)
