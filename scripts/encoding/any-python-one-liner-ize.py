#!/usr/bin/env python

"""convert a single-file Python script into a one-liner shell command"""

from __future__ import print_function

import base64
import sys
import zlib

from argparse import ArgumentParser, RawDescriptionHelpFormatter
from functools import partial

try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

print_err = partial(print, '[!] ', sep='', file=sys.stderr)


class CustomErrorArgumentParser(ArgumentParser):
    """Thin extension of ArgumentParser for custom error message."""

    def error(self, message):
        print_err('Error when argument-parsing -- ', message)
        sys.exit(1)


def get_parsed_args():
    """Configuration for argparse."""
    parser = CustomErrorArgumentParser(
        prog='one-liner-ize.py',
        usage='one-liner-ize.py OPTIONS fin',
        description=__doc__,
        formatter_class=RawDescriptionHelpFormatter
    )

    parser.add_argument(
        'fin',
        action='store',
        help='path to input file from which to generate strings'
    )
    parser.add_argument(
        '-p', '--python-exe',
        action='store',
        default='python',
        help='path to the python binary to use for generated one-liner'
    )

    return parser.parse_args()


def main():
    try:
        opts = get_parsed_args()

        with open(opts.fin, 'rb') as f:
            script = f.read()

        compressed_script = zlib.compress(script)
        encoded_script = base64.b64encode(compressed_script).decode()

        one_liner = ''
        one_liner += opts.python_exe + ' -c "'
        one_liner += "exec(__import__('zlib').decompress("
        one_liner += "__import__('base64').b64decode(b'"
        one_liner += encoded_script
        one_liner += "')).decode())"
        one_liner += '"'

        print(one_liner)
    except FileNotFoundError:
        print_err('Unable to find specified input file')
        return 1
    except Exception as e:
        print_err('Received unknown exception; re-raising it!')
        raise e

    return 0


if __name__ == '__main__':
    sys.exit(main())
