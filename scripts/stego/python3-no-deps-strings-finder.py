#!/usr/bin/env python

"""
This script will generate several strings files for a binaries, and then search
them for a flag format encoded in several different formats.

For example, running the following command:
strings-finder.py -vv -f 'myCTF{' --out-dir mybinary.strings mybinary
would do the following things:
    * Encode 'myCTF{' into a bunch of different encodings
    * Create a directory ./mybinary,strings
    * Populate that directory with the output of several different strings
        runs, each looking at different types of strings
    * Tell you if any of the encoded flag formats showed up in any of the
        strings command output files
"""

from __future__ import print_function

import codecs
import os
import shlex
import shutil
import subprocess
import sys

from argparse import (
    ArgumentParser,
    RawDescriptionHelpFormatter)
from base64 import (
    a85encode,
    b16encode,
    b32encode,
    b64encode,
    b85encode)
from binascii import (
    b2a_uu)
from collections import (
    namedtuple)
from functools import (
    partial)
from operator import (
    itemgetter)
from pathlib import (
    Path)

try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError


print_info = partial(print, '[*] ', sep='')
print_err = partial(print, '[!] ', sep='', file=sys.stderr)


EncodedFlagFormat = namedtuple(
    'EncodedFlagFormat', ['encoding', 'value'])
MatchingNeedle = namedtuple(
    'MatchingNeedle', ['strings_file_path', 'line', 'encoded_flag_format'])


def bytes_r(b):
    """Reverse a bytes-like object."""
    return bytes(reversed(b))


# ENCODERS are functions that accept and return a bytes-like object
ENCODERS = {
    'a85encode':
        a85encode,
    'a85encode-reversed-plaintext':
        lambda b: a85encode(bytes_r(b)),
    'a85encode-reversed-encoded':
        lambda b: bytes_r(a85encode(b)),
    'base16':
        b16encode,
    'base16-reversed-plaintext':
        lambda b: b16encode(bytes_r(b)),
    'base16-reversed-encoded':
        lambda b: bytes_r(b16encode(b)),
    'base32':
        lambda b: b32encode(b).rstrip(b'='),
    'base32-reversed-plaintext':
        lambda b: b32encode(bytes_r(b)).rstrip(b'='),
    'base32-reversed-encoded':
        lambda b: bytes_r(b32encode(b).rstrip(b'=')),
    'base64':
        lambda b: b64encode(b).rstrip(b'='),
    'base64-reversed-plaintext':
        lambda b: b64encode(bytes_r(b)).rstrip(b'='),
    'base64-reversed-encoded':
        lambda b: bytes_r(b64encode(b).rstrip(b'=')),
    'base85':
        b85encode,
    'base85-reversed-plaintext':
        lambda b: b85encode(bytes_r(b)),
    'base85-reversed-encoded':
        lambda b: bytes_r(b85encode(b)),
    'hex':
        lambda b: codecs.encode(b, 'hex'),
    'hex-reversed-plaintext':
        lambda b: codecs.encode(bytes_r(b), 'hex'),
    'hex-reversed-encoded':
        lambda b: bytes_r(codecs.encode(b, 'hex')),
    'raw':
        lambda b: b,
    'raw-reversed':
        lambda b: bytes_r(b),
    'rot13':
        lambda b: codecs.encode(b.decode(), 'rot_13').encode(),
    'rot13-reversed-plaintext':
        lambda b: codecs.encode(bytes_r(b).decode(), 'rot_13').encode(),
    'rot13-reversed-encoded':
        lambda b: bytes_r(codecs.encode(b.decode(), 'rot_13').encode()),
    'uu':
        lambda b: b2a_uu(b).rstrip(),
    'uu-reversed-plaintext':
        lambda b: b2a_uu(bytes_r(b)).rstrip(),
    'uu-reversed-encoded':
        lambda b: bytes_r(b2a_uu(b).rstrip()),
}

STRINGS_CONFIGS = {
    'default': '-a -e s',
    'single-8-bit-byte': '-a -e S',
    '16-bit-big-endian': '-a -e b',
    '16-bit-little-endian': '-a -e l',
    '32-bit-big-endian': '-a -e B',
    '32-bit-little-endian': '-a -e L',
}


class CustomErrorArgumentParser(ArgumentParser):
    """Thin extension of ArgumentParser for custom error message."""

    def error(self, message):
        print_err('Error when argument-parsing -- ', message)
        sys.exit(1)


def get_path_to_strings_binary(opts):
    """Do basic environment checks to make sure this script can run."""
    if opts.path_to_strings_binary is not None:
        return

    path_to_strings = shutil.which('strings')
    if not path_to_strings:
        raise RuntimeError('strings program is not in your PATH')

    opts.path_to_strings_binary = path_to_strings


def get_encoded_strings(opts):
    """Encode the search string in a variety of formats."""
    flag_format_bytes = opts.flag_format.encode('utf-8')
    for enc_name, enc_func in sorted(ENCODERS.items(), key=itemgetter(0)):
        yield EncodedFlagFormat(enc_name, enc_func(flag_format_bytes))


def get_strings_file_path(opts, config_name):
    """Get the path to a strings output file."""
    fout_name = '%s.strings.%s' % (opts.fin, config_name)
    fout_path = os.path.join(opts.out_dir, fout_name)
    return os.path.abspath(fout_path)


def gen_strings_files(opts):
    """Generate the strings files to be search.

    Will check for the each file's existence in the current directory before
    trying to generate it from the binary.

    """
    for config_name, strings_args in STRINGS_CONFIGS.items():
        fout_path = get_strings_file_path(opts, config_name)
        fout_path_obj = Path(fout_path)

        fout_path_obj.parent.mkdir(parents=True, exist_ok=True)
        if fout_path_obj.exists() and not opts.force:
            continue

        with open(fout_path, 'w') as f:
            strings_cmd = [opts.path_to_strings_binary]
            strings_cmd.extend(shlex.split(strings_args))
            strings_cmd.append(opts.fin)
            subprocess.call(strings_cmd, stdout=f)


def search_strings_files(opts, needles):
    """Search the generated strings files."""
    for config_name, strings_args in STRINGS_CONFIGS.items():
        strings_path = get_strings_file_path(opts, config_name)
        try:
            with open(strings_path, 'rb') as f:
                for line in f:
                    for encoded_flag_format in needles:
                        if encoded_flag_format.value in line:
                            # more indents is better
                            yield MatchingNeedle(
                                strings_path,
                                line,
                                encoded_flag_format
                            )
        except UnicodeDecodeError:
            print_err(strings_path)
            continue
        except FileNotFoundError as e:
            raise RuntimeError(
                'File %s did not exist when expected' % strings_path) from e


def get_parsed_args():
    """Configuration for argparse."""
    parser = CustomErrorArgumentParser(
        prog='strings-finder.py',
        usage='strings-finder.py OPTIONS fin',
        description=__doc__,
        formatter_class=RawDescriptionHelpFormatter)

    parser.add_argument(
        'fin',
        nargs='?',
        action='store',
        help='path to input file from which to generate strings')
    parser.add_argument(
        '-f', '--flag-format',
        required=True,
        action='store',
        help='the flag format to search for')
    parser.add_argument(
        '--force',
        action='store_true',
        default=False,
        help='overwrite existing .strings files')
    parser.add_argument(
        '-o', '--out-dir',
        action='store',
        default=os.getcwd(),
        help='the directory in which to generate the various .strings files')
    parser.add_argument(
        '-v', '--verbosity',
        action='count',
        default=0,
        help='print increasingly verbose information')
    parser.add_argument(
        '-p', '--path-to-strings-binary',
        action='store',
        required=False,
        help='the path to the strings binary to use')
    parser.add_argument(
        '-e', '--only-encode',
        action='store_true',
        default=False,
        help='when present, just print encodings of the specific flag format')

    return parser.parse_args()


def main():
    try:
        opts = get_parsed_args()

        if not opts.only_encode:
            if opts.fin is None:
                print_err('Must specify a file to analyze; ',
                          'use -e to only print encodings')
                return 1
            elif not Path(opts.fin).exists():
                print_err('Specified file ', opts.fin, ' does not exist')
                return 1

        needles = list(get_encoded_strings(opts))
        max_encoding_len = max(len(n.encoding) for n in needles)
        print_info('Generated the following encoded versions of ',
                   opts.flag_format, ':')
        for needle in needles:
            print('    ', needle.encoding.ljust(max_encoding_len, ' '), ' ',
                  needle.value, sep='')

        if opts.only_encode:
            return 0

        get_path_to_strings_binary(opts)
        if opts.verbosity > 0:
            print_info('Using strings binary at ', opts.path_to_strings_binary)

        gen_strings_files(opts)
        for match in search_strings_files(opts, needles):
            print_info('GOT A MATCH!')
            print('   File name:', match.strings_file_path)
            print('   Matching line:', match.line)
            print('   Encoder:', match.encoded_flag_format.encoding)
            print('   Encoded value:', match.encoded_flag_format.value)
    except RuntimeError as e:
        print_err(e)
        return 1
    except Exception as e:
        print_err('Received unknown reception; re-raising it!')
        raise e

    return 0


if __name__ == '__main__':
    sys.exit(main())
