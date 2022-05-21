#!/usr/bin/env python3

"""
This script is meant to setup quick and easy exploit development enviroments
for CTF challenge binaries.

Requires pwntools to run.
"""

import argparse
import os
import stat
import sys
import textwrap
from typing import NamedTuple, Optional
from pathlib import Path

from pwn import context, log, which

_libc_to_ubuntu_map = {
    "2.23": "16.04",
    "2.27": "18.04",
    "2.31": "20.04",
    "2.32": "20.10",
}

# XXX: Check arch of binary and install appropriate qemu + friends?


class DockerContext(NamedTuple):
    docker_tag: str
    binary_path: Path
    libc_path: Optional[Path]


def bail(msg):
    log.critical(msg)
    sys.exit(1)


def get_parsed_args():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "-b", "--binary",
        action="store",
        required=True,
        help="the challenge binary",
    )
    parser.add_argument(
        "-l", "--libc",
        action="store",
        required=False,
        help="the glibc file (from which version is derived) or the version \n"
             "to use",
    )
    parser.add_argument(
        "-t", "--docker-tag",
        action="store",
        required=False,
        default=None,
        help="the docker tag to use; this will override any inf derived from the \n"
             "libc version"
    )

    return parser.parse_args()


def environment_checks():
    path_to_docker = which("docker")
    if path_to_docker is None:
        bail("Unable to find docker binary; is it installed?")

    log.info(f"Using docker at {path_to_docker}")


def gen_dockerfile(ctx):
    lines = []

    def write(line, newline=True):
        line = textwrap.dedent(line)
        if newline:
            line += "\n"
        lines.append(line)

    def apt_get(packages):
        write(f"RUN DEBIAN_FRONTEND=noninteractive apt-get install -y {packages}", newline=False)

    write(f"FROM {ctx.docker_tag}")
    write("RUN apt-get update")
    apt_get("build-essential gdb git")
    apt_get("curl tmux vim wget")
    apt_get("sudo")
    apt_get(" ".join([
        "zlib1g-dev",
        "libbz2-dev",
        "libssl-dev",
        "libffi-dev",
        "libncurses5-dev",
        "libncursesw5-dev",
        "libreadline-dev",
        "libsqlite3-dev",
        "llvm",
        "xz-utils",
        "tk-dev",
        "liblzma-dev",
        "python-openssl",
    ]))
    write("", newline=False)

    write("""\
       RUN useradd --create-home --shell /bin/bash ctf 
       RUN echo "ctf:ctf" | chpasswd
       RUN adduser ctf sudo
       USER ctf""")

    # Install GEF + extras.
    write("""\
        ENV LC_CTYPE C.UTF-8
        RUN wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh
        RUN wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef-extras.sh | sh""")

    # pyenv installation for Python version management.
    write("""\
        RUN curl https://pyenv.run | bash

        ENV HOME /home/ctf
        ENV PYENV_ROOT $HOME/.pyenv
        ENV PATH $PYENV_ROOT/shims:$PYENV_ROOT/bin:$PATH
        RUN pyenv install 3.8.7
        RUN pyenv global 3.8.7
        RUN pyenv rehash

        RUN pip install pwntools z3-solver""")

    write("""\
        WORKDIR /ctf
        CMD /bin/bash""")

    dockerfile = Path("dev.Dockerfile")
    if dockerfile.exists():
        bail(f"Dockerfile already exists at {dockerfile.resolve()}")

    with dockerfile.open("w") as f:
        f.write("\n".join(lines))


def gen_docker_scripts(ctx):
    image_tag = f"{ctx.binary_path.name}-dev"

    def make_executable(path):
        # See: https://stackoverflow.com/a/12792002
        st = os.stat(path)
        os.chmod(path, st.st_mode | 0o111)

    log.info(f"Setting up scripts for tag {image_tag}")

    with open("dev-docker-build.sh", "w") as f:
        print("#!/bin/bash", file=f)
        print(f"docker build -f dev.Dockerfile -t {image_tag} .", file=f)
    make_executable("dev-docker-build.sh")

    with open("dev-docker-run.sh", "w") as f:
        print("#!/bin/bash", file=f)
        print(f"docker run -it -v $(pwd):/ctf {image_tag} /bin/bash", file=f)
    make_executable("dev-docker-run.sh")


def main():
    environment_checks()

    opts = get_parsed_args()

    binary_path = Path(opts.binary).resolve()
    context.binary = str(binary_path)
    elf = context.binary

    if opts.docker_tag is not None:
        docker_tag = opts.docker_tag
        libc_path = None
    else:
        # XXX: need to derive below two items from challenge files / arguments
        docker_tag = "ubuntu:21.04"
        libc_path = None

    ctx = DockerContext(
        docker_tag=docker_tag,
        binary_path=binary_path,
        libc_path=libc_path
    )

    gen_dockerfile(ctx)
    gen_docker_scripts(ctx)

    log.success("All done!")


if __name__ == "__main__":
    main()
