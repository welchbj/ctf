FROM debian:buster-20190610-slim

RUN apt-get update

RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential gdb git
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y curl tmux vim wget
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y sudo
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y zlib1g-dev libbz2-dev libssl-dev libffi-dev libncurses5-dev libncursesw5-dev libreadline-dev libsqlite3-dev llvm xz-utils tk-dev liblzma-dev python-openssl

RUN useradd --create-home --shell /bin/bash ctf 
RUN echo "ctf:ctf" | chpasswd
RUN adduser ctf sudo
USER ctf

ENV LC_CTYPE C.UTF-8
RUN wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh
RUN wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef-extras.sh | sh

RUN curl https://pyenv.run | bash

ENV HOME /home/ctf
ENV PYENV_ROOT $HOME/.pyenv
ENV PATH $PYENV_ROOT/shims:$PYENV_ROOT/bin:$PATH
RUN pyenv install 3.8.7
RUN pyenv global 3.8.7
RUN pyenv rehash

RUN pip install pwntools z3-solver

WORKDIR /ctf
CMD /bin/bash
