# DevOps

This file contains some notes about editors, languages, and other tools I like to use on CTFs.

## Version Control

During CTFs, I still like to commit my writeups as a backup method. However, I can't push them to the public instance of this repo while the competition is ongoing, so I use a separate remote as a private version.

When a new CTF is starting, I'll create a new branch and push it to the private repo (which is mapped to `origin`):

```sh
git checkout -b ctf/year/name-of-ctf
git push -u origin --all
```

And when the CTF is over, I can publicly release my writeups:

```sh
# Merge the CTF branch in master.
git checkout master
git merge ctf/year/name-of-ctf

# Push to private.
git push -u origin --all

# Push to public
git push -u public --all
```

This process is explained at a high level in [this StackOverflow answer](https://stackoverflow.com/a/14243407).

## Editors

### Visual Studio Code

[Visual Studio Code](https://code.visualstudio.com/) is my standard for any long-term or more-invovled development. These are the plugins I use:

* [C/C++](https://github.com/microsoft/vscode-cpptools) - Tools for C/C++ dev.
* [Docker](https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-docker) - Tools for Docker dev.
* [EditorConfig](https://github.com/editorconfig/editorconfig-vscode) - Tool for making sure files conform to basic formatting rules.
* [Pitch Black Theme](https://vscodethemes.com/e/viktorqvarfordt.vscode-pitch-black-theme) - A nice relaxed theme.
* [Python](https://github.com/Microsoft/vscode-python) - Tools for Python dev.
* [Vim](https://github.com/VSCodeVim/Vim) - Vim keybindings.
* [Git Graph](https://github.com/mhutchie/vscode-git-graph) - BitBucket-esque Git branch graph visualization.
* [GitLens](https://github.com/eamodio/vscode-gitlens) - Nice tools for learning about the Git context of the code you are working on.
* [vscode-icons](https://github.com/vscode-icons/vscode-icons) - Nice sidebar file icons.
* [CodeSnap](https://github.com/kufii/CodeSnap) - Sweet code screenshots.
* [Fira Code](https://github.com/tonsky/FiraCode) - Font with programming ligatures.
* [Todo Tree](https://github.com/Gruntfuggly/todo-tree) - Tree view of TODO/FIXME/XXX/etc. comments in your code.

### Vim

When doing quick exploit development in the terminal, Vim is my editor of choice. It pairs nicely with [tmux](https://github.com/tmux/tmux) for rapid script editing and execution. My `.vimrc` can be found [here](https://github.com/welchbj/dotfiles/blob/master/.vimrc).

## Languages

### Python

[Python](https://docs.python.org/3/library/) is my language choice for pretty much all solution scripts and bigger-scope tooling. Its standard library has a lot of cool tools. Some of my favorites that have been especially useful include:

* [`atexit`](https://docs.python.org/3/library/atexit.html) - Simple utilities for registering cleanup functions to run at program exit.
* [`ftplib`](https://docs.python.org/3/library/ftplib.html) - A full-functioning FTP client framework.
* [`html`](https://docs.python.org/3/library/html.html) - Utilities for escaping / unescaping HTML entities. Nice for cleaning up output for tools interacting with web applications.
* [`difflib`](https://docs.python.org/3/library/difflib.html) - Quickly work on diffs of sequences.
* [`shlex`](https://docs.python.org/3/library/shlex.html) - Parse shell syntax. Great for tool development.
* [`statistics`](https://docs.python.org/3/library/statistics.html) - Basic statistic functions (mean, median, etc.). Useful for challenges involving timing attack analysis.
* [`zlib`](https://docs.python.org/3/library/zlib.html) - Simple compression.
* [`textwrap`](https://docs.python.org/3/library/textwrap.html) - `textwrap.dedent` is a nice tool for more-easily inlining multiline strings in your code .

There are seemingly endless insanely high quality third-party libraries available for pretty much any kind of analysis you need to do, as well.

### PHP

[PHP](https://www.php.net/) is a great choice for rapid web prototyping. For challenges that involve writing a quick and dirty web server that you can force some automated part of the challenge to interact with, I actually prefer PHP to Python.

### Golang

I haven't started writing any tools in [Go](https://golang.org/), but I'm starting to see it be a requirement for building a lot of new open source utilities. I have run into issues in the past with setting up an appropriate version / environment variable configuration. [This StackOverflow answer](https://stackoverflow.com/a/41323785) has solved all of my problems.
