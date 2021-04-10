# pawn

Used an unorthodox approach of writing bytes around `__malloc_hook` by dereferencing `board[4][][]` to access libc addresses relative to an entry in the (no PIE) binary's GOT.

## Referenced Solutions

* [bi0s](https://blog.bi0s.in/2021/04/08/Pwn/AngstromCTF21-Pawn/)
* [nobodyisnobody](https://ctftime.org/writeup/27029)
* [ptr-yudai](https://ptr-yudai.hatenablog.com/entry/2021/04/08/115245#Binary-200pts-Pawn-43-solves)
