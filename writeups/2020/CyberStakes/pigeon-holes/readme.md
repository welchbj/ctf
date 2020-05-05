# Pigeon Holes

This was a creative challenge that can be solved by treating the firmware server as a compression length oracle.

It took me a little while to figure out the intended vulnerability in this program. At first, the use of AES in GCM mode paired with the ability to choose a nonce and tag for decryption led me to believe that this would be some variation of [the Forbidden Attack](https://eprint.iacr.org/2016/475.pdf). Intimidated by the amount of work that sounded like, I searched for something simpler.

Eventually, I realized that the compression of a new firmware string before its encryption looked slightly suspicious. Some googling around led me to [these](http://www.rajatswarup.com/blog/2013/04/21/plaidctf-2013-crypto-250-compression-writeup/) [writeups](https://www.rogdham.net/2018/09/17/csaw-ctf-2018-write-ups.en), which deal with similar challenges where zlib compression length of a partially controlled plaintext can be used as an oracle for leaking secrets present elsewhere in the same plaintext. In fact, some real-life attacks on HTTPS like [CRIME](https://en.wikipedia.org/wiki/CRIME) and [BREACH](https://en.wikipedia.org/wiki/BREACH) are based on similar concepts.

We only require a cursory understanding of how zlib compression works in order to implement this attack. My understanding is based on [this excellent reference](https://zlib.net/feldspar.html). The core concept we are attacking in zlib's compression algorithm is the collapsing of identical strings into one record within the compressed result. I recommend looking at the `Blah blah blah` example in the section *LZ77 Compression* of the linked reference to better understand this concept.

Because we control some of the data that follows the flag in the firmware string that gets compressed, if that data matches the flag, then those two identical strings will be collapsed into one record. This results in a shorter compressed length. Consequently, we can know if we have guessed the beginning of the flag correctly if we enter data that results in the same compressed length as having entered nothing at all.

This challenge is made a bit easier by the following:

* Due to the mode of operation, the length of the ciphertext will be identical to the length of the plaintext that it encrypted.
* The server's compression error message tells us the exact length of our compressed plaintext, provided that it exceeds 229.
* The server is using `level=9` in its use of [the Python `zlib` module](https://docs.python.org/3/library/zlib.html), which aggressively optimizes for compression size over performance. This exaggerates the reduced compressed length for any plaintexts that include several identical strings.

We did gloss over some of the grittier details of zlib compression, and we can't make 100% accurate assumptions on whether our guess of the next flag character was correct solely based on whether the compressed length changed. This is due to a few factors, the predominant one being that parts of our incorrect guess might be collapsed with other non-flag parts of the plaintext that they match. To remedy this, I implemented my solution as a depth first search (DFS) of paths in the tree of guesses where the compressed length remains the same for each and every successive character guessed. This filters out all false positives which might pop up, as only the guess that matches the real flag will maintain the same compressed length through a full traversal to the bottom of the tree. This might be better understood with some sample output from the solution script (which is attempting to leak the sample flag `th1s_1s_A_Sampl3_flAg`):

```
th -> 274
th1 -> 274
th1s -> 274
th1s_ -> 274
th1s_1 -> 274
th1s_1s -> 274
th1s_1s_ -> 274
th1s_1s_A -> 274
th1s_1s_A_ -> 274
th1s_1s_A_Q -> 274
th1s_1s_A_S -> 274
th1s_1s_A_Sa -> 274
th1s_1s_A_Sam -> 274
th1s_1s_A_Samp -> 274
th1s_1s_A_Sampl -> 274
th1s_1s_A_SamplQ -> 274
th1s_1s_A_SamplW -> 274
th1s_1s_A_SamplX -> 274
th1s_1s_A_SamplXX -> 274
th1s_1s_A_SamplXXe -> 274
th1s_1s_A_SamplXXD -> 274
th1s_1s_A_SamplXXY -> 274
th1s_1s_A_SamplXXYX -> 274
th1s_1s_A_SamplXXYY -> 274
th1s_1s_A_SamplXXYZ -> 274
th1s_1s_A_SamplXXZ -> 274
th1s_1s_A_SamplXXZZ -> 274
th1s_1s_A_SamplY -> 274
th1s_1s_A_SamplZ -> 274
th1s_1s_A_Sampl3 -> 274
th1s_1s_A_Sampl3_ -> 274
th1s_1s_A_Sampl3_f -> 274
th1s_1s_A_Sampl3_fl -> 274
th1s_1s_A_Sampl3_flA -> 274
th1s_1s_A_Sampl3_flAg -> 274
```

In the above output, the string on the left is our current guess, and the string on the right is the length of that guess's compressed plaintext. We are tracing through the tree of guesses to see which next steps preserve the compressed length of 274 (as this implies that our current guess is being collapsed with the flag). We can see that we encounter some false positives in the above output, but the DFS corrects itself over the long-term by pruning any paths that *ever* result in a compressed length not matching the desired 274.
