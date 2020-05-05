# Sharing is Caring

This ended up being a fairly straightforward problem that was solved by decrypting a message that had been encrypted via [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing).

I was able to extract all of the secrets from the 5 images using the awesome steganography tool [zsteg](https://github.com/zed-0xff/zsteg). From there, the Python library [`secretsharing`](https://github.com/blockstack/secret-sharing) could be used to decrypt the message (which was the flag). The only slight mis-step I had was forgetting to convert the secrets from decimal to hex, which was needed for consumption by the Python library I used.
