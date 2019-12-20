# HD Pepe

This was a fairly simple but still fun challenge that involved some steganography. The solve flow goes:

* Start with an [image of Pepe](./pepe.png)
* Look at image metadata, which reveals a link to a GitHub repo with an encoder script
* Create a decoder script that extracts the alpha-value-encoded payload, which is the base64-encoded flag

My decoder/solve script is available [here](./solve.py).
