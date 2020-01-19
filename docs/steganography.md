# Steganography

## General Tools

Sometimes, the problem isn't so hard. Just running `strings` or `xxd` might get you what you need.

The tool [`binwalk`](https://tools.kali.org/forensics/binwalk) is always a great starting point when you are given some kind of binary file. It can detect embedded files within files you give it, and then extract them. It's fairly straightforward to use:
```sh
# extract files from the provided file
binwalk -e the_file

# force extraction, even if binwalk doesn't want to
binwalk --dd '.*' the_file
```

An alternative to `binwalk` is [`foremost`](https://github.com/korczis/foremost). Use it in the following way:
```sh
foremost -i the_file
```

## xor-ing data

A great tool for performing XOR analysis is [`xortool`](https://github.com/hellman/xortool). It provides a lot of options, but here are some examples of its use:
```sh
# specify an input file to xor with a known key-length of 10 and anticipated
# most-common-byte of the pt (in this case, 00); the most common byte is likely
# 00 for binary files and 20 for text files
xortool -l 10 -c 00 some_xored_binary_file

# filter outputs based on known plaintext charsets; options for the -t parameter
# include printable, base32, and base64; using the -b flag also means that we
# do not know what the most common character in the plaintext should be (-o
# will limit this bruteforce to printable characters)
xortool -l 32 -f -t base64 -b some_xored_file

# probe for keylengths longer than the default maximum of 65
xortool -m 128 some_xored_file
```

For implementing xor-ing within a Python script, `pwntools` is a good choice. The library ships with a few pieces of xor functionality, which can be used in the following ways:
```python
# TODO: xor, xor_key, xor_pair examples
```

## Unicode Woes

If you encounter odd strings of unicode characters that you can't view, try pasting it into one of these sites:

* [Cyrillic decoder](https://2cyr.com/decode/)
* [ftfy](https://ftfy.now.sh/)

## Audio Analysis

### Visualization

An awesome tool for visualizing an audio file is [SonicVisualiser](https://www.sonicvisualiser.org/). Flags are often encoded within the waveforms of audio files.

### WAV Files

The [WavSteg](https://github.com/ragibson/Steganography#wavsteg) tool from the `stego-lsb` suite is a nice starting point for LSB analysis of WAV files. You can invoke as so:
```sh
stegolsb wavsteg -r -i the_file.wav -o output.txt -n 2
```

## Image Analysis

### General Toolkits

The most extensive collection of steganography tools is the [stego-toolkit](https://github.com/DominicBreuker/stego-toolkit) project. It has a lot of [scripts](https://github.com/DominicBreuker/stego-toolkit/tree/d2f7892c8c31addfcc92a42a56b54363a3ae1148/scripts) for orchestrating a lot of other popular stego tools.

### Metadata

A quick glance at an image file's metadata is a good starting point. `exiftool` is a nice tool for printing out this diagnostic information:
```sh
exiftool image.png
```

If you see some discrepancies between the metadata's reported image dimensions and the size of the image on disk, that's probably worth looking into.

If the image has a thumbnail, it's probably worth extracting that and looking at it, too. This can also be nested, as shown below:
```sh
exiftool -binary -ThumbnailImage image.jpg | exiftool -binary -ThumbnailImage - | exiftool -binary -ThumbnailImage - > thumbnail.jpg && eog thumbnail.jpg
```

### File Corruption

If you are given a corrupted image file that you do not know what to do with, you might be able to score a quick win with an online service like [officerecovery.com](https://online.officerecovery.com/pixrecovery/).

### Magic Bytes

Below is a table of the common byte sequences found within the most popular image formats.

| Format                 | Python formatted bytes             |
| ---------------------- | ---------------------------------- |
| BMP                    | `b'BM'`                            |
| GIF magic bytes        | `b'GIF87a'` or `b'GIF89b'`         |
| PNG magic bytes        | `\x89\x50\x4e\x47\x0d\x0a\x1a\x0a` |
| PNG image header chunk | `b'IHDR'`                          |
| TIFF big-endian        | `b'\x49\x49\x2a\x00'`              |
| TIFF little-endian     | `b'\x4d\x4d\x00\x2a'`              |
| JPEG                   | `TODO`                             |

### BMP File Format

TODO

### JPEG File Format

TODO

### PNG File Format

TODO: [Deep dive into PNG spec](https://www.w3.org/TR/PNG-Structure.html)
TODO: [PNG chunks](http://www.libpng.org/pub/png/spec/1.2/PNG-Chunks.html)

### LSB Steganography

TODO

### zsteg

[zsteg](https://github.com/zed-0xff/zsteg) is a tool for testing various steganography tricks on a provided input image. If you are lucky enough to be working with an image that is of the PNG or BMP format, `zsteg` might auto-find the flag for you. To run all of `zsteg`'s checks, use:
```sh
zsteg -a picture.png
```

## Office Documents

### `oletools`

Some challenges may involve extracting information from various Microsoft Office files. A good suite of tools for working with these documents is  [`python-oletools`](https://github.com/decalage2/oletools/wiki). See below for more detailed examples for a few of the tools in this collection.

#### `olevba`

If you see files with the extension `.docm`, there is a good chance there is some kind of embedded VBA macro inside that is worth taking a look at. `olevba` will dump this information out for you. Its usage is straightforward:
```sh
olevba the_file.docm
```

## Microsoft Office Hashes

While not strictly related to steganography, discussion of Microsoft Office password hashes fits wihtin this section. If you find a password protected document, you can convert the password hash into a `hashcat`- or `john`-crackable format using the [`office2john`](https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/run/office2john.py) script:
```sh
./office2john.py my-pw-prot-office-doc.docx
```

Further explanation of this process can be found at [this helpful link](pentestcorner.com/cracking-microsoft-office-97-03-2007-2010-2013-password-hashes-with-hashcat/).

If you happen to already know they key for decryption, then the [`msoffcrypto-tool`](https://github.com/nolze/msoffcrypto-tool) will let you unlock the file:
```sh
# check if the file is indeed encrypted
msoffcrypto-tool my-document.docx --test -v

# decrypt and write to decrypted.docx
msoffcrypto-tool encrypted.docx decrypted.docx -p PaSsWoRd
```
