# Steganography

Steganography is the art of abusing file formats and encodings to hide data. It can make for some interesting CTF problems.

## General Tools

Sometimes, the problem isn't so hard. Just running `strings` or `xxd`

The tool `binwalk` is always a great starting point when you are given some kind of binary file. It can detect embedded files within files you give it, and then extract them. It's fairly straightforward to use:
```sh
# TODO
TODO
```
TODO: https://tools.kali.org/forensics/binwalk

## xor-ing data

TODO: xortool

For implementing xor-ing within a Python script, `pwntools` is a good choice. The library ships with an `xor()` function, which can be used in the following ways:
```python
>>> TODO
```

## Image Analysis

### Metadata

A quick glance at an image file's metadata is a good starting point. `exiftool` is a nice tool for printing out this diagnostic information:
```sh
exiftool image.png
```

If you see some discrepancies between the metadata's reported image dimensions and the size of the image on disk, that's probably worth looking into.

TODO

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
