#!/usr/bin/env python3

"""
Author: [Chvalov Andrii](https://linkedin.com/in/chvalov)
Company: [iterasec.com](https://iterasec.com/)

Function: (de)compress special Xamarin .dll files

Installation notes:
This program requires the python lz4 library.
Install via
* "lz4" (pip)
* "python3-lz4" (Debian, Ubuntu)

```
uint32 magic = 0x5A4C4158; // 'XALZ', little-endian
uint32 index; // Index into an internal assembly descriptor table
uint32 uncompressed_length;
```
"""

import argparse
from struct import unpack
from io import BytesIO
import lz4.block

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--input", required=True, help="Path to input .dll file")
parser.add_argument("-o", "--output", required=True, help="Path to output .dll file")
parser.add_argument("-d", "--index", help="Descriptor index: e.g.: '16 00 00 00'")
args = parser.parse_args()

header_magic = b'XALZ'


def decompress(data: bytes) -> bytes:
    header_uncompressed_length = unpack('<I', data[8:12])[0]  # Note: `<` little-endian, `I` unsigned int
    payload = data[12:]

    print("Header index: %s" % data[4:8])
    print("Compressed payload size: %s bytes" % len(payload))
    print("Uncompressed length according to header: %s bytes" % header_uncompressed_length)
    return lz4.block.decompress(payload, uncompressed_size=header_uncompressed_length)


def compress(data: bytes) -> bytes:
    compressed = lz4.block.compress(data, mode="high_compression")
    with BytesIO() as bio:
        bio.write(header_magic)  # b'XALZ'
        bio.write(bytes.fromhex(args.index))  # Index into an internal assembly descriptor table
        bio.write(compressed)
        return bio.getvalue()


def writer(data: bytes):
    with open(args.output, "wb") as output_file:
        output_file.write(data)
        output_file.close()


if __name__ == "__main__":
    with open(args.input, "rb") as data:
        dll = data.read()
        if dll[:4] == header_magic:  # b'XALZ'
            writer(decompress(dll))
        else:
            writer(compress(dll))
        data.close()
    print("result written to file")
