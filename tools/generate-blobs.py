#!/usr/bin/env python3

import argparse
import hashlib
import os
import pathlib
import sys

def gen_blobs(enc_path, dec_path, out_path):
    # Sanity checks
    pathlib.Path(out_path).mkdir(parents=True, exist_ok=True)
    enc_len = len(os.listdir(enc_path))
    dec_len = len(os.listdir(dec_path))
    out_len = len(os.listdir(out_path))
    assert enc_len != 0
    assert dec_len != 0
    assert out_len == 0
    assert enc_len == dec_len
    
    for fname in os.listdir(enc_path):
        # Read input data
        enc_fname = os.path.join(enc_path, fname)
        dec_fname = os.path.join(dec_path, fname)
        with open(enc_fname, 'rb') as f:
            enc_data = f.read()
            enc_hash = hashlib.md5(enc_data).hexdigest().upper()
        with open(dec_fname, 'rb') as f:
            dec_data = f.read()
        # Write output data
        out_fname = os.path.join(out_path, enc_hash + '.bin')
        with open(out_fname, 'wb') as f:
            f.write(dec_data)
    
def main():
    # Define arguments
    parser = argparse.ArgumentParser(
        description='Generate blobs compatible with Orbital from pairs of encrypted:decrypted files.')
    parser.add_argument('enc',
        metavar='path/to/enc', help='path to encrypted blobs',
    )
    parser.add_argument('dec',
        metavar='path/to/dec', help='path to decrypted blobs',
    )
    parser.add_argument('out',
        metavar='path/to/out', help='path to output blobs',
    )
    # Parse arguments
    args = parser.parse_args()
    gen_blobs(args.enc, args.dec, args.out)


if __name__ == '__main__':
    main()
