#!/usr/bin/env python3
# Copyright (C) 2023 maxim3007

import argparse
import hashlib
import getpass
import os
from cryptography.fernet import Fernet
import base64
from prompt_toolkit.shortcuts import ProgressBar
import struct, zlib

print("\nencr.py  Copyright (C) 2023  maxim3007\n")

parser = argparse.ArgumentParser()
parser.add_argument("-e", help="encrypt file")
parser.add_argument("-d", help="decrypt file")

args = parser.parse_args()

payload_size = "<Q"

def fixlength(bs, length):
    bs = bs [:length]
    while True:
        try:
            bs.decode('utf-8')
            break
        except UnicodeDecodeError:
            bs = bs [:-1]
    return bs + b'\0' * (length - len (bs))

class EncryptionErr(Exception): pass
class DecryptionErr(Exception): pass

class CompressErr(Exception): pass
class DecompressErr(Exception): pass


def encrypt_file(fname):
    fullpath = os.path.abspath(os.path.expanduser(fname))
    if os.path.isfile(fullpath):
        print(f"Encrypting file {fname}")
        password = getpass.getpass(f"Enter a password for {fname}: ").encode()
        password2 = getpass.getpass(f"Please repeat the password for {fname}: ").encode()
        assert password == password2
        assert len(password) <= 32
        fixed_len_pwd = fixlength(password, 32)
        key = base64.urlsafe_b64encode(fixed_len_pwd)
        fernet = Fernet(key)
        chunksize = 65536
        filesize = os.stat(fullpath).st_size
        print(f"Got file of size {filesize}")
        iterations = filesize//chunksize+1
        npath = fullpath + ".enc"
        tempfile = fullpath + ".temp"
        with open(fullpath, "rb") as inp, open(tempfile, "wb") as out:
            try:
                stnew = True
                with ProgressBar("Encrypting") as pb:
                    for i in pb(range(iterations)):
                        if stnew:
                            chunk = inp.read(chunksize)
                            if not chunk:
                                stnew = False
                                continue
                            data = fernet.encrypt(chunk)
                            out.write(struct.pack(payload_size, len(data)))
                            out.write(data)
                            if len(chunk) < chunksize:
                                stnew = False
                                continue
                print("Encrypted file!")
            except:
                try:
                    os.remove(tempfile)
                except:
                    pass
                raise EncryptionErr("error")
        with open(tempfile, "rb") as inp, open(npath, "wb") as out:
            try:
                stnew = True
                filesize = os.stat(tempfile).st_size
                iterations = filesize//chunksize+1
                with ProgressBar("Compressing") as pb:
                    for i in pb(range(iterations)):
                        if stnew:
                            chunk = inp.read(chunksize)
                            if not chunk:
                                stnew = False
                                continue
                            data = zlib.compress(chunk)
                            out.write(struct.pack(payload_size, len(data)))
                            out.write(data)
                            if len(chunk) < chunksize:
                                stnew = False
                                continue
                print("Compressed file!")
                os.remove(tempfile)
            except:
                os.remove(npath)
                os.remove(tempfile)
                raise CompressErr("error")
    else:
        print(f"File {fname} does not exist or it is a directory!")

def decrypt_file(fname):
    fullpath = os.path.abspath(os.path.expanduser(fname))
    if os.path.isfile(fullpath):
        print(f"Decrypting file {fname}")
        password = getpass.getpass(f"Enter a password for {fname}: ").encode()
        fixed_len_pwd = fixlength(password, 32)
        key = base64.urlsafe_b64encode(fixed_len_pwd)
        fernet = Fernet(key)
        chunksize = 8
        npath = ".".join(fullpath.split(".")[:-1])
        tempfile = ".".join(fullpath.split(".")[:-1])+".temp"
        with open(fullpath, "rb") as inp, open(tempfile, "wb") as out:
            try:
                filesize = os.stat(fullpath).st_size
                print(f"Got file of size {filesize}")
                iterations = filesize//chunksize+1
                stnew = True
                with ProgressBar("Decompressing") as pb:
                    for i in pb(range(iterations)):
                        if stnew:
                            size_data = inp.read(8)
                            if len(size_data) == 0:
                                stnew = False
                                continue
                            chunk = inp.read(struct.unpack(payload_size, size_data)[0])
                            dec = zlib.decompress(chunk)
                            out.write(dec)
                print("Decompressed file!")
            except Exception as e:
                try:
                    os.remove(tempfile)
                except:
                    pass
                raise DecompressErr("error")
        with open(tempfile, "rb") as inp, open(npath, "wb") as out:
            try:
                filesize = os.stat(tempfile).st_size
                print(f"Got file of size {filesize}")
                iterations = filesize//chunksize+1
                stnew = True
                with ProgressBar("Decrypting") as pb:
                    for i in pb(range(iterations)):
                        if stnew:
                            size_data = inp.read(8)
                            if len(size_data) == 0:
                                stnew = False
                                continue
                            chunk = inp.read(struct.unpack(payload_size, size_data)[0])
                            dec = fernet.decrypt(chunk)
                            out.write(dec)
                print("Decrypted file!")
                os.remove(tempfile)
            except Exception as e:
                try:
                    os.remove(npath)
                    os.remove(tempfile)
                except:
                    pass
                raise DecryptionErr("error")
    else:
        print(f"File {fname} does not exist or it is a directory!")


if args.e:
    try:
        encrypt_file(args.e)
    except Exception as e:
        print(f"can't encrypt file: {str(type(e))} {str(e)}")
elif args.d:
    try:
        decrypt_file(args.d)
    except Exception as e:
        print(f"can't decrypt file: {str(type(e))} {str(e)}")
else:
    parser.print_help()

