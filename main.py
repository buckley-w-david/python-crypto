#!/usr/bin/python3

import argparse
from secrets import randbits
from io import BytesIO
import pickle
import RC5

class Key:
    def __init__(self, key, blocksize, keysize, rounds):
        self.key = key
        self.blocksize = blocksize
        self.keysize = keysize
        self.rounds = rounds

def _encrypt(args):
    key = randbits(args.keysize).to_bytes(args.keysize//8, byteorder='little')
    if (args.cmdtext):
        with BytesIO() as f, open(args.outfile, 'wb') as out:
            f.write(args.text.encode())
            f.seek(0)
            RC5.encrypt_file(f, out, key, args.blocksize, args.rounds)
    else:    
        with open('{}'.format(args.text), 'rb') as f, open(args.outfile, 'wb') as out:
            RC5.encrypt_file(f, out, key, args.blocksize, args.rounds)

    stored_key = Key(key, args.blocksize, args.keysize, args.rounds)
    with open('{}.key'.format(args.outfile), 'wb') as out:
        pickle.dump(stored_key, open("{}.key".format(args.outfile), 'wb'))

def _decrypt(args):
    key = None
    with open(args.key, 'rb') as f:
        key = pickle.load(f)
    if (args.cmdtext):
        with BytesIO() as f, open(args.outfile, 'wb') as out:
            f.write(args.text.encode())
            f.seek(0)
            RC5.decrypt_file(f, out, key.key, key.blocksize, key.rounds)
    else:
        with open('{}'.format(args.text), 'rb') as f, open(args.outfile, 'wb') as out:
            RC5.decrypt_file(f, out, key.key, key.blocksize, key.rounds)


def _keysize_type(x):
    x = int(x)
    if x < 0 or x > 2040:
        raise argparse.ArgumentTypeError("invalid choice: {} (choose from 0-2040)".format(x))
    return x

def _rounds_type(x):
    x = int(x)
    if x < 0 or x > 255:
        raise argparse.ArgumentTypeError("invalid choice: {} (choose from 0-255)".format(x))
    return x

if __name__ == '__main__':
    #Main argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('text', help="The plaintext wanted to be encrypted/decrypted")
    parser.add_argument('--cmdtext', action='store_true',
                        help="Specify this argument if the text entered on the commandline is the text to \
operate on, it is by default treated as a filename")

    subparsers = parser.add_subparsers(dest='operation', help='Option to specify to encrypt or decrypt the input')
    subparsers.required = True
    
    #Subparser for encryption
    parser_e = subparsers.add_parser('encrypt', help='Option to select to encrypt input')
    parser_e.add_argument('--blocksize', type=int, choices=(32, 64, 128), default=64,
                        help="The block size in bits for the cipher to operate on the input data (32, 64, 128)")
    
    parser_e.add_argument('--keysize', type=_keysize_type, default=128,
                        help="The key size in bits for the cihper to generate (0-2040)")

    parser_e.add_argument('--rounds', type=_rounds_type, default=12,
                        help="The number of rounds used in the key expansion (0-255)")
    parser_e.add_argument('outfile', help="Name of output encrypted file")
    parser_e.set_defaults(func=_encrypt)

    #Subparer for decryption
    parser_d = subparsers.add_parser('decrypt', help='Option to select to decrypt input')
    parser_d.add_argument('key', help="The file generated holding the key during encryption")
    parser_d.add_argument('outfile', help="Name of output unencrypted file")
    parser_d.set_defaults(func=_decrypt)

    args = parser.parse_args()
    args.func(args)

    
