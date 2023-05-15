#!/usr/bin/env python3
"""Re-sign certificate, with new expiration date
"""

from __future__ import print_function

import argparse, sys

from OpenSSL import crypto

def args():
    P = argparse.ArgumentParser(description='Accept a cert. request and issue a cert.')
    P.add_argument('cabasename', help='Base name for CA .key and .pem files')
    P.add_argument('basename', help='Base name of the output .key and .pem files')
    P.add_argument('--expire', metavar='days', type=int, default=365,
                   help="CA key will expire after some time (def. 365 days)")
    P.add_argument('--sign', metavar='algo', default='sha256',
                   help="Signing algorithm, defaults to SHA-256")

    return P.parse_args()

def getpw(X):
    import getpass
    pw1 = None
    while not pw1:
        pw1 = getpass.getpass('password> ')
    return pw1

def main(args):

    with open(args.cabasename+'.key', 'rb') as F:
        cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, F.read(), getpw)

    with open(args.basename+'.pem', 'rb') as F:
        cert= crypto.load_certificate(crypto.FILETYPE_PEM, F.read())

    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(args.expire*86400)

    cert.sign(cakey, args.sign)

    with open(args.basename+'.pem', 'wb') as F:
        F.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

if __name__=='__main__':
    main(args())
