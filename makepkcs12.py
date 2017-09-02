#!/usr/bin/env python
"""Construct a PKCS12 file from its consitituent parts

Verify with

    openssl pkcs12 -info -in some.p12
"""

import argparse

from OpenSSL import crypto

def args():
    P = argparse.ArgumentParser(description='Assemble a PKCS12 file')
    P.add_argument('certfile')
    P.add_argument('keyfile')
    P.add_argument('pkcs12file')
    P.add_argument('--cacertfile')
    P.add_argument('--pw', action='store_true')
    P.add_argument('--name', help="Friendly name")

    return P.parse_args()

def main(args):
    P = crypto.PKCS12()

    with open(args.certfile, 'rb') as F:
        P.set_certificate(crypto.load_certificate(crypto.FILETYPE_PEM, F.read()))

    with open(args.keyfile, 'rb') as F:
        P.set_privatekey(crypto.load_privatekey(crypto.FILETYPE_PEM, F.read()))

    if args.cacertfile:
        with open(args.cacertfile, 'rb') as F:
            P.set_ca_certificates([crypto.load_certificate(crypto.FILETYPE_PEM, F.read())])

    if args.name:
        P.set_friendlyname(args.name)

    pw = pw2 = None
    if args.pw:
        from getpass import getpass
        while (not pw or not pw2) and pw!=pw2:
            pw = getpass('New Password:')
            pw2= getpass('Again:')

    with open(args.pkcs12file, 'wb') as F:
        F.write(P.export(passphrase=pw))

if __name__=='__main__':
    main(args())
