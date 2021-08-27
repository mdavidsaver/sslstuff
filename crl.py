#!/usr/bin/env python
"""(re)generate a Certificate Revokation list (CRL)

verify with

  openssl crl -in myca.crl -CAfile myca.pem -verify -text
"""

from __future__ import print_function

import argparse, sys

from OpenSSL import crypto

def args():
    P = argparse.ArgumentParser(description='Re-generate CRL file, optionally adding a new revokation')
    P.add_argument('cabasename', help='Base name for CA .key and .pem files')
    P.add_argument('--revoke', metavar='cert',
                   help="Certificate file (PEM) to revoke")
    P.add_argument('--reason', metavar='text', default='unspecified',
                   help="Reason for revokaton (def. unspecified)")
    P.add_argument('--list-reasons', action='store_true',
                   help='List reason codes')
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
    if args.list_reasons:
        for reason in crypto.Revoked().all_reasons():
            print(reason)
        return

    with open(args.cabasename+'.key', 'rb') as F:
        cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, F.read(), getpw)

    with open(args.cabasename+'.pem', 'rb') as F:
        cacert= crypto.load_certificate(crypto.FILETYPE_PEM, F.read())

    with open(args.cabasename+'.crl', 'rb') as F:
        crl = crypto.load_crl(crypto.FILETYPE_PEM, F.read())

    for rev in crl.get_revoked() or []:
        print('rev', rev)

    if args.revoke:
        with open(args.revoke, 'rb') as F:
            cert= crypto.load_certificate(crypto.FILETYPE_PEM, F.read())

        print('S/N %x'%cert.get_serial_number())
        rev = crypto.Revoked()
        rev.set_serial(b'%x'%cert.get_serial_number())

        # hack to get current date in ASN1
        junk = crypto.X509()
        junk.gmtime_adj_notBefore(0)
        rev.set_rev_date(junk.get_notBefore())

        rev.set_reason(args.reason.encode())

        print('S/N', rev.get_serial())
        print('when', rev.get_rev_date())

        crl.add_revoked(rev)

    try:
        crlblob = crl.export(cacert, cakey, crypto.FILETYPE_PEM, args.expire, args.sign.encode())
    except TypeError:
        crlblob = crl.export(cacert, cakey, crypto.FILETYPE_PEM, args.expire)
    with open(args.cabasename+'.crl', 'wb') as F:
        F.write(crlblob)

if __name__=='__main__':
    main(args())
