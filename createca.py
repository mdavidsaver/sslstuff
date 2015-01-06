#!/usr/bin/env python
"""Generate a minimal certificate authority key and cert

inspect the resulting cert with

  openssl x509 -text -in <myname>.pem
"""

import argparse

from OpenSSL import crypto

def args():
    P = argparse.ArgumentParser(description='Generate a minimal CA key and certificate')
    P.add_argument('basename', help='Base name for output .key and .pem files')
    P.add_argument('DN', help='The distinguishing name as a comma seperated list (eg. "CN=foo,C=US")')
    P.add_argument('--bits', metavar='N', type=int, default=4096,
                   help='Key size in bits (def. 4096)')
    P.add_argument('--expire', metavar='days', type=int, default=365,
                   help="CA key will expire after some time")
    P.add_argument('--serial', metavar='N', type=long, default=1,
                   help="Certificate serial number")
    P.add_argument('--comment', metavar='str',
                   help="Certificate Comment")
    P.add_argument('--sign', metavar='algo', default='sha1',
                   help="Signing algorithm, defaults to SHA1")

    return P.parse_args()

def main(args):
    assert args.basename and args.DN

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, args.bits)

    cert = crypto.X509()

    cert.set_pubkey(key)

    cert.set_version(2)
    cert.set_serial_number(args.serial)

    subj = cert.get_subject()

    for blob in map(str.strip, args.DN.split(',')):
        K,_,V = blob.partition('=')
        if not V.strip():
            print 'Invalid DN component',blob
            sys.exit(1)
        setattr(subj, K.strip(), V.strip())
    print 'DN',subj.get_components()

    cert.set_issuer(subj) # CA issuse to self

    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(args.expire*86400)

    # See openssl.cnf for extension names and values
    cert.add_extensions([
        crypto.X509Extension('subjectKeyIdentifier', False, "hash", subject=cert),
        crypto.X509Extension('basicConstraints', True, "CA:TRUE"), # no pathlen
        crypto.X509Extension('nsCertType', False, 'sslCA'),
        crypto.X509Extension('keyUsage', True, 'cRLSign, keyCertSign'),
    ])
    cert.add_extensions([
        crypto.X509Extension('authorityKeyIdentifier', False, "keyid:always,issuer:always", issuer=cert),
    ])
    if args.comment:
        cert.add_extensions([
            crypto.X509Extension('nsComment', False, args.comment),
        ])

    cert.sign(key, args.sign)

    with open(args.basename+'.pem', 'wb') as F:
        F.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    with open(args.basename+'.key', 'wb') as F:
        F.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

if __name__=='__main__':
    main(args())
