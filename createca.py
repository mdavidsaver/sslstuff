#!/usr/bin/env python3
"""Generate a minimal certificate authority key and cert

inspect the resulting cert with

  openssl x509 -text -in <myname>.pem
"""

from __future__ import print_function

import argparse, sys

from OpenSSL import crypto

def args():
    P = argparse.ArgumentParser(description='Generate a minimal CA key and certificate')
    P.add_argument('basename', help='Base name for output .key and .pem files')
    P.add_argument('DN', help='The distinguishing name as a comma seperated list (eg. "CN=foo,C=US")')
    P.add_argument('--bits', metavar='N', type=int, default=4096,
                   help='Key size in bits (def. 4096)')
    P.add_argument('--expire', metavar='days', type=int, default=365,
                   help="CA key will expire after some time (def. 365 days)")
    P.add_argument('--serial', metavar='N', type=int, default=1,
                   help="Certificate serial number (def. 1)")
    P.add_argument('--comment', metavar='str',
                   help="Certificate Comment")
    P.add_argument('--sign', metavar='algo', default='sha256',
                   help="Signing algorithm, defaults to SHA-256")
    P.add_argument('--nopw', action='store_true',
                   help="Don't encrypt CA private key file (use with caution)")
    P.add_argument('--permit', metavar='str', action='append', default=[],
                   help="Name(s) for which this CA may issue certs. (See 'Name Constraints' in \"man x509v3_config\")")
    P.add_argument('--exclude', metavar='str', action='append', default=[],
                   help="Name(s) for which this CA may not issue certs. (See 'Name Constraints' in \"man x509v3_config\")")

    return P.parse_args()

def setpw(X):
    import getpass
    pw1, pw2 = None, 'invalid'

    while not pw1 or pw1!=pw2:
        pw1 = getpass.getpass('password> ')
        pw2 = getpass.getpass('again> ')

    assert pw1==pw2
    return pw1

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
        if K!=K.upper():
            print("DN components must be upper case")
            sys.exit(1)
        if not V.strip():
            print('Invalid DN component',blob)
            sys.exit(1)
        setattr(subj, K.strip(), V.strip())
    print('DN',subj.get_components())

    cert.set_issuer(subj) # CA issue to self

    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(args.expire*86400)

    # See "man x509v3_config" and https://tools.ietf.org/html/rfc5280
    cert.add_extensions([
        crypto.X509Extension(b'subjectKeyIdentifier', False, b"hash", subject=cert),
        crypto.X509Extension(b'basicConstraints', True, b"CA:TRUE"), # no pathlen
        crypto.X509Extension(b'nsCertType', False, b'sslCA'),
        crypto.X509Extension(b'keyUsage', True, b'cRLSign, keyCertSign'),
    ])
    # a CA certs is its own issuer
    cert.add_extensions([
        crypto.X509Extension(b'authorityKeyIdentifier', False, b"keyid:always,issuer:always", issuer=cert),
    ])
    if args.permit or args.exclude:
        constraints = [b'excluded;'+C.encode() for C in args.exclude] + [b'permitted;'+C.encode() for C in args.permit]
        cert.add_extensions([
            crypto.X509Extension(b'nameConstraints', False, b','.join(constraints)),
        ])
    if args.comment:
        cert.add_extensions([
            crypto.X509Extension(b'nsComment', False, args.comment.encode()),
        ])

    cert.sign(key, args.sign)

    with open(args.basename+'.pem', 'wb') as F:
        F.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    with open(args.basename+'.key', 'wb') as F:
        if args.nopw:
            F.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        else:
            F.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key, 'AES128', setpw))

    # empty CRL
    crl = crypto.CRL()
    try:
        crlblob = crl.export(cert, key, crypto.FILETYPE_PEM, args.expire, args.sign.encode())
    except TypeError:
        # older pyOpenSSL
        crlblob = crl.export(cert, key, crypto.FILETYPE_PEM, args.expire)
    with open(args.basename+'.crl', 'wb') as F:
        F.write(crlblob)

    with open(args.basename+'.ser', 'w') as F: # start a new serial numbers file
        F.write('%d|%s\n'%(args.serial, ' '.join(sys.argv[1:])))

if __name__=='__main__':
    main(args())
