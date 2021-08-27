#!/usr/bin/env python
"""Issue a certificate from a request

inspect the resulting cert with

  openssl x509 -text -in <myname>.pem
"""

from __future__ import print_function

import argparse, sys

from OpenSSL import crypto

def args():
    P = argparse.ArgumentParser(description='Accept a cert. request and issue a cert.')
    P.add_argument('cabasename', help='Base name for CA .key and .pem files')
    P.add_argument('basename', help='Base name of the output .key and .pem files')
    P.add_argument('DN', help='The distinguishing name as a comma seperated list (eg. "CN=foo,C=US")')
    P.add_argument('--bits', metavar='N', type=int, default=4096,
                   help='Key size in bits (def. 4096)')
    P.add_argument('--expire', metavar='days', type=int, default=365,
                   help="CA key will expire after some time (def. 365 days)")
    P.add_argument('--serial', metavar='N', type=int,
                   help="Certificate serial number (def. auto)")
    P.add_argument('--comment', metavar='str',
                   help="Certificate Comment")
    P.add_argument('--alt', metavar='str', action='append',
                   help="Alt. subject name (eg. email:my@addr, IP:1.2.3.4 or DNS:foo.com)")
    P.add_argument('--sign', metavar='algo', default='sha256',
                   help="Signing algorithm, defaults to SHA-256")

    P.add_argument('--server', action='store_const', const='server', dest='action', default='client',
                   help="Generate a SSL server certificate")
    P.add_argument('--client', action='store_const', const='client', dest='action',
                   help="Generate a SSL client certificate (default)")

    return P.parse_args()

def getpw(X):
    import getpass
    pw1 = None
    while not pw1:
        pw1 = getpass.getpass('password> ')
    return pw1

def main(args):
    assert args.cabasename!=args.basename, "You probably don't intend to overwrite the cacert"

    with open(args.cabasename+'.key', 'rb') as F:
        cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, F.read(), getpw)

    with open(args.cabasename+'.pem', 'rb') as F:
        cacert= crypto.load_certificate(crypto.FILETYPE_PEM, F.read())

    if not args.serial:
        with open(args.cabasename+'.ser', 'r+') as F:
            for L in F:
                args.serial = int(L.split('|',1)[0].strip())
        args.serial += 1

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, args.bits)

    cert = crypto.X509()

    cert.set_version(2) # aka. version 3
    cert.set_serial_number(args.serial)

    subj = cert.get_subject()

    # CN= O= OU= C= etc...
    for blob in map(str.strip, args.DN.split(',')):
        K,_,V = blob.partition('=')
        if not V.strip():
            print('Invalid DN component',blob)
            sys.exit(1)
        setattr(subj, K.strip(), V.strip())
    print('DN',subj.get_components())

    # takes DN
    cert.set_issuer(cacert.get_subject())

    cert.set_pubkey(key)

    # relative times
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(args.expire*86400)

    # See "man x509v3_config" and https://tools.ietf.org/html/rfc5280
    cert.add_extensions([
        crypto.X509Extension(b'basicConstraints', True, b"CA:FALSE"),
        crypto.X509Extension(b'authorityKeyIdentifier', False, b"keyid:always,issuer:always", issuer=cacert),
        crypto.X509Extension(b'subjectKeyIdentifier', False, b"hash", subject=cert),
        #crypto.X509Extension(b'issuerAltName', False, b"issuer:copy", issuer=cacert),
        #crypto.X509Extension(b'subjectAltName', False, b"email:copy"),
    ])
    if args.action=='client':
        cert.add_extensions([
            crypto.X509Extension(b'nsCertType', False, b'client, email, objsign'),
            crypto.X509Extension(b'keyUsage', False, b'digitalSignature, keyEncipherment'),
            crypto.X509Extension(b'extendedKeyUsage', False, b'clientAuth'),
        ])

    elif args.action=='server':
        cert.add_extensions([
            crypto.X509Extension(b'nsCertType', False, b'server'),
            crypto.X509Extension(b'keyUsage', False, b'digitalSignature, keyEncipherment'),
            crypto.X509Extension(b'extendedKeyUsage', False, b'serverAuth'),
        ])

    else:
        raise RuntimeError('logic error')

    if args.alt:
        cert.add_extensions([
            crypto.X509Extension(b'subjectAltName', False, (','.join(args.alt)).encode()),
        ])

    if args.comment:
        cert.add_extensions([
            crypto.X509Extension(b'nsComment', False, args.comment.encode()),
        ])

    cert.sign(cakey, args.sign)

    with open(args.cabasename+'.ser', 'a') as F: # append to serial numbers file
        F.write('%d|%s\n'%(args.serial, ' '.join(sys.argv[1:])))

    with open(args.basename+'.pem', 'wb') as F:
        F.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    with open(args.basename+'.key', 'wb') as F:
        F.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

if __name__=='__main__':
    main(args())
