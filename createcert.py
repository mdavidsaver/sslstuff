#!/usr/bin/env python
"""Issue a certificate from a request

inspect the resulting cert with

  openssl x509 -text -in <myname>.pem
"""

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
                   help="CA key will expire after some time")
    P.add_argument('--serial', metavar='N', type=long, default=1,
                   help="Certificate serial number")
    P.add_argument('--comment', metavar='str',
                   help="Certificate Comment")
    P.add_argument('--alt', metavar='str',
                   help="Alt. subject name (server aliases or client email)")
    P.add_argument('--sign', metavar='algo', default='sha1',
                   help="Signing algorithm, defaults to SHA1")

    P.add_argument('--server', action='store_const', const='server', dest='action', default='client',
                   help="Generate a SSL server certificate")
    P.add_argument('--client', action='store_const', const='client', dest='action',
                   help="Generate a SSL client certificate (default)")

    return P.parse_args()

def main(args):
    assert args.cabasename!=args.basename, "You probably don't intend to overwrite the cacert"

    with open(args.cabasename+'.key', 'rb') as F:
        cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, F.read())
    with open(args.cabasename+'.pem', 'rb') as F:
        cacert= crypto.load_certificate(crypto.FILETYPE_PEM, F.read())

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, args.bits)

    cert = crypto.X509()

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

    cert.set_issuer(cacert.get_subject())

    cert.set_pubkey(key)

    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(args.expire*86400)

    cert.add_extensions([
        crypto.X509Extension('basicConstraints', True, "CA:FALSE"),
        crypto.X509Extension('authorityKeyIdentifier', False, "keyid:always,issuer:always", issuer=cacert),
        crypto.X509Extension('subjectKeyIdentifier', False, "hash", subject=cert),
        #crypto.X509Extension('issuerAltName', False, "issuer:copy", issuer=cacert),
        #crypto.X509Extension('subjectAltName', False, "email:copy"),
    ])
    if args.action=='client':
        cert.add_extensions([
            crypto.X509Extension('nsCertType', False, 'client, email, objsign'),
            crypto.X509Extension('keyUsage', False, 'digitalSignature, keyEncipherment'),
            crypto.X509Extension('extendedKeyUsage', False, 'clientAuth'),
        ])

    elif args.action=='server':
        cert.add_extensions([
            crypto.X509Extension('nsCertType', False, 'server'),
            crypto.X509Extension('extendedKeyUsage', False, 'serverAuth'),
        ])

    else:
        raise RuntimeError('logic error')

    if args.alt:
        cert.add_extensions([
            crypto.X509Extension('subjectAltName', False, args.alt),
        ])

    if args.comment:
        cert.add_extensions([
            crypto.X509Extension('nsComment', False, args.comment),
        ])

    cert.sign(cakey, args.sign)

    with open(args.basename+'.pem', 'wb') as F:
        F.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

    with open(args.basename+'.key', 'wb') as F:
        F.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

if __name__=='__main__':
    main(args())
