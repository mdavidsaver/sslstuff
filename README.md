SSL notes and scripts
=====================

SSL related things I occsionally need to remember.

Certificate creation with pyOpenSSL.

Generating a server and client cert for testing purposes.

    ./createca.py --bits 1024 --expire 30 fooca "CN=My CA,O=Me"
    ./createcert.py --bits 1024 --expire 30 --server fooca theserver "CN=localhost"
    ./createcert.py --bits 1024 --expire 30 --client fooca client1 "CN=myusername"

Building a PKCS12 file

    ./makepkcs12.py client1.pem client1.key --cacertfile fooca.pem fooclient.p12

Print

    openssl x509 -in theserver.pem -text

To test

    openssl s_server -Verify 1 -cert theserver.pem -key theserver.key -CAfile fooca.pem

And in another terminal

    openssl s_client -connect localhost:4433 -verify 1 -cert client1.pem -key client1.key -CAfile fooca.pem

Decisions
---------

- Keys are RSA with selectable length and digest algorithm
- Only one CA allowed, no secondary CAs
