#!/bin/sh
set -e -x

msg() {
  echo
  echo "======== $1 ======="
  echo
}

BASE="$PWD"

WORK=`mktemp -d`

trap "rm -r $WORK" INT TERM KILL QUIT EXIT

cd "$WORK"

msg "Create Self Signed"

python "$BASE/createself.py" --bits 1024 --expire 1 self "CN=Test self"

openssl x509 -in self.pem -text

msg "Create CA"

python "$BASE/createca.py" --bits 1024 --expire 1 --nopw theca "CN=The CA"

openssl x509 -in theca.pem -text

msg "Create Server"

python "$BASE/createcert.py" --bits 1024 --expire 1 --server theca server1 "CN=server1.a" --alt "IP:1.1.1.1" --alt "DNS:server1.b"

openssl x509 -in server1.pem -text

msg "Create Client"

python "$BASE/createcert.py" --bits 1024 --expire 1 --client theca myself "CN=$USER" --alt "email:travis.localhost"

openssl x509 -in myself.pem -text

msg "Package client as pkcs12"

python "$BASE/makepkcs12.py" --cacertfile theca.pem myself.pem myself.key myself.p12

openssl pkcs12 -in myself.p12 -passin pass: -nokeys -nodes -chain -info
