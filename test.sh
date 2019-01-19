#!/bin/sh
set -e -x

die() {
  echo "$1"
  exit 1
}

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

openssl crl -in theca.crl -CAfile theca.pem -verify -text

msg "Create Server"

python "$BASE/createcert.py" --bits 1024 --expire 1 --server theca server1 "CN=server1.a" --alt "IP:1.1.1.1" --alt "DNS:server1.b"

openssl x509 -in server1.pem -text

openssl verify -x509_strict -CAfile theca.pem -CRLfile theca.crl -crl_check_all -purpose nssslserver -purpose sslserver server1.pem

msg "Create Client"

python "$BASE/createcert.py" --bits 1024 --expire 1 --client theca myself "CN=$USER" --alt "email:travis.localhost"

openssl x509 -in myself.pem -text

openssl verify -x509_strict -CAfile theca.pem -CRLfile theca.crl -crl_check_all -purpose sslclient myself.pem
# TODO   -purpose smimesign -purpose smimeencrypt

msg "Package client as pkcs12"

python "$BASE/makepkcs12.py" --cacertfile theca.pem myself.pem myself.key myself.p12

openssl pkcs12 -in myself.p12 -passin pass: -nokeys -nodes -chain -info

msg "Translate to Java keystore"
# a la. glassfish

keytool -noprompt -importcert \
-alias theca -file theca.pem \
-keystore cacerts.jks -storepass 'changeit'

keytool -list \
-keystore cacerts.jks -storepass 'changeit'

python "$BASE/makepkcs12.py" server1.pem server1.key server1.p12

keytool -noprompt -importkeystore \
-srcstoretype PKCS12 -srckeystore server1.p12 --srcstorepass '' \
-destkeystore keystore.jks -deststorepass 'changeit'

keytool -list \
-keystore keystore.jks -storepass 'changeit'

msg "Revoke Server"

python "$BASE/crl.py" --revoke server1.pem theca

openssl crl -in theca.crl -CAfile theca.pem -verify -text

openssl verify -x509_strict -CAfile theca.pem -CRLfile theca.crl -crl_check_all server1.pem && die "server cert not revoked"
openssl verify -x509_strict -CAfile theca.pem -CRLfile theca.crl -crl_check_all myself.pem

msg "Revoke Client"

python "$BASE/crl.py" --revoke myself.pem theca

openssl crl -in theca.crl -CAfile theca.pem -verify -text

openssl verify -x509_strict -CAfile theca.pem -CRLfile theca.crl -crl_check_all server1.pem && die "server cert not revoked"
openssl verify -x509_strict -CAfile theca.pem -CRLfile theca.crl -crl_check_all myself.pem && die "client cert not revoked"

exit 0
