#!/bin/sh
set -e -x

openssl version

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
PYTHON="${PYTHON:=python}"

WORK=`mktemp -d`

trap "rm -r $WORK" INT TERM KILL QUIT EXIT

cd "$WORK"

msg "Create Self Signed"

${PYTHON} "$BASE/createself.py" --bits 1024 --expire 1 self "CN=Test self"

openssl x509 -in self.pem -text

msg "Create CA"

# older openssl doesn't support IP name constraints
# --permit 'IP:1.1.1.0/255.255.255.0'
${PYTHON} "$BASE/createca.py" --bits 1024 --expire 1 \
 --permit 'DNS:.example' --permit 'email:example' \
 --nopw theca "CN=The CA"

openssl x509 -in theca.pem -text

openssl crl -in theca.crl -CAfile theca.pem -verify -text

msg "Create Server"

${PYTHON} "$BASE/createcert.py" --bits 1024 --expire 1 --server theca server1 "CN=server.example" --alt "DNS:server.example" --alt "IP:1.1.1.1"

openssl x509 -in server1.pem -text

# verify correct hostname and IP
openssl verify -x509_strict -CAfile theca.pem -CRLfile theca.crl -crl_check_all \
-verify_hostname server.example \
-purpose nssslserver -purpose sslserver server1.pem

# correct hostname, wrong IP
openssl verify -x509_strict -CAfile theca.pem -CRLfile theca.crl -crl_check_all \
-verify_hostname server.example -verify_ip 1.1.2.1 \
-purpose nssslserver -purpose sslserver server1.pem \
&& die "Unexpected verify success"

# wrong hostname and IP
openssl verify -x509_strict -CAfile theca.pem -CRLfile theca.crl -crl_check_all \
-verify_hostname server.other -verify_ip 1.1.2.1 \
-purpose nssslserver -purpose sslserver server1.pem \
&& die "Unexpected verify success"

msg "Create Client"

${PYTHON} "$BASE/createcert.py" --bits 1024 --expire 1 --client theca myself "CN=$USER" --alt "email:$USER@example"

openssl x509 -in myself.pem -text

openssl verify -x509_strict -CAfile theca.pem -CRLfile theca.crl -crl_check_all \
-verify_email "$USER@example" \
-purpose sslclient myself.pem
# TODO   -purpose smimesign -purpose smimeencrypt

openssl verify -x509_strict -CAfile theca.pem -CRLfile theca.crl -crl_check_all \
-verify_email "$USER@other" \
-purpose sslclient myself.pem \
&& die "Unexpected verify success"

msg "Package client as pkcs12"

${PYTHON} "$BASE/makepkcs12.py" --cacertfile theca.pem myself.pem myself.key myself.p12

openssl pkcs12 -in myself.p12 -passin pass: -nokeys -nodes -chain -info

msg "Translate to Java keystore"
# a la. glassfish

keytool -noprompt -importcert \
-alias theca -file theca.pem \
-keystore cacerts.jks -storepass 'changeit'

keytool -list \
-keystore cacerts.jks -storepass 'changeit'

${PYTHON} "$BASE/makepkcs12.py" server1.pem server1.key server1.p12

keytool -noprompt -importkeystore \
-srcstoretype PKCS12 -srckeystore server1.p12 --srcstorepass '' \
-destkeystore keystore.jks -deststorepass 'changeit'

keytool -list \
-keystore keystore.jks -storepass 'changeit'

msg "Revoke Server"

${PYTHON} "$BASE/crl.py" --revoke server1.pem theca

openssl crl -in theca.crl -CAfile theca.pem -verify -text

openssl verify -x509_strict -CAfile theca.pem -CRLfile theca.crl -crl_check_all server1.pem && die "server cert not revoked"
openssl verify -x509_strict -CAfile theca.pem -CRLfile theca.crl -crl_check_all myself.pem

msg "Revoke Client"

${PYTHON} "$BASE/crl.py" --revoke myself.pem theca

openssl crl -in theca.crl -CAfile theca.pem -verify -text

openssl verify -x509_strict -CAfile theca.pem -CRLfile theca.crl -crl_check_all server1.pem && die "server cert not revoked"
openssl verify -x509_strict -CAfile theca.pem -CRLfile theca.crl -crl_check_all myself.pem && die "client cert not revoked"

exit 0
