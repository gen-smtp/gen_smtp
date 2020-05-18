#!/bin/sh
# https://www.postgresql.org/docs/current/ssl-tcp.html#SSL-CERTIFICATE-CREATION

DATADIR=test/fixtures
CA_SUBJ="/CN=gen_smtp CA"
SERVER1_SUBJ="/CN=epgsql server"
set -x

# generate root key
openssl genrsa -out ${DATADIR}/root.key 2048
# generate root cert
openssl req -new -x509 -text -days 3650 -key ${DATADIR}/root.key -out ${DATADIR}/root.crt -subj "$CA_SUBJ"

for DOMAIN in "mx1.example.com" "mx2.example.com"; do
	KEY=${DATADIR}/${DOMAIN}-server.key
	CSR=${DATADIR}/${DOMAIN}-server.csr
	CRT=${DATADIR}/${DOMAIN}-server.crt
	# generate server1 key
	openssl genrsa -out $KEY 2048
	# generate server signature request
	openssl req -new -key $KEY -out $CSR -subj "/CN=${DOMAIN}"
	# create signed server cert
	openssl x509 -req -text -days 3650 -in $CSR -CA ${DATADIR}/root.crt -CAkey ${DATADIR}/root.key -CAcreateserial -out $CRT
done

rm ${DATADIR}/*.csr
