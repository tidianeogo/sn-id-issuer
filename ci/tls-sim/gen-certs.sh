#!/bin/bash
# AC de test + certificat serveur pour sn-id.test (simulation de tunnel HTTPS en CI).
set -euo pipefail
cd "$(dirname "$0")"; mkdir -p certs; cd certs
[ -f server.crt ] && exit 0
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 30 -subj "/CN=sn-id-issuer test CA" \
  -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=sn-id.test" 2>/dev/null
printf "subjectAltName=DNS:sn-id.test\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:false\nauthorityKeyIdentifier=keyid\n" > ext.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 30 -extfile ext.cnf 2>/dev/null
chmod 644 server.key
echo "certificats générés dans $(pwd)"
