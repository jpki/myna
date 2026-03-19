#!/bin/bash
set -e
DIR="$(dirname "$0")/fixtures"
mkdir -p "$DIR"

for TYPE in auth sign; do
    # CA
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$DIR/${TYPE}_ca_key.pem" -out "$DIR/${TYPE}_ca_cert.pem" \
      -days 3650 -subj "/CN=Test ${TYPE} CA"
    openssl x509 -in "$DIR/${TYPE}_ca_cert.pem" -outform der \
      -out "$DIR/${TYPE}_ca_cert.der"

    # End entity
    openssl req -newkey rsa:2048 -nodes \
      -keyout "$DIR/${TYPE}_key.pem" -out "$DIR/${TYPE}.csr" \
      -subj "/CN=Test ${TYPE} User"
    openssl x509 -req -in "$DIR/${TYPE}.csr" \
      -CA "$DIR/${TYPE}_ca_cert.pem" -CAkey "$DIR/${TYPE}_ca_key.pem" \
      -CAcreateserial -out "$DIR/${TYPE}_cert.pem" -days 3650
    openssl x509 -in "$DIR/${TYPE}_cert.pem" -outform der \
      -out "$DIR/${TYPE}_cert.der"

    rm -f "$DIR/${TYPE}.csr" "$DIR/${TYPE}_ca_cert.srl"
    rm -f "$DIR/${TYPE}_ca_key.pem" "$DIR/${TYPE}_ca_cert.pem" "$DIR/${TYPE}_cert.pem"
done
