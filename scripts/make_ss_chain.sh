#!/bin/sh

if test -d certs; then
  echo "Directory exists."
else
  mkdir certs 
fi

cd certs

CANAME=MyOrg-RootCA
openssl genrsa -out $CANAME.key 4096
openssl req -x509 -new -nodes -key $CANAME.key -sha256 -days 1826 -out $CANAME.crt -subj '/CN=MyRootCA/C=AT/ST=Vienna/L=Vienna/O=MyOrg'

ISSUER=$CANAME

for INTERMEDIATE in 1 2
do
   KEY=intermediate${INTERMEDIATE}
   openssl genrsa -out $KEY.key 4096 
   openssl req -new -nodes -key $KEY.key -out $KEY.csr -subj "/CN=MyIntermediate$KEY/C=AT/ST=Vienna/L=Vienna/O=MyOrg"
   openssl x509 -req -in $KEY.csr -extfile extfile.cnf -extensions v3_ca -CA $ISSUER.crt -CAkey $ISSUER.key -CAcreateserial -out $KEY.crt -days 730 -sha256
   ISSUER=$KEY
done

MYCERT=myserver
openssl req -new -nodes -out $MYCERT.csr -newkey rsa:4096 -keyout $MYCERT.key -subj '/CN=MyCert/C=AT/ST=Vienna/L=Vienna/O=MyOrg'
openssl x509 -req -in $MYCERT.csr -CA $ISSUER.crt -CAkey $ISSUER.key -CAcreateserial -out $MYCERT.crt -days 730 -sha256