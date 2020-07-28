ca=spamfree-ca
cli=spamfree

# CA
openssl genrsa -des3 -out $ca.key 2048
openssl req -new -x509 -config $ca.cfg  -days 1000 -key $ca.key -out $ca.crt

# client
openssl genrsa -des3 -out $cli.key 2048
openssl req -new  -config $cli.cfg -key $cli.key -out $cli.csr
openssl x509 -req -days 1000 -in $cli.csr -CA $ca.crt -CAkey $ca.key -set_serial 04 -out $cli.crt
openssl pkcs12 -export -in $cli.crt -inkey $cli.key -certfile $ca.crt -out $cli.p12
