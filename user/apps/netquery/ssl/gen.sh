#!/bin/sh
rm CAfile.pem
for i in ca.crt nexusca.crt ; do
	openssl x509 -in $i -text >> CAfile.pem
done


