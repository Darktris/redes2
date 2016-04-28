# Creacion clave privada cliente
#openssl genrsa -out client/clientkey.pem 2048
# Creacion clave publica y firmada por la CA
#openssl req -new -x509 -key client/clientkey.pem \
#-subj '/C=ES/ST=Madrid/L=Madrid/CN=client.uam.es' \
#-out clientcert.pem
openssl req -new -newkey rsa:2048 -keyout ./client/clientkey.pem \
-subj '/C=ES/ST=Madrid/L=Madrid/CN=client.uam.es/O=UAM/OU=EPS' \
-out ./client/client.csr -config ./ca/conf -nodes #-x509 esto hace certificado
#Firma la CA el certificado
openssl ca -cert ./ca/root.pem -keyfile ./ca/rootkey.pem \
-in ./client/client.csr -out ./client/clientcert.pem -config ./ca/conf
# Combinar certificados
cat ./client/clientcert.pem ./client/clientkey.pem > client.pem
# Comprobacion certificado
openssl x509 -subject -issuer -noout -in client.pem
