# Creacion clave privada cliente
#openssl genrsa -out client/clientkey.pem 2048
# Creacion clave publica y firmada por la CA
#openssl req -new -x509 -key client/clientkey.pem \
#-subj '/C=ES/ST=Madrid/L=Madrid/CN=client.uam.es' \
#-out clientcert.pem
openssl req -new -newkey rsa:2048 -keyout ./server/serverkey.pem \
-subj '/C=ES/ST=Madrid/L=Madrid/CN=server.uam.es/O=UAM/OU=EPS' \
-out ./server/server.csr -config ./ca/conf -nodes #-x509 esto hace certificado
#Firma la CA el certificado
openssl ca -cert ./ca/root.pem -keyfile ./ca/rootkey.pem \
-in ./server/server.csr -out ./server/servercert.pem -config ./ca/conf
# Combinar certificados
cat ./server/servercert.pem ./server/serverkey.pem > server.pem
# Comprobacion certificado
openssl x509 -subject -issuer -noout -in server.pem
