# Limpieza del directorio
rm -rf ./ca/*.pem
rm -rf ./ca/*.txt
rm -rf ./ca/serial
rm -rf client
rm -rf server
mkdir -p ca server client
# Creacion clave privada root
openssl genrsa -out ./ca/rootkey.pem 2048
touch ./ca/index.txt ./ca/serial
echo "01" > ./ca/serial
mkdir -p ./ca/newcerts
# Creacion clave publica y firmada por la CA
openssl req -new -x509 -key ./ca/rootkey.pem \
-subj '/C=ES/ST=Madrid/L=Madrid/CN=ca.uam.es' \
-out ./ca/rootcert.pem
# Combinar certificados
cat ./ca/rootcert.pem ./ca/rootkey.pem > ./ca/root.pem
# Comprobacion certificado
openssl x509 -subject -issuer -noout -in ./ca/root.pem
