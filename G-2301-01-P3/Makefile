CC = gcc
CFLAGS = -L$(LDIR) -I$(IDIR) -g `pkg-config --cflags gtk+-3.0` -DNOCHDIR -DNDEBUG 
LDFLAGS = -lpthread -lircredes -lircinterface -lsoundredes -lirctad -lredes2-G-2301-01-P3 -lsoundredes -lpulse -lpulse-simple `pkg-config --libs gtk+-3.0` -lssl -lcrypto -rdynamic 
AR = ar 

TAR_FILE= G-2301-01-P3.tar.gz
SDIR = src
SLDIR = srclib
IDIR = includes
LDIR = lib
ODIR = obj
MDIR = man
DDIR = doc
BDIR = .

_LIB = libredes2-G-2301-01-P3.a
LIB = $(patsubst %,$(LDIR)/%,$(_LIB))

_LOBJ = G-2301-01-P1-daemon.o G-2301-01-P1-tcp.o G-2301-01-P1-udp.o G-2301-01-P2-rtp.o G-2301-01-P1-tools.o G-2301-01-P2-ucomm.o G-2301-01-P2-ccomm.o G-2301-01-P3-ssl.o G-2301-01-P1-server.o G-2301-01-P1-irc.o G-2301-01-P3-ssl-server.o
LOBJ = $(patsubst %,$(ODIR)/%,$(_LOBJ))

_DEPS = 
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = xchat2.o G-2301-01-P1-irc_server.o G-2301-01-P3-ssl_echo_server.o G-2301-01-P3-ssl_client.o #soundtest.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

_BIN = xchat2 G-2301-01-P3-ssl_echo_server G-2301-01-P3-ssl_client G-2301-01-P1-irc_server #soundtest
BIN = $(patsubst %,$(BDIR)/%,$(_BIN))

all: $(BIN) readme printopt

printopt:
	@echo ">>>> Opciones del makefile <<<<"
	@echo "'make' para construir"
	@echo "'make clean' para limpiar el entorno"
	@echo "'make doc' para generar la documentacion"
	@echo "'make compress' para comprimir la práctica"
	@echo "'make certificates' o 'make certificados' para generar los certificados"
$(LIB): $(LOBJ)
	$(AR) rcv $@ $^

$(LOBJ):$(ODIR)/%.o: $(SLDIR)/%.c
	$(CC) -c -o $@ $< $(CFLAGS)

$(OBJ):$(ODIR)/%.o: $(SDIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS) 

$(BIN):%: $(ODIR)/%.o $(LIB)
	$(CC) -o $@ $^ $(LDFLAGS) $(CFLAGS)

compress: clean doc
	rm -rf $(TAR_FILE)
	rm -rf G-2301-01-P3
	tar -zcvf ../$(TAR_FILE) ../G-2301-01-P3
	mv ../$(TAR_FILE) $(TAR_FILE)

doc: clean 
	doxygen
	@cat Readme

log: 
	tail -F /var/log/syslog | grep irc

readme: 
	@cat Readme
certificates: certificados
certificados:
	@echo "Generando clave de la CA"
	# Limpieza del directorio
	rm -rf cert/ca/*.pem cert/ca/*.txt cert/ca/serial cert/client cert/server
	mkdir -p cert/ca cert/server cert/client
	# Creacion clave privada root
	openssl genrsa -out cert/ca/rootkey.pem 2048
	touch cert/ca/index.txt cert/ca/serial
	echo "01" > cert/ca/serial
	mkdir -p cert/ca/newcerts
	# Creacion clave publica y firmada por si mismo
	openssl req -new -x509 -key ./cert/ca/rootkey.pem \
	-subj '/C=ES/ST=Madrid/L=Madrid/CN=ca.uam.es' \
	-out ./cert/ca/rootcert.pem
	# Combinar certificados
	cat cert/ca/rootcert.pem cert/ca/rootkey.pem > cert/ca/root.pem
	# Comprobacion certificado
	openssl x509 -subject -issuer -noout -in cert/ca/root.pem
	
	@echo "Generando certificado del cliente"
	# Generamos clave privada y peticion de firma
	openssl req -new -newkey rsa:2048 -keyout cert/client/clientkey.pem \
	-subj '/C=ES/ST=Madrid/L=Madrid/CN=client.uam.es/O=UAM/OU=EPS' \
	-out cert/client/client.csr -config cert/ca/conf -nodes 
	#Firma la CA el certificado
	openssl ca -cert cert/ca/root.pem -keyfile cert/ca/rootkey.pem \
	-in cert/client/client.csr -out cert/client/clientcert.pem -config cert/ca/conf -batch
	# Combinar certificados
	cat cert/client/clientcert.pem cert/client/clientkey.pem > cert/client.pem
	# Comprobacion certificado
	openssl x509 -subject -issuer -noout -in cert/client.pem
	@echo "Generando certificado del servidor"
	# Generamos clave privada y peticion de firma
	openssl req -new -newkey rsa:2048 -keyout cert/server/serverkey.pem \
	-subj '/C=ES/ST=Madrid/L=Madrid/CN=server.uam.es/O=UAM/OU=EPS' \
	-out cert/server/server.csr -config cert/ca/conf -nodes 
	#Firma la CA el certificado
	openssl ca -cert cert/ca/root.pem -keyfile cert/ca/rootkey.pem \
	-in cert/server/server.csr -out cert/server/servercert.pem -config cert/ca/conf -batch
	# Combinar certificados
	cat cert/server/servercert.pem cert/server/serverkey.pem cert/ca/rootcert.pem > cert/server.pem
	# Comprobacion certificado
	openssl x509 -subject -issuer -noout -in cert/server.pem

.PHONY: clean
clean:
	@rm -frv $(BIN) $(LIB) $(OBJ) $(LOBJ) 
	@mkdir -p obj lib
	@rm -fv $(TAR_FILE)
	@rm -fv core vgcore*  
