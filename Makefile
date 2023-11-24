LIBS += -I/usr/include/tirpc -ltirpc -lnsl
SERVER = server.cpp server_session.cpp server_utils.cpp auth_svc.c auth_xdr.c
CLIENT = client.cpp client_session.cpp client_utils.cpp auth_clnt.c auth_xdr.c

build: server client

.PHONY: build clean

server:
	g++ -o $@ -g $(SERVER) $(LIBS)

client:
	g++ -o $@ -g $(CLIENT) $(LIBS)

rpc:
	rpcgen -C auth.x

clean:
	rm -f client server
