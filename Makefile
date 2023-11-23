#/**
#	Sisteme de programe pentru retele de calculatoare
#	
#	Copyright (C) 2008 Ciprian Dobre & Florin Pop
#	Univerity Politehnica of Bucharest, Romania
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.

#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
# */
LIBS += -ltirpc -lnsl
build: server client

rpc:
	rpcgen -C auth.x

server:
	g++ -g -o server -g server.cpp session.cpp auth_svc.c auth_xdr.c $(LIBS)

client:
	g++ -g -o client -g client.cpp auth_clnt.c auth_xdr.c $(LIBS)

clean:
	rm -f client server
