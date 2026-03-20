.PHONY: client server
client: vpnclient
server: vpnserver

vpnclient:
    gcc myclient.c -lssl -lcrypto -o vpnclient
vpnserver:
    gcc myserver.c -lssl -lcrypto -lsqlite3 -o vpnserver

