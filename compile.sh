#!/bin/bash
gcc myclient.c -lssl -lcrypto -o vpnclient
echo "Successfully compiled myclient.c to vpnclient"
gcc myserver.c -lssl -lcrypto -lsqlite3 -o vpnserver
echo "Successfully compiled myserver.c to vpnserver"
