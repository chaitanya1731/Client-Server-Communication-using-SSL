# Client-Server-Communication-using-SSL
Implemented a client and a server using Secure Socket Layer (SSL). SSL enables to establish a secure connection between the server and the client.

Created certificate using 

    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out chaitanya.pem -days 365
    

Install the OpenSSL library, for ubuntu use the below command.

    sudo apt-get install libssl–dev


Steps to run (terminal) -
  
    >> gcc -Wall -o sslserv Server.c -L/usr/lib -lssl -lcrypto       (Compile server code)
    >> gcc -Wall -o sslcli  Client.c -L/usr/lib -lssl -lcrypto       (Compile client code)
    >> ./sslserv                                                     (Start server)
    >> ./sslcli  127.0.0.1                                           (Start client code on localhost)
