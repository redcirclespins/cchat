# *cchat* - CLI chat-app written in C with Linux Socket API featuring TLS

## FEATURES

- straightforward source code
- TLS up to 1.3 via OpenSSL
- clean chat interface

## DEPENDENCIES

- OpenSSL

```
sudo apt update;sudo apt install gcc make openssl libssl-dev
```

## CERTIFICATES

```
mkdir cert;cd cert
openssl rand -out pass -hex 32
openssl genrsa -aes256 -passout pass:$(cat pass) -out cert.key 4096
openssl req -new -key cert.key -passin pass:$(cat pass) -out cert.pem -x509 -days 356
```

when executing last command press enter everywhere except COMMON NAME field<br>
in COMMON NAME enter ip address of server where the server-side will be hosted<br>
you can also enter 'localhost' for testing 

## COMPILE

before compilation put password form cert/pass to *CERTPWD* macro at the top of *server.c* file

```
make
```

## RUN SERVER & CLIENT

```
usage: ./server <port>
```

before running client you should:
1. ```mkdir cert```
2. copy the *cert.pem* inside the cert directory
3. ensure the user that will run the client has read permissions to the file *cert.pem*

```
usage: ./client <server-ip-address> <port>
```

## ENABLE PORT FORWARDING ON SERVER SIDE

1. you should ensure traffic coming from outside world to specified port is let through the NAT device (router)<br>
*you can do this through web panel of router in PORT FORWARDING section for example*
2. on the machine where the server-side is run you should also enable port forwarding so that firewall lets through the packages coming to server<br>
*you can do this with iptables / ufw / firewalld (change the port):*

```
sudo iptables -A INPUT -p tcp --dport <port> -j ACCEPT
```

**OR**

```
sudo ufw allow <port>/tcp
```

**OR**

```
sudo firewall-cmd --permanent --add-port=<port>/tcp
sudo firewall-cmd --reload
```

## COMING SOON

- end-to-end encryption
- windows support
- android support
- ipv6 support
