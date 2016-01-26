## Simple dynamic DNS server

From 

http://mkaczanowski.com/golang-build-dynamic-dns-service-go/#server_code

## Start the server

```
godep go build
sudo ./dyndns 
```

Put this in update.txt:

```
server 127.0.0.1
debug no
zone example.com.
update delete db.example.com A
update add db.example.com. 120 A 10.2.23.67
send
```

## Do an update

```
nsupdate update.txt 
```

## Do a lookup

```
dig +short @127.0.0.1 db.example.com
10.2.23.67
```
