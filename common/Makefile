.PHONY: keys clean default

OPENSSL=openssl

.DEFAULT: keys

keys: public-key.pem
	cp public-key.pem private-key.pem ../auth-server
	cp public-key.pem ../caddy-server

public-key.pem: private-key.pem
	openssl ec -in private-key.pem -pubout -out public-key.pem

private-key.pem:
	openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem

clean:
	rm -rf *.pem
