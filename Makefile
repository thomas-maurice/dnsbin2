all:
	if ! [ -d bin ]; then mkdir bin; fi
	go build -v -o ./bin/server ./server
	go build -v -o ./bin/cli ./cli


docker:
	docker build -t dnsbin2-server .
