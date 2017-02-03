
build:
	go build -o jinc

clean:
	rm -rf jinc

deps:
	go get -u github.com/urfave/cli
	go get -u github.com/howeyc/gopass
	go get -u github.com/ebfe/scard
	go get -u github.com/ianmcmahon/encoding_ssh
	go get -u github.com/fullsailor/pkcs7

run:
	go run *.go
