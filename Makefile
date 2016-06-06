
build:
	go build -o jpki

clean:
	rm -rf jpki

deps:
	go get -u github.com/urfave/cli
	go get -u github.com/howeyc/gopass
	go get -u github.com/ebfe/go.pcsclite/scard
	go get -u github.com/ianmcmahon/encoding_ssh

run:
	go run *.go
