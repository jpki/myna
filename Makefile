
build:
	go build -o jpki

deps:
	go get -u github.com/urfave/cli
	go get -u github.com/ebfe/go.pcsclite/scard
	go get -u github.com/howeyc/gopass

run:
	go run *.go
