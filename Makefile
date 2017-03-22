
native:
	go build -o myna

win:
	GOOS=windows GOARCH=amd64 go build -o myna.exe

osx:
	GOOS=darwin GOARCH=386 go build -o myna

clean:
	rm -rf myna

deps:
	go get -u github.com/urfave/cli
	go get -u github.com/howeyc/gopass
	go get -u github.com/ebfe/scard
	go get -u github.com/ianmcmahon/encoding_ssh
	go get -u github.com/fullsailor/pkcs7

run:
	go run *.go
