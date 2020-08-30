
native:
	go build

linux:
	GOOS=linux GOARCH=amd64 go build -o myna_linux

windows:
	GOOS=windows GOARCH=amd64 go build -o myna.exe

osx:
	GOOS=darwin GOARCH=amd64 go build -o myna

clean:
	rm -rf myna myna.exe

get-deps:
	go get -u github.com/spf13/cobra
	go get -u github.com/howeyc/gopass
	go get -u github.com/ebfe/scard
	go get -u github.com/ianmcmahon/encoding_ssh
	go get -u github.com/yu-ichiro/pkcs7
	go get -u github.com/hamano/brokenasn1
