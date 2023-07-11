
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
	go mod download
