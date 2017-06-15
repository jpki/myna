
mynag: mynag.go bindata.go
	go build

bindata.go:
	go-bindata usagi.png ../LICENSE

get-deps:
	go get -u github.com/mattn/go-gtk/gtk

clean:
	rm -rf mynag
