test: deps
	go test -race -v ./...

coverage: deps
	go list -f '{{if (len .TestGoFiles)}}{{.ImportPath}}{{end}}' ./... | grep -v /vendor/ \
	  | xargs -L1 -i bash -c 'go test -v -race -coverprofile="coverage.$$(echo "$$1" | md5sum | head -c 16).txt" -covermode=atomic "$$1"' "" {}

export IPFS_API ?= v04x.ipfs.io

gx:
	go get -u github.com/whyrusleeping/gx
	go get -u github.com/whyrusleeping/gx-go

deps: gx
	gx --verbose install --global
	gx-go rewrite
	go get -t ./...

