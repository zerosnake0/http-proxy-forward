#!/bin/sh
set -ex
cd `dirname $0`
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 go build -a -installsuffix cgo -ldflags="-s -w" -o bin/proxy main.go
