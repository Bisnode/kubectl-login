#!/usr/bin/env bash

export GOOS=windows
export GOARCH=amd64

go build -v -o dist/windows/amd64/kubectl-login.exe

export GOOS=linux
export GOARCH=amd64

go build -v -o dist/linux/amd64/kubectl-login

export GOOS=darwin
export GOARCH=amd64

go build -v -o dist/darwin/amd64/kubectl-login
