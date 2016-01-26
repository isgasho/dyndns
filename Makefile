all: 
	go vet
	go fmt
	godep go build
