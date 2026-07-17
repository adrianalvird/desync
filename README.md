# About this framework :
This framework is just a basic desync detector with very high false positive rate . It's just for testing purpose only .

# Build :
$ go mod init desync
$ go mod tidy
$ go build -o desync ./cmd/main.go


# Usage : 
$ ./desync -target target.json
