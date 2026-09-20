.PHONY: build test check security fuzz clean proxy-demo proxy-check public-proxy

build:
	go build -trimpath -o bin/veil ./cmd/veil

test:
	go test ./...

check:
	go vet ./...
	go test -race -cover ./...

security:
	gosec ./...

fuzz:
	go test ./cell -run='^$$' -fuzz='^FuzzChannel$$' -fuzztime=10s
	go test ./cell -run='^$$' -fuzz='^FuzzVersions$$' -fuzztime=10s
	go test ./cell -run='^$$' -fuzz='^FuzzBodies$$' -fuzztime=10s
	go test ./ntor -run='^$$' -fuzz='^FuzzFinish$$' -fuzztime=10s
	go test ./cell -run='^$$' -fuzz='^FuzzChannelHandshakeBodies$$' -fuzztime=10s
	go test ./torcert -run='^$$' -fuzz='^FuzzCertificateChain$$' -fuzztime=10s
	go test ./directory -run='^$$' -fuzz='^FuzzDirectoryDocuments$$' -fuzztime=10s
	go test ./circuit -run='^$$' -fuzz='^FuzzStreamControl$$' -fuzztime=10s
	go test ./socks5 -run='^$$' -fuzz='^FuzzRequest$$' -fuzztime=10s
	go test ./socks5 -run='^$$' -fuzz='^FuzzNegotiate$$' -fuzztime=10s
	go test ./onion -run='^$$' -fuzz='^FuzzDescriptor$$' -fuzztime=10s
	go test ./onion -run='^$$' -fuzz='^FuzzDescriptorItemsAndLinks$$' -fuzztime=10s

clean:
	rm -rf bin coverage.out

proxy-demo:
	python3 scripts/proxy_demo.py

proxy-check:
	python3 scripts/proxy_demo.py --check

public-proxy: build
	./bin/veil proxy -public -state ./state-public -listen 127.0.0.1:9050
