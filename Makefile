.PHONY: all generate build run test-traffic clean

all: generate build

generate:
	go generate

build:
	go build -o ebpf-agent .

run:
	sudo ./ebpf-agent

test-traffic:
	@echo "Generating test TCP traffic..."
	curl -s https://google.com > /dev/null || true
	curl -s -I https://github.com > /dev/null || true
	@echo "Test requests completed."

clean:
	rm -f ebpf-agent bpf_bpfel.go bpf_bpfel.o
