package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// 1. Remove memory limit for eBPF map allocations
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock limit: %v", err)
	}

	// 2. Load compiled eBPF objects into kernel
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("failed loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// 3. Attach to kernel tracepoint
	tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TraceInetSockSetState, nil)
	if err != nil {
		log.Fatalf("failed attaching tracepoint: %v", err)
	}
	defer tp.Close()

	// 4. Create ring buffer reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("failed opening ringbuf reader: %v", err)
	}
	defer rd.Close()

	// 5. Handle graceful termination (Ctrl+C)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		fmt.Println("\nReceived interrupt. Detaching eBPF program and exiting...")
		rd.Close()
	}()

	fmt.Println("🚀 eBPF agent active. Monitoring TCP state transitions... (Ctrl+C to quit)")

	// 6. Event processing loop
	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("error reading ringbuf: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("error unmarshaling event: %v", err)
			continue
		}

		fmt.Printf("PID: %-6d | Ports: %5d -> %-5d | TCP State: %d -> %d\n",
			event.Pid, event.Sport, event.Dport, event.Oldstate, event.Newstate)
	}
}
