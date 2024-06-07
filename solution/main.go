package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

const (
	bpfProgramFile = "drop_tcp_port.o"
	mapName        = "port_map"
	defaultPort    = 4040
)

func main() {
	// Parse port from command line arguments
	port := defaultPort
	if len(os.Args) == 2 {
		p, err := strconv.Atoi(os.Args[1])
		if err != nil {
			log.Fatalf("Invalid port: %v", err)
		}
		port = p
	} else if len(os.Args) > 2 {
		fmt.Printf("Usage: %s [port]\n", os.Args[0])
		os.Exit(1)
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load the compiled eBPF program into the kernel.
	spec, err := ebpf.LoadCollectionSpec(bpfProgramFile)
	if err != nil {
		log.Fatalf("Failed to load eBPF program: %v", err)
	}

	objs := struct {
		XdpDropTcpPort *ebpf.Program `ebpf:"xdp_drop_tcp_port"`
		PortMap        *ebpf.Map     `ebpf:"port_map"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Failed to load and assign eBPF objects: %v", err)
	}
	defer objs.XdpDropTcpPort.Close()
	defer objs.PortMap.Close()

	// Update the port number in the BPF map.
	var key uint32 = 0
	value := uint16(port)
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, value)

	if err := objs.PortMap.Put(key, buf); err != nil {
		log.Fatalf("Failed to update BPF map: %v", err)
	}

	// Attach the eBPF program to the XDP hook.
	ifaceName := "eth0" // Change this to your network interface
	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", ifaceName, err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDropTcpPort,
		Interface: iface.Attrs().Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer link.Close()

	fmt.Printf("Loaded BPF program and set port to %d\n", port)

	// Keep the program running.
	select {}
}
