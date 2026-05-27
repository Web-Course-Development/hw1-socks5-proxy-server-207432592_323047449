package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// TODO: Implement SOCKS5 protocol
	// 1. Read client greeting and negotiate authentication method
	// 2. Perform authentication if required (when PROXY_USER env var is set)
	// 3. Read CONNECT request
	// 4. Connect to target server
	// 5. Send success/error reply
	// 6. Relay data between client and target

	_, err := negotiateAuth(conn)
	if err != nil {
		log.Printf("negotiateAuth error: %v", err)
		return
	}
}

func negotiateAuth(conn net.Conn) (byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, fmt.Errorf("reading greeting header: %w", err)
	}
	
	if header[0] != 0x05 {
		return 0, fmt.Errorf("unexpected SOCKS version: %d", header[0])
	}

	nMethods := int(header[1])
 	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, fmt.Errorf("reading methods: %w", err)
	}

 	proxyUser := os.Getenv("PROXY_USER")
	requireAuth := proxyUser != ""
	selected := byte(0xFF)
	for _, m := range methods {
		if requireAuth && m == 0x02 {
			selected = 0x02
			break
		}
		if !requireAuth && m == 0x00 {
			selected = 0x00
			break
		}
	}
 
	if _, err := conn.Write([]byte{0x05, selected}); err != nil {
		return 0, fmt.Errorf("writing method selection: %w", err)
	}

	if selected == 0xFF {
		return 0, fmt.Errorf("no acceptable auth method offered by client")
	}

	return selected, nil
}