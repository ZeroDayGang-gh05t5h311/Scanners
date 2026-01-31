package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var DEFAULT_PORTS = map[int]string{
	21:  "ftp",
	22:  "ssh",
	23:  "telnet",
	25:  "smtp",
	80:  "http",
	443: "https",
}

const BANNER_READ_BYTES = 4096

type ScanResult struct {
	Host        string
	Port        int
	ServiceGuess string
	Reachable   bool
	Banner      string
	HTTPHeaders map[string]string
	Notes       []string
	DurationS   float64
}

func setSocketTimeout(conn net.Conn, timeout float64) error {
	err := conn.SetDeadline(time.Now().Add(time.Duration(timeout * float64(time.Second))))
	return err
}

func recvAll(conn net.Conn, timeout float64, maxBytes int) (string, error) {
	err := setSocketTimeout(conn, timeout)
	if err != nil {
		return "", err
	}
	var buffer string
	buf := make([]byte, 2048)
	for len(buffer) < maxBytes {
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			return buffer, err
		}
		buffer += string(buf[:n])
		if strings.Contains(buffer, "\r\n\r\n") {
			break
		}
	}
	return buffer, nil
}

func parseHTTPResponse(data string, headers map[string]string, notes []string) {
	lines := strings.Split(data, "\r\n")
	if len(lines) == 0 {
		return
	}

	statusLine := lines[0]
	headers["status_line"] = statusLine
	statusParts := strings.SplitN(statusLine, " ", 3)
	if len(statusParts) >= 2 {
		statusCode := statusParts[1]
		reason := ""
		if len(statusParts) > 2 {
			reason = statusParts[2]
		}
		headers["status_code"] = statusCode
		headers["reason"] = reason
		if statusCode != "200" {
			notes = append(notes, "HTTP non-200 status: "+statusCode)
		}
	} else {
		notes = append(notes, "Malformed HTTP status line")
		return
	}

	for _, line := range lines[1:] {
		if len(line) == 0 {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
}

func probeHTTPS(conn net.Conn, host string, timeout float64, result *ScanResult) {
	// Using Go's tls package for HTTPS
	config := &tls.Config{
		InsecureSkipVerify: true, // This skips verifying the server's certificate, just like the C++ example
		ServerName:         host,
	}

	tlsConn := tls.Client(conn, config)
	err := tlsConn.Handshake()
	if err != nil {
		result.Notes = append(result.Notes, "TLS handshake failed: "+err.Error())
		return
	}

	result.Reachable = true

	// Fix for the TLS version string
	tlsVersion := tlsConn.ConnectionState().Version
	var tlsVersionStr string
	switch tlsVersion {
	case tls.VersionTLS13:
		tlsVersionStr = "TLSv1.3"
	case tls.VersionTLS12:
		tlsVersionStr = "TLSv1.2"
	case tls.VersionTLS11:
		tlsVersionStr = "TLSv1.1"
	case tls.VersionTLS10:
		tlsVersionStr = "TLSv1.0"
	default:
		tlsVersionStr = fmt.Sprintf("Unknown version %d", tlsVersion)
	}
	result.Notes = append(result.Notes, "TLS version: "+tlsVersionStr)

	// Send HTTP request to probe
	req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: banner-scanner/1.0\r\n\r\n", host)
	_, err = tlsConn.Write([]byte(req))
	if err != nil {
		result.Notes = append(result.Notes, "HTTP send error: "+err.Error())
		return
	}

	data, err := recvAll(tlsConn, timeout, BANNER_READ_BYTES)
	if err != nil {
		result.Notes = append(result.Notes, "Failed to read HTTP response: "+err.Error())
		return
	}

	result.Banner = data
	parseHTTPResponse(data, result.HTTPHeaders, result.Notes)

	if server, ok := result.HTTPHeaders["Server"]; ok {
		normalized := ""
		if strings.Contains(server, "Apache") {
			normalized = "Apache"
		} else if strings.Contains(server, "nginx") {
			normalized = "nginx"
		} else if strings.Contains(server, "Microsoft-IIS") {
			normalized = "IIS"
		}
		result.Notes = append(result.Notes, "Normalized server: "+normalized)
	}
}

func probeTCPBanner(host string, port int, timeout float64) ScanResult {
	var result ScanResult
	result.Host = host
	result.Port = port
	result.ServiceGuess = DEFAULT_PORTS[port]
	result.HTTPHeaders = make(map[string]string) // Initialize the HTTPHeaders map here

	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, time.Duration(timeout)*time.Second)
	if err != nil {
		result.Notes = append(result.Notes, "connect failed: "+err.Error())
		return result
	}
	defer conn.Close()

	start := time.Now()
	err = setSocketTimeout(conn, timeout)
	if err != nil {
		result.Notes = append(result.Notes, "Failed to set timeout: "+err.Error())
		return result
	}

	// Handle HTTP (80, 443) ports specially
	if port == 80 || port == 443 {
		if port == 443 {
			probeHTTPS(conn, host, timeout, &result)
		} else {
			req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n\r\n", host)
			_, err := conn.Write([]byte(req))
			if err != nil {
				result.Notes = append(result.Notes, "HTTP send error: "+err.Error())
				data, _ := recvAll(conn, timeout, BANNER_READ_BYTES)
				result.Banner = data
			} else {
				data, _ := recvAll(conn, timeout, BANNER_READ_BYTES)
				result.Banner = data
				parseHTTPResponse(data, result.HTTPHeaders, result.Notes)
			}
		}
	} else {
		data, err := recvAll(conn, timeout, BANNER_READ_BYTES)
		if err != nil {
			result.Notes = append(result.Notes, "Failed to read banner: "+err.Error())
		} else {
			result.Banner = data
		}
	}

	result.DurationS = time.Since(start).Seconds()
	return result
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  ", os.Args[0], "target_host [--timeout 3.0] [--threads 8] [--json out.json]")
		return
	}

	host := os.Args[1]
	timeout := 3.0
	threads := 8
	jsonOut := ""

	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "--timeout" && i+1 < len(os.Args) {
			timeout, _ = strconv.ParseFloat(os.Args[i+1], 64)
			i++
		} else if arg == "--threads" && i+1 < len(os.Args) {
			threads, _ = strconv.Atoi(os.Args[i+1])
			i++
		} else if arg == "--json" && i+1 < len(os.Args) {
			jsonOut = os.Args[i+1]
			i++
		} else {
			fmt.Println("Unknown or incomplete option:", arg)
			return
		}
	}

	var ports []struct {
		Port   int
		Service string
	}

	for port, service := range DEFAULT_PORTS {
		ports = append(ports, struct {
			Port    int
			Service string
		}{port, service})
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []ScanResult
	workQueue := make(chan int, len(ports))

	// Add all the ports to the work queue
	for i := 0; i < len(ports); i++ {
		workQueue <- i
	}

	// Define the worker goroutine
	worker := func() {
		defer wg.Done()
		for idx := range workQueue {
			port := ports[idx].Port
			result := probeTCPBanner(host, port, timeout)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}
	}

	// Start worker goroutines
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go worker()
	}

	// Close the work queue after assigning work
	close(workQueue)

	// Wait for all goroutines to finish
	wg.Wait()

	// Output the results
	for _, result := range results {
		fmt.Printf("[%s:%d] ", result.Host, result.Port)
		if !result.Reachable {
			fmt.Println("unreachable")
			continue
		}
		fmt.Printf("reachable (%.2fs)\n", result.DurationS)
		if result.Banner != "" {
			fmt.Println(result.Banner)
		}
		for _, note := range result.Notes {
			fmt.Printf("  - %s\n", note)
		}
		fmt.Println()
	}

	// If output file is provided, write JSON results
	if jsonOut != "" {
		file, _ := os.Create(jsonOut)
		defer file.Close()

		type JSONResult struct {
			Host       string            `json:"host"`
			Port       int               `json:"port"`
			Reachable  bool              `json:"reachable"`
			Duration   float64           `json:"duration"`
			Banner     string            `json:"banner"`
			Headers    map[string]string `json:"headers"`
			Notes      []string          `json:"notes"`
		}

		jResults := make([]JSONResult, len(results))
		for i, r := range results {
			jResults[i] = JSONResult{
				Host:      r.Host,
				Port:      r.Port,
				Reachable: r.Reachable,
				Duration:  r.DurationS,
				Banner:    r.Banner,
				Headers:   r.HTTPHeaders,
				Notes:     r.Notes,
			}
		}

		jsonData, _ := json.MarshalIndent(map[string]interface{}{
			"results": jResults,
		}, "", "  ")

		file.Write(jsonData)
	}
}
