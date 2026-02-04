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
	Host         string
	Port         int
	ServiceGuess string
	Reachable    bool
	Banner       string
	HTTPHeaders  map[string]string
	Notes        []string
	DurationS    float64
}
func setSocketTimeout(conn net.Conn, timeout float64) error {
	return conn.SetDeadline(time.Now().Add(time.Duration(timeout * float64(time.Second))))
}
func recvAll(conn net.Conn, timeout float64, maxBytes int) (string, error) {
	if err := setSocketTimeout(conn, timeout); err != nil {
		return "", err
	}
	var buffer string
	tmp := make([]byte, 2048)
	for len(buffer) < maxBytes {
		n, err := conn.Read(tmp)
		if n > 0 {
			buffer += string(tmp[:n])
			if strings.Contains(buffer, "\r\n\r\n") {
				break
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return buffer, err
		}
	}
	return buffer, nil
}
func parseHTTPResponse(data string, headers map[string]string, notes *[]string) {
	lines := strings.Split(data, "\r\n")
	if len(lines) == 0 {
		return
	}
	statusLine := lines[0]
	headers["status_line"] = statusLine
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		*notes = append(*notes, "Malformed HTTP status line")
		return
	}
	headers["status_code"] = parts[1]
	if len(parts) == 3 {
		headers["reason"] = parts[2]
	} else {
		headers["reason"] = ""
	}
	if parts[1] != "200" {
		*notes = append(*notes, "HTTP non-200 status: "+parts[1])
	}
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		pos := strings.Index(line, ":")
		if pos < 0 {
			continue
		}
		key := line[:pos]
		val := strings.TrimLeft(line[pos+1:], " \t")
		headers[key] = val
	}
}
func probeHTTPS(conn net.Conn, host string, timeout float64, result *ScanResult) {
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}
	tlsConn := tls.Client(conn, cfg)
	_ = tlsConn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		result.Notes = append(result.Notes, "TLS handshake failed")
		return
	}
	result.Reachable = true
	state := tlsConn.ConnectionState()
	// TLS version
	var ver string
	switch state.Version {
	case tls.VersionTLS13:
		ver = "TLSv1.3"
	case tls.VersionTLS12:
		ver = "TLSv1.2"
	case tls.VersionTLS11:
		ver = "TLSv1.1"
	case tls.VersionTLS10:
		ver = "TLSv1.0"
	default:
		ver = fmt.Sprintf("Unknown (%d)", state.Version)
	}
	result.Notes = append(result.Notes, "TLS version: "+ver)
	// Cipher
	result.Notes = append(result.Notes, "Cipher: "+tls.CipherSuiteName(state.CipherSuite))
	// ALPN
	if state.NegotiatedProtocol != "" {
		result.Notes = append(result.Notes, "ALPN protocol: "+state.NegotiatedProtocol)
	}
	// Certificate
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Notes = append(result.Notes, "TLS Subject: "+cert.Subject.String())
		result.Notes = append(result.Notes, "TLS Issuer: "+cert.Issuer.String())
	}
	req := fmt.Sprintf(
		"HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: banner-scanner/1.0\r\n\r\n",
		host,
	)
	_, _ = tlsConn.Write([]byte(req))
	data, _ := recvAll(tlsConn, timeout, BANNER_READ_BYTES)
	result.Banner = data
	parseHTTPResponse(data, result.HTTPHeaders, &result.Notes)
	if srv, ok := result.HTTPHeaders["Server"]; ok {
		norm := ""
		if strings.Contains(srv, "Apache") {
			norm = "Apache"
		} else if strings.Contains(srv, "nginx") {
			norm = "nginx"
		} else if strings.Contains(srv, "Microsoft-IIS") {
			norm = "IIS"
		}
		if norm != "" {
			result.Notes = append(result.Notes, "Normalized server: "+norm)
		}
	}
}
func probeTCPBanner(host string, port int, timeout float64) ScanResult {
	result := ScanResult{
		Host:         host,
		Port:         port,
		ServiceGuess: DEFAULT_PORTS[port],
		HTTPHeaders:  make(map[string]string),
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), time.Duration(timeout)*time.Second)
	if err != nil {
		result.Notes = append(result.Notes, "connect failed")
		return result
	}
	defer conn.Close()
	result.Reachable = true
	_ = setSocketTimeout(conn, timeout)
	if port == 80 || port == 443 {
		if port == 443 {
			probeHTTPS(conn, host, timeout, &result)
		} else {
			userAgent := "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.166 Safari/537.36\r\n\r\n"
			req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s", host, userAgent)
			if _, err := conn.Write([]byte(req)); err != nil {
				result.Notes = append(result.Notes, "HTTP send error")
			}
			data, _ := recvAll(conn, timeout, BANNER_READ_BYTES)
			result.Banner = data
			parseHTTPResponse(data, result.HTTPHeaders, &result.Notes)
		}
	} else {
		data, _ := recvAll(conn, timeout, BANNER_READ_BYTES)
		result.Banner = data
	}
	result.DurationS = time.Since(start).Seconds()
	return result
}
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println(" ", os.Args[0], "target_host [--timeout 3.0] [--threads 8] [--json out.json]")
		return
	}
	host := os.Args[1]
	timeout := 3.0
	threads := 8
	jsonOut := ""
	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--timeout":
			i++
			timeout, _ = strconv.ParseFloat(os.Args[i], 64)
		case "--threads":
			i++
			threads, _ = strconv.Atoi(os.Args[i])
		case "--json":
			i++
			jsonOut = os.Args[i]
		default:
			fmt.Println("Unknown or incomplete option:", os.Args[i])
			return
		}
	}
	var ports []int
	for p := range DEFAULT_PORTS {
		ports = append(ports, p)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	results := []ScanResult{}
	work := make(chan int, len(ports))
	for i := range ports {
		work <- i
	}
	close(work)
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go func() {
			defer wg.Done()
			for idx := range work {
				r := probeTCPBanner(host, ports[idx], timeout)
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	for _, r := range results {
		fmt.Printf("[%s:%d] ", r.Host, r.Port)
		if !r.Reachable {
			fmt.Println("unreachable")
			continue
		}
		fmt.Printf("reachable (%.2fs)\n", r.DurationS)
		if r.Banner != "" {
			fmt.Println(r.Banner)
		}
		for _, n := range r.Notes {
			fmt.Println("  -", n)
		}
		fmt.Println()
	}
	if jsonOut != "" {
		f, _ := os.Create(jsonOut)
		defer f.Close()
		json.NewEncoder(f).Encode(map[string]interface{}{
			"results": results,
		})
	}
}
