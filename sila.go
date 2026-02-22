package main
import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)
var DEFAULT_PORTS = map[int]string{
	21:   "ftp",
	22:   "ssh",
	23:   "telnet",
	25:   "smtp",
	53:   "dns",
	80:   "http",
	110:  "pop3",
	143:  "imap",
	443:  "https",
	3306: "mysql",
	6379: "redis",
	8080: "http-alt",
	8443: "https-alt",
}

const BANNER_READ_BYTES = 4096

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 4096)
	},
}

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

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	reader := bufio.NewReader(conn)
	var builder strings.Builder
	builder.Grow(maxBytes)

	for builder.Len() < maxBytes {
		n, err := reader.Read(buf)
		if n > 0 {
			builder.Write(buf[:n])
			if strings.Contains(builder.String(), "\r\n\r\n") {
				break
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return builder.String(), err
		}
	}

	return builder.String(), nil
}

func detectFingerprints(data string, port int, result *ScanResult) {
	if data == "" {
		return
	}

	switch {
	case strings.HasPrefix(data, "SSH-"):
		result.Notes = append(result.Notes, "Fingerprint: SSH service detected")

	case strings.HasPrefix(data, "220") && strings.Contains(data, "FTP"):
		result.Notes = append(result.Notes, "Fingerprint: FTP service detected")

	case strings.HasPrefix(data, "+OK"):
		result.Notes = append(result.Notes, "Fingerprint: POP3 service detected")

	case strings.Contains(data, "* OK"):
		result.Notes = append(result.Notes, "Fingerprint: IMAP service detected")

	case strings.HasPrefix(data, "220") && strings.Contains(data, "SMTP"):
		result.Notes = append(result.Notes, "Fingerprint: SMTP service detected")

	case strings.Contains(data, "Redis"):
		result.Notes = append(result.Notes, "Fingerprint: Redis service detected")

	case strings.Contains(data, "mysql_native_password"):
		result.Notes = append(result.Notes, "Fingerprint: MySQL service detected")

	case strings.HasPrefix(data, "HTTP/"):
		result.Notes = append(result.Notes, "Fingerprint: HTTP service detected")

	case port == 53 && len(data) > 0:
		result.Notes = append(result.Notes, "Fingerprint: Possible DNS service")

	case strings.Contains(strings.ToLower(data), "telnet"):
		result.Notes = append(result.Notes, "Fingerprint: Telnet service detected")
	}
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
	}

	if parts[1] != "200" {
		*notes = append(*notes, "HTTP non-200 status: "+parts[1])
	}

	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		if pos := strings.Index(line, ":"); pos > 0 {
			headers[line[:pos]] = strings.TrimSpace(line[pos+1:])
		}
	}
}

func probeHTTPS(conn net.Conn, host string, timeout float64, result *ScanResult) {
	cfg := &tls.Config{InsecureSkipVerify: true}
	if net.ParseIP(host) == nil {
		cfg.ServerName = host
	}

	tlsConn := tls.Client(conn, cfg)
	_ = tlsConn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	if err := tlsConn.Handshake(); err != nil {
		result.Notes = append(result.Notes, "TLS handshake failed")
		return
	}

	state := tlsConn.ConnectionState()

	result.Notes = append(result.Notes, "TLS version detected")
	result.Notes = append(result.Notes, "Cipher: "+tls.CipherSuiteName(state.CipherSuite))

	req := fmt.Sprintf(
		"HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: banner-scanner/1.0\r\nConnection: close\r\n\r\n",
		host,
	)

	_, _ = tlsConn.Write([]byte(req))
	data, _ := recvAll(tlsConn, timeout, BANNER_READ_BYTES)

	result.Banner = data
	parseHTTPResponse(data, result.HTTPHeaders, &result.Notes)
	detectFingerprints(data, result.Port, result)
}

func probeTCPBanner(host string, port int, timeout float64) ScanResult {
	result := ScanResult{
		Host:         host,
		Port:         port,
		ServiceGuess: DEFAULT_PORTS[port],
		HTTPHeaders:  make(map[string]string, 16),
		Notes:        make([]string, 0, 8),
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), time.Duration(timeout)*time.Second)
	result.DurationS = time.Since(start).Seconds()

	if err != nil {
		result.Notes = append(result.Notes, "connect failed")
		return result
	}

	defer conn.Close()
	result.Reachable = true

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	_ = setSocketTimeout(conn, timeout)

	if port == 80 || port == 8080 {
		req := fmt.Sprintf(
			"HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: banner-scanner/1.0\r\nConnection: close\r\n\r\n",
			host,
		)
		conn.Write([]byte(req))
		data, _ := recvAll(conn, timeout, BANNER_READ_BYTES)
		result.Banner = data
		parseHTTPResponse(data, result.HTTPHeaders, &result.Notes)
		detectFingerprints(data, port, &result)

	} else if port == 443 || port == 8443 {
		probeHTTPS(conn, host, timeout, &result)

	} else {
		data, _ := recvAll(conn, timeout, BANNER_READ_BYTES)
		result.Banner = data
		detectFingerprints(data, port, &result)
	}
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
	work := make(chan int, len(ports))
	for _, p := range ports {
		work <- p
	}
	close(work)
	results := make([]ScanResult, 0, len(ports))
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go func() {
			defer wg.Done()
			for port := range work {
				r := probeTCPBanner(host, port, timeout)
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
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
