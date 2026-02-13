package main
import (
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"math/rand"
	"os"
	"io/ioutil"
	"encoding/hex"
)
const (
	CONCURRENCY          = 8 //These may need to change depending on your target!
 	REQUEST_TIMEOUT      = 15 
	RATE_LIMIT_DELAY     = 0.15
	MAX_RETRIES          = 2
	METHOD_FAIL_LIMIT    = 12
)
var SUPPORTED_METHODS = []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
var HEADER_KEYS_TO_TEST = []string{"User-Agent", "Referer", "X-Forwarded-For", "X-Client-IP"}
var CMD_SEPARATORS = []string{";", "|", "&&", "||"}
type Logger struct {
	mu sync.Mutex
	fh *os.File
}
func NewLogger(path string) (*Logger, error) {
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &Logger{fh: fh}, nil
}
func (l *Logger) log(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := time.Now()
	logMsg := fmt.Sprintf("[%s] %s\n", t.Format("2006-01-02 15:04:05"), msg)
	l.fh.WriteString(logMsg)
	fmt.Print(logMsg)
}
func sha256Hash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
func makeMarker(prefix string) string {
	if prefix == "" {
		prefix = "INJ"
	}
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rand.Seed(time.Now().UnixNano())
	marker := prefix + "-"
	for i := 0; i < 6; i++ {
		marker += string(chars[rand.Intn(len(chars))])
	}
	return marker
}
func percentEncode(s string) string {
	var encoded strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 32 && c <= 126 {
			encoded.WriteByte(c)
		} else {
			encoded.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return encoded.String()
}
type HttpResponse struct {
	FinalURL string
	Status   int
	Headers  map[string]string
	Body     string
}
type HTTPClient struct {
	logger *Logger
}

func NewHTTPClient(logger *Logger) *HTTPClient {
	return &HTTPClient{logger: logger}
}
func (c *HTTPClient) fetch(url, method, data string, extraHeaders map[string]string) HttpResponse {
	client := &http.Client{Timeout: time.Duration(REQUEST_TIMEOUT) * time.Second}
	req, err := http.NewRequest(method, url, strings.NewReader(data))
	if err != nil {
		c.logger.log("Error creating request: " + err.Error())
		return HttpResponse{}
	}
	req.Header.Add("User-Agent", "SafeScannerStdLib/1.1")
	req.Header.Add("Accept", "*/*")
	for key, value := range extraHeaders {
		req.Header.Add(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		c.logger.log("Error making request: " + err.Error())
		return HttpResponse{}
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.logger.log("Error reading response body: " + err.Error())
		return HttpResponse{}
	}
	headers := make(map[string]string)
	for key, value := range resp.Header {
		headers[key] = strings.Join(value, ", ")
	}
	return HttpResponse{
		FinalURL: resp.Request.URL.String(),
		Status:   resp.StatusCode,
		Headers:  headers,
		Body:     string(body),
	}
}
type BaselineResponse struct {
	URL       string
	Status    int
	HdrHash   string
	BodyHash  string
}
func NewBaselineResponse(r HttpResponse) BaselineResponse {
	hdrs := ""
	for key, value := range r.Headers {
		hdrs += key + value
	}
	return BaselineResponse{
		URL:      r.FinalURL,
		Status:   r.Status,
		HdrHash:  sha256Hash(hdrs),
		BodyHash: sha256Hash(r.Body),
	}
}
func (b BaselineResponse) differs(r HttpResponse) bool {
	if r.Status != b.Status || r.FinalURL != b.URL {
		return true
	}
	hdrs := ""
	for key, value := range r.Headers {
		hdrs += key + value
	}
	return sha256Hash(hdrs) != b.HdrHash || sha256Hash(r.Body) != b.BodyHash
}
type Finding struct {
	Timestamp float64
	Ctx       string
	URL       string
	Method    string
	FinalURL  string
	Status    int
	Hits      []string
}
type SafeInjectionScanner struct {
	targets         []string
	client          *HTTPClient
	logger          *Logger
	mu              sync.Mutex
	results         []Finding
	methodFailCount map[string]map[string]int
}
func NewSafeInjectionScanner(targets []string, client *HTTPClient, logger *Logger) *SafeInjectionScanner {
	return &SafeInjectionScanner{
		targets:         targets,
		client:          client,
		logger:          logger,
		methodFailCount: make(map[string]map[string]int),
	}
}
func (s *SafeInjectionScanner) methodOK(url, method string) bool {
	failCount, exists := s.methodFailCount[url][method]
	return exists && failCount < METHOD_FAIL_LIMIT
}
func (s *SafeInjectionScanner) recordFail(url, method string) {
	s.methodFailCount[url][method]++
	if s.methodFailCount[url][method] == METHOD_FAIL_LIMIT {
		s.logger.log(fmt.Sprintf("SKIP %s %s (failure limit reached)", method, url))
	}
}
func (s *SafeInjectionScanner) record(f Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = append(s.results, f)
	s.logger.log(fmt.Sprintf("FINDING %s %s", f.Ctx, f.FinalURL))
}
func (s *SafeInjectionScanner) scanTarget(url string) {
	s.logger.log("TARGET start " + url)
	allowed := s.client.fetch(url, "OPTIONS", "", nil).Headers["Allow"]
	methods := SUPPORTED_METHODS
	if allowed != "" {
		methods = strings.Split(allowed, ",")
	}
	base := s.client.fetch(url, "GET", "", nil)
	baseline := NewBaselineResponse(base)
	for _, method := range methods {
		if !s.methodOK(url, method) {
			continue
		}
		for _, headerKey := range HEADER_KEYS_TO_TEST {
			marker := makeMarker("")
			extraHeaders := map[string]string{headerKey: marker}
			r := s.client.fetch(url, method, "", extraHeaders)
			if baseline.differs(r) && strings.Contains(r.Body, marker) {
				f := Finding{
					Timestamp: float64(time.Now().Unix()),
					Ctx:       "header:" + headerKey,
					URL:       url,
					Method:    method,
					FinalURL:  r.FinalURL,
					Status:    r.Status,
					Hits:      []string{"reflection"},
				}
				s.record(f)
			}
			time.Sleep(time.Duration(RATE_LIMIT_DELAY * float64(time.Second)))
		}
	}
	s.logger.log("TARGET done " + url)
}
func (s *SafeInjectionScanner) run() {
	var wg sync.WaitGroup
	for i := 0; i < CONCURRENCY; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				s.mu.Lock()
				if len(s.targets) == 0 {
					s.mu.Unlock()
					return
				}
				url := s.targets[0]
				s.targets = s.targets[1:]
				s.mu.Unlock()
				s.scanTarget(url)
			}
		}()
	}
	wg.Wait()
}
func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: SafeInjectionScanner <url>...")
		return
	}
	targets := os.Args[1:]
	logger, err := NewLogger("scan.log")
	if err != nil {
		log.Fatal("Error creating logger: ", err)
	}
	logger.log("Scan started")
	client := NewHTTPClient(logger)
	scanner := NewSafeInjectionScanner(targets, client, logger)
	scanner.run()
	logger.log("Scan complete")
}
