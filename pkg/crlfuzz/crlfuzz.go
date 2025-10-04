package crlfuzz

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aleister1102/crlfuzz/pkg/request"
)

// Scan will scanning for CRLF vulnerability against target
func Scan(urlStr string, method string, data string, headers []string, proxy string) (bool, error) {
	// Parse the base URL to extract host, scheme, etc.
	_, err := url.Parse(urlStr)
	if err != nil {
		// If URL parsing fails, try to extract host manually for raw request
		return sendRawRequest(urlStr, method, data, headers, proxy)
	}

	// Check if the URL contains control characters or invalid escapes
	if strings.Contains(urlStr, "\r") || strings.Contains(urlStr, "\n") ||
		strings.Contains(urlStr, "%oa") || strings.Contains(urlStr, "%u0") {
		// Send raw request to bypass URL validation
		return sendRawRequest(urlStr, method, data, headers, proxy)
	}

	// Standard HTTP request for valid URLs
	client := request.Client(proxy)
	req, e := http.NewRequest(method, urlStr, strings.NewReader(data))
	if e != nil {
		return false, errors.New(e.Error())
	}
	for _, header := range headers {
		parts := strings.SplitN(header, ":", 2)

		if len(parts) != 2 {
			continue
		}

		req.Header.Set(parts[0], parts[1])
	}

	res, e := client.Do(req)
	if e != nil {
		return false, errors.New(e.Error())
	}
	defer res.Body.Close()

	return isVuln(res), nil
}

// sendRawRequest sends a raw HTTP request bypassing URL validation
func sendRawRequest(urlStr string, method string, data string, headers []string, proxy string) (bool, error) {
	// Parse URL to extract components
	var scheme, host, path string

	if strings.HasPrefix(urlStr, "https://") {
		scheme = "https"
		urlStr = strings.TrimPrefix(urlStr, "https://")
	} else if strings.HasPrefix(urlStr, "http://") {
		scheme = "http"
		urlStr = strings.TrimPrefix(urlStr, "http://")
	} else {
		return false, errors.New("invalid URL scheme")
	}

	// Extract host and path
	parts := strings.SplitN(urlStr, "/", 2)
	host = parts[0]
	if len(parts) > 1 {
		path = "/" + parts[1]
	} else {
		path = "/"
	}

	// Set default port
	port := "80"
	if scheme == "https" {
		port = "443"
	}

	// Check if host contains port
	if strings.Contains(host, ":") {
		hostParts := strings.Split(host, ":")
		host = hostParts[0]
		port = hostParts[1]
	}

	// Connect to the server
	var conn net.Conn
	var err error

	address := net.JoinHostPort(host, port)

	if scheme == "https" {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		}
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 30 * time.Second}, "tcp", address, tlsConfig)
	} else {
		conn, err = net.DialTimeout("tcp", address, 30*time.Second)
	}

	if err != nil {
		return false, err
	}
	defer conn.Close()

	// Set timeouts
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Construct raw HTTP request
	rawRequest := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path)
	rawRequest += fmt.Sprintf("Host: %s\r\n", host)
	rawRequest += "User-Agent: CRLFuzz/1.4.0\r\n"
	rawRequest += "Accept: */*\r\n"

	for _, header := range headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			rawRequest += fmt.Sprintf("%s:%s\r\n", parts[0], parts[1])
		}
	}

	if data != "" {
		rawRequest += fmt.Sprintf("Content-Length: %d\r\n", len(data))
		rawRequest += "Content-Type: application/x-www-form-urlencoded\r\n"
	}

	rawRequest += "Connection: close\r\n\r\n"

	if data != "" {
		rawRequest += data
	}

	// Send request
	_, err = conn.Write([]byte(rawRequest))
	if err != nil {
		return false, err
	}

	// Read response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return isVuln(resp), nil
}

func isVuln(r *http.Response) bool {
	for key, header := range r.Header {
		if key == keyHeader {
			for _, value := range header {
				if strings.Contains(value, valHeader) {
					return true
				}
			}
		}
	}

	return false
}
