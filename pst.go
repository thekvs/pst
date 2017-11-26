package main

import (
	"bufio"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	unknownAuthType int = iota
	basicAuthType   int = iota
	digestAuthType  int = iota
)

type config struct {
	connections   int
	urlsFile      string
	proxy         string
	duration      time.Duration
	sleep         time.Duration
	logFile       string
	reqNumPerConn int
	reqNumTotal   int
}

type proxyUserAuthData struct {
	username string
	password string
}

type digestAuthData struct {
	realm  string
	qop    string
	nonce  string
	cnonce string
	nc     uint64
}

const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
const defaultUserAgent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)"
const tcpKeepAliveInterval = 1 * time.Minute
const maxRedirectsCount = 10

const (
	proxyAuthorizationHeader = "Proxy-Authorization"
	proxyAuthenticateHeader  = "Proxy-Authenticate"
	userAgentHeader          = "User-Agent"
)

func closeResource(c io.Closer) {
	err := c.Close()
	if err != nil {
		log.Fatal(err)
	}
}

func makeRandomString(length int) string {
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = chars[rand.Intn(len(chars))]
	}

	return string(b)
}

func getProxyUserAuthData(client *http.Client, req *http.Request) *proxyUserAuthData {
	tr := client.Transport
	info, _ := tr.(*http.Transport).Proxy(req)

	if info.User == nil {
		return nil
	}

	username := info.User.Username()
	password, _ := info.User.Password()

	data := &proxyUserAuthData{username: username, password: password}

	return data
}

func addBasicAuthHeader(req *http.Request, userData *proxyUserAuthData) {
	if userData == nil {
		return
	}

	s := userData.username + ":" + userData.password
	header := "Basic " + base64.StdEncoding.EncodeToString([]byte(s))

	req.Header.Add(proxyAuthorizationHeader, header)
}

func addDigestAuthHeader(req *http.Request, userData *proxyUserAuthData, digestData *digestAuthData) {
	if userData == nil || digestData == nil {
		return
	}

	s := userData.username + ":" + digestData.realm + ":" + userData.password
	ha1 := fmt.Sprintf("%x", md5.Sum([]byte(s)))

	uri := req.URL.Path
	if req.URL.RawQuery != "" {
		uri += "?" + req.URL.RawQuery
	}

	s = req.Method + ":" + uri
	ha2 := fmt.Sprintf("%x", md5.Sum([]byte(s)))

	var (
		response string
		header   string
	)

	if digestData.qop == "" {
		s = ha1 + ":" + digestData.nonce + ":" + ha2
		response = fmt.Sprintf("%x", md5.Sum([]byte(s)))
		header = fmt.Sprintf("Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"",
			userData.username,
			digestData.realm,
			digestData.nonce,
			uri,
			response)
	} else if digestData.qop == "auth" || digestData.qop == "auth-int" {
		nc := fmt.Sprintf("%08x", digestData.nc)
		digestData.nc++
		s = ha1 + ":" + digestData.nonce + ":" + nc + ":" + digestData.cnonce + ":" + digestData.qop + ":" + ha2
		response = fmt.Sprintf("%x", md5.Sum([]byte(s)))
		header = fmt.Sprintf("Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", qop=%s, nc=%s, cnonce=\"%s\", response=\"%s\"",
			userData.username,
			digestData.realm,
			digestData.nonce,
			uri,
			digestData.qop,
			nc,
			digestData.cnonce,
			response)
	} else {
		log.Fatalf("unexpected proxy's qop directive value: '%s'", digestData.qop)
	}

	req.Header.Add(proxyAuthorizationHeader, header)
}

func getDigestAuthData(h string) *digestAuthData {
	m := make(map[string]string)

	quotedStringsRegexp := regexp.MustCompile("\"(.*?)\"")
	commasRegexp := regexp.MustCompile(",")

	quotes := quotedStringsRegexp.FindAllStringSubmatchIndex(h, -1)
	commas := commasRegexp.FindAllStringSubmatchIndex(h, -1)

	separateCommas := make([]int, 0, 8)
	var quotedComma bool

	for _, commaIndices := range commas {
		commaIndex := commaIndices[0]
		quotedComma = false
		for _, quoteIndices := range quotes {
			if len(quoteIndices) == 4 && commaIndex >= quoteIndices[2] && commaIndex <= quoteIndices[3] {
				quotedComma = true
				break
			}
		}
		if !quotedComma {
			separateCommas = append(separateCommas, commaIndex)
		}
	}

	tokens := make([]string, 0, 10)
	s := 0

	for _, val := range separateCommas {
		e := val
		tokens = append(tokens, strings.Trim(h[s:e], " "))
		s = e + 1
	}

	tokens = append(tokens, strings.Trim(h[s:len(h)], " "))

	for _, token := range tokens {
		kv := strings.SplitN(token, "=", 2)
		m[kv[0]] = strings.Trim(kv[1], "\"")
	}

	data := digestAuthData{nc: 1}

	if v, ok := m["realm"]; ok {
		data.realm = v
	}

	if v, ok := m["nonce"]; ok {
		data.nonce = v
	}

	if v, ok := m["qop"]; ok {
		data.qop = v
	}

	data.cnonce = makeRandomString(16)

	return &data
}

func worker(cfg *config, client *http.Client, ch chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	var (
		userAuthData           *proxyUserAuthData
		digestData             *digestAuthData
		authType               int
		singleURLRequestsCount int
		processedUrlsCount     int
	)

	addAuthHeader := func(req *http.Request) {
		switch authType {
		case basicAuthType:
			addBasicAuthHeader(req, userAuthData)
		case digestAuthType:
			addDigestAuthHeader(req, userAuthData, digestData)
		}
	}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		redirectsCount := len(via)
		if redirectsCount > 0 {
			if redirectsCount > maxRedirectsCount {
				errorMsg := fmt.Sprintf("too many (%d) redirects", redirectsCount)
				return errors.New(errorMsg)
			}

			headers := via[redirectsCount-1].Header
			req.Header.Set(userAgentHeader, headers.Get(userAgentHeader))
			addAuthHeader(req)
		}

		return nil
	}

	for {
		url, alive := <-ch
		// check if channel has been closed
		if !alive {
			return
		}

		if strings.HasPrefix(url, "https://") {
			log.Printf("HTTPS protocol not supported yet, skipping '%s'\n", url)
			continue
		}

		singleURLRequestsCount = 0

		for {
			if singleURLRequestsCount >= 2 {
				log.Fatalf("Failed to authenticate on proxy server")
			}

			if cfg.sleep > 0 {
				time.Sleep(cfg.sleep)
			}

			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				log.Printf("Error '%v' while preparing request for url '%s'", err, url)
				break
			}

			req.Header.Add(userAgentHeader, defaultUserAgent)
			addAuthHeader(req)

			resp, err := client.Do(req)
			if err != nil {
				log.Printf("Error '%v' while fetching '%s'\n", err, url)
				break
			}

			_, err = ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Printf("Error '%v' while reading body from '%s'", err, url)
			}
			closeResource(resp.Body)
			singleURLRequestsCount++

			if resp.StatusCode != 407 {
				break
			}

			if userAuthData == nil {
				userAuthData = getProxyUserAuthData(client, req)
			}

			if authType == unknownAuthType {
				h := resp.Header.Get(proxyAuthenticateHeader)
				s := strings.SplitN(h, " ", 2)
				if len(s) != 2 {
					log.Fatalf("unexpected 'Proxy-Authenticate' header format: '%s'\n", h)
				}
				switch s[0] {
				case "Digest":
					authType = digestAuthType
					digestData = getDigestAuthData(s[1])
				case "Basic":
					authType = basicAuthType
				default:
					log.Fatalln("Unexpected auth. scheme type:", s[0])
				}
			}
		}

		processedUrlsCount++
		if cfg.reqNumPerConn > 0 && processedUrlsCount >= cfg.reqNumPerConn {
			return
		}
	}
}

func urlSubmitter(cfg *config, urlProcessChannel chan string, quitSignalChannel chan bool) {
	file, err := os.Open(cfg.urlsFile)
	if err != nil {
		log.Fatalf("Can't open file '%s': %v\n", cfg.urlsFile, err)
	}
	defer closeResource(file)

	var (
		url                string
		submittedUrlsCount int
	)

	for {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			url = scanner.Text()
			if strings.HasPrefix(url, "#") || strings.HasPrefix(url, "//") {
				continue
			}

			select {
			case exit := <-quitSignalChannel:
				if exit {
					close(urlProcessChannel)
					return
				}
			default:
				urlProcessChannel <- url
				submittedUrlsCount++
				if cfg.reqNumTotal > 0 && submittedUrlsCount >= cfg.reqNumTotal {
					close(urlProcessChannel)
					return
				}
			}
		}
		_, err = file.Seek(0, os.SEEK_SET)
		if err != nil {
			log.Fatalf("Seet() failed: %v\n", err)
		}
	}
}

func initLogger(cfg *config) {
	if cfg.logFile != "" {
		fh, err := os.OpenFile(cfg.logFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			log.Fatalf("couldn't open log file '%s'\n%v", cfg.logFile, err)
		}
		log.SetOutput(fh)
	}
}

func customDial(network, addr string) (net.Conn, error) {
	remoteAddr, err := net.ResolveTCPAddr(network, addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTCP(network, nil, remoteAddr)
	if err == nil {
		err = conn.SetKeepAlive(true)
		if err != nil {
			return conn, err
		}

		err = conn.SetKeepAlivePeriod(tcpKeepAliveInterval)
		if err != nil {
			return conn, err
		}
	}

	return conn, err
}

func checkCmdLineArgs(cfg *config) {
	if (cfg.duration > 0 && (cfg.reqNumTotal > 0 || cfg.reqNumPerConn > 0)) ||
		(cfg.reqNumTotal > 0 && cfg.reqNumPerConn > 0) {
		log.Fatalln("ambiguous cmd. line parametes")
	}

	if cfg.duration == 0 && cfg.reqNumTotal == 0 && cfg.reqNumPerConn == 0 {
		log.Fatalln("not enough args. given, at least one of the options -d, -r, -R has to be specified")
	}

	if cfg.proxy == "" {
		log.Fatalln("empty proxy not allowed")
	}
}

func makeHTTPClient(cfg *config) *http.Client {
	parsedProxyURL, parseError := url.Parse(cfg.proxy)
	proxyFunc := func(req *http.Request) (*url.URL, error) {
		return parsedProxyURL, parseError
	}

	transport := &http.Transport{Proxy: proxyFunc, Dial: customDial}
	client := &http.Client{Transport: transport}

	return client
}

func main() {
	rand.Seed(time.Now().UnixNano())

	connections := flag.Int("c", 10, "number of simultaneous connections to proxy")
	duration := flag.Duration("d", 0*time.Second, "for how long run stress test")
	sleep := flag.Duration("s", 0, "for how much time pause between urls' requests in a single connection")
	urlsFile := flag.String("u", "urls.txt", "file with urls (one per line) to request through proxy")
	proxy := flag.String("p", "http://127.0.0.1:3128", "HTTP proxy address")
	logFile := flag.String("l", "", "log file")
	reqNumPerConn := flag.Int("r", 0, "number of requests each connection has to issue")
	reqNumTotal := flag.Int("R", 0, "number of requests each connection has to issue")

	flag.Parse()

	cfg := &config{
		connections:   *connections,
		urlsFile:      *urlsFile,
		proxy:         *proxy,
		duration:      *duration,
		sleep:         *sleep,
		logFile:       *logFile,
		reqNumPerConn: *reqNumPerConn,
		reqNumTotal:   *reqNumTotal,
	}

	checkCmdLineArgs(cfg)
	initLogger(cfg)

	wg := &sync.WaitGroup{}
	wg.Add(cfg.connections)

	urlProcessChannel := make(chan string)
	quitSignalChannel := make(chan bool)

	go urlSubmitter(cfg, urlProcessChannel, quitSignalChannel)

	client := makeHTTPClient(cfg)
	for i := 0; i < cfg.connections; i++ {
		go worker(cfg, client, urlProcessChannel, wg)
	}

	if cfg.duration > 0 {
		time.Sleep(cfg.duration)
		quitSignalChannel <- true
	}

	wg.Wait()
	log.Println("Done.")
}
