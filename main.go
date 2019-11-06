package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"

	"github.com/natefinch/lumberjack"
)

var (
	port    int
	secure  bool
	pemPath string
	keyPath string
	logPath string
)

func init() {
	flag.IntVar(&port, "port", 9000, "port")
	flag.BoolVar(&secure, "secure", false, "use https")
	flag.StringVar(&pemPath, "pem", "server.pem", "path to pem file")
	flag.StringVar(&keyPath, "key", "server.key", "path to key file")
	flag.StringVar(&logPath, "log", "", "log path")
	flag.Parse()

	if logPath != "" {
		log.SetOutput(&lumberjack.Logger{
			Filename:   logPath,
			MaxSize:    1,
			MaxBackups: 3,
			Compress:   true,
		})
	}
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	proxyURL, err := http.ProxyFromEnvironment(r)
	if err != nil {
		log.Println("unable to get proxy url", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	var host string
	if proxyURL == nil {
		host = r.URL.Host
	} else {
		host = proxyURL.Host
	}
	dstConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		log.Println("unable to dial", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if proxyURL != nil {
		b, err := httputil.DumpRequest(r, true)
		if err != nil {
			log.Println("unable to dump request", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		if _, err := io.Copy(dstConn, bytes.NewReader(b)); err != nil {
			log.Println("unable to send connection", err)
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	} else {
		w.WriteHeader(http.StatusOK)
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Println("Hijacking not supported")
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	srcConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	go transfer(dstConn, srcConn)
	go transfer(srcConn, dstConn)
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func main() {
	server := http.Server{
		Addr: ":" + strconv.Itoa(port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("incoming request: %-15s -> %s\n", r.RemoteAddr, r.URL.String())
			if r.Method == http.MethodConnect {
				handleConnect(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	log.Println("serving...")
	if secure {
		log.Fatal(server.ListenAndServeTLS(pemPath, keyPath))
	} else {
		log.Fatal(server.ListenAndServe())
	}
}
