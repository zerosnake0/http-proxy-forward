package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/natefinch/lumberjack"
	"github.com/zerosnake0/autoproxy"
)

var config struct {
	Port int `yaml:"port"`
	TLS  struct {
		Enabled bool   `yaml:"enabled"`
		Cert    string `yaml:"cert"`
		Key     string `yaml:"key"`
	} `yaml:"tls"`

	Log struct {
		Path string `yaml:"path"`
	}
	AutoProxy struct {
		SortDuration string   `yaml:"sortDuration"`
		Files        []string `yaml:"files"`
	} `yaml:"autoproxy"`
}

var (
	ap           *autoproxy.AutoProxy
	sn           uint64
	proxyFunc    func(*http.Request) (*url.URL, error)
	roundTripper http.RoundTripper
)

func init() {
	var configFile string
	flag.StringVar(&configFile, "config", "config.yaml", "config yaml file")
	flag.Parse()

	b, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatalf("unable to read config file %q: %s", configFile, err)
	}

	if err := yaml.Unmarshal(b, &config); err != nil {
		log.Fatalf("unable to unmarshal config: %s", err)
	}

	// autoproxy
	sd, err := time.ParseDuration(config.AutoProxy.SortDuration)
	if err != nil {
		log.Fatalf("bad sort duration %q: %s", config.AutoProxy.SortDuration, err)
	}
	ap = autoproxy.New(&autoproxy.Option{
		SortPeriod: sd,
	})
	for _, fileName := range config.AutoProxy.Files {
		b, err := ioutil.ReadFile(fileName)
		if err != nil {
			log.Fatalf("unable to read autoproxy file %q: %s", fileName, err)
		}
		err = ap.Read(bytes.NewReader(b))
		if err != nil {
			log.Fatalf("unable to read autoproxy rules of file %q: %s", fileName, err)
		}
	}
	proxyFunc = func(req *http.Request) (*url.URL, error) {
		match := ap.Match(req.URL)
		log.Printf("%d match: %t", req.Context().Value("id").(uint64), match)
		if !match {
			return nil, nil
		}
		return http.ProxyFromEnvironment(req)
	}
	roundTripper = &http.Transport{
		Proxy: proxyFunc,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if config.Log.Path != "" {
		log.SetOutput(&lumberjack.Logger{
			Filename:   config.Log.Path,
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
	proxyURL, err := proxyFunc(r)
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
	resp, err := roundTripper.RoundTrip(req)
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
		Addr: ":" + strconv.Itoa(config.Port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := atomic.AddUint64(&sn, 1)
			msg := fmt.Sprintf("[%d] %-15s -> %s", id, r.RemoteAddr, r.URL.String())
			log.Printf("beg: %s", msg)
			defer log.Printf("end: %s", msg)
			r = r.WithContext(context.WithValue(r.Context(), "id", id))
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
	if config.TLS.Enabled {
		log.Fatal(server.ListenAndServeTLS(config.TLS.Cert, config.TLS.Key))
	} else {
		log.Fatal(server.ListenAndServe())
	}
}
