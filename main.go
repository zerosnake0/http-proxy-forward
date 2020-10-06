package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/mattn/go-colorable"
	"github.com/natefinch/lumberjack"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
	"github.com/zerosnake0/autoproxy"
	"golang.org/x/net/http/httpproxy"
	"gopkg.in/yaml.v2"
)

var config struct {
	Port int `yaml:"port"`
	Auth struct {
		Force  bool   `yaml:"force"`
		Smart  string `yaml:"smart"`
		Direct string `yaml:"direct"`
	}
	TLS struct {
		Enabled bool   `yaml:"enabled"`
		Cert    string `yaml:"cert"`
		Key     string `yaml:"key"`
	} `yaml:"tls"`

	Log struct {
		Format string `yaml:"format"`
		Path   string `yaml:"path"`
	}

	Proxy struct {
		HTTP  string `yaml:"http"`
		HTTPS string `yaml:"https"`
	} `yaml:"proxy"`
	AutoProxy struct {
		Enabled      bool     `yaml:"enabled"`
		SortDuration string   `yaml:"sortDuration"`
		Files        []string `yaml:"files"`
	} `yaml:"autoproxy"`
	Connect struct {
		Enabled      bool     `yaml:"enabled"`
		SortDuration string   `yaml:"sortDuration"`
		Files        []string `yaml:"files"`
	} `yaml:"connect"`
}

type userKey struct{}

var (
	ap               *autoproxy.AutoProxy
	authSmart        string
	authDirect       string
	proxyConfigFunc  func(*url.URL) (*url.URL, error)
	roundTripper     http.RoundTripper
	connectProxyFunc func(req *http.Request) (*url.URL, error)
)

func loadConfig(configFile string) error {
	b, err := ioutil.ReadFile(configFile)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, &config)
}

func loadAutoProxy(sortDuration string, files []string) (*autoproxy.AutoProxy, error) {
	sd, err := time.ParseDuration(sortDuration)
	if err != nil {
		return nil, err
	}
	proxy := autoproxy.New(&autoproxy.Option{
		SortPeriod: sd,
	})
	for _, fileName := range files {
		b, err := ioutil.ReadFile(fileName)
		if err != nil {
			return nil, fmt.Errorf("unable to read autoproxy from file %q: %s", fileName, err)
		}
		err = proxy.Read(bytes.NewReader(b))
		if err != nil {
			return nil, fmt.Errorf("unable to read autoproxy from file %q: %s", fileName, err)
		}
	}
	return proxy, nil
}

func proxyFunc(ap *autoproxy.AutoProxy) func(req *http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if ap != nil {
			user := req.Context().Value(userKey{}).(string)
			if user == "smart" {
				match := ap.Match(req.URL)
				hlog.FromRequest(req).Info().Bool("match", match).Msg("proxy")
				if !match {
					return nil, nil
				}
			}
		}
		return proxyConfigFunc(req.URL)
	}
}

func setupAutoProxy() {
	if config.AutoProxy.Enabled {
		var err error
		ap, err = loadAutoProxy(config.AutoProxy.SortDuration, config.AutoProxy.Files)
		if err != nil {
			log.Fatal().Err(err).Msg("unable to load autoproxy")
		}
	}
	roundTripper = &http.Transport{
		Proxy: proxyFunc(ap),
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
}

func formatAuthString(user, pwd string) string {
	auth := user + ":" + pwd
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

func setupAuthString() {
	authSmart = formatAuthString("smart", config.Auth.Smart)
	authDirect = formatAuthString("direct", config.Auth.Direct)
}

func setupProxy() {
	proxyConfig := httpproxy.Config{
		HTTPProxy:  config.Proxy.HTTP,
		HTTPSProxy: config.Proxy.HTTPS,
	}
	proxyConfigFunc = proxyConfig.ProxyFunc()
}

func setupConnectProxy() {
	var (
		connectAP *autoproxy.AutoProxy
		err       error
	)
	if config.Connect.Enabled {
		connectAP, err = loadAutoProxy(config.Connect.SortDuration, config.Connect.Files)
		if err != nil {
			log.Fatal().Err(err).Msg("unable to load connect autoproxy")
		}
	}
	connectProxyFunc = proxyFunc(connectAP)
}

func init() {
	consoleWriter := zerolog.NewConsoleWriter(func(w *zerolog.ConsoleWriter) {
		w.TimeFormat = time.RFC3339
		w.Out = colorable.NewColorableStdout()
	})
	log.Logger = zerolog.New(consoleWriter).With().Timestamp().Logger()

	var configFile string
	flag.StringVar(&configFile, "config", "config.yaml", "config yaml file")
	flag.Parse()

	if err := loadConfig(configFile); err != nil {
		log.Fatal().Err(err).Str("file", configFile).Msg("unable to read config file")
	}

	if config.Log.Path != "" {
		var writer io.Writer = &lumberjack.Logger{
			Filename:   config.Log.Path,
			MaxSize:    1,
			MaxBackups: 3,
			Compress:   true,
		}
		if config.Log.Format != "json" {
			writer = zerolog.NewConsoleWriter(func(cw *zerolog.ConsoleWriter) {
				cw.TimeFormat = time.RFC3339
				cw.Out = colorable.NewNonColorable(writer)
			})
		}
		log.Logger = zerolog.New(writer).With().Timestamp().Logger()
	}

	setupAuthString()
	setupProxy()
	setupAutoProxy()
	setupConnectProxy()
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	proxyURL, err := connectProxyFunc(r)
	if err != nil {
		hlog.FromRequest(r).Error().Err(err).Msg("unable to get proxy url")
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	hlog.FromRequest(r).Info().Bool("match", proxyURL != nil).Msg("proxy")
	var host string
	if proxyURL == nil {
		host = r.URL.Host
	} else {
		host = proxyURL.Host
	}
	d := net.Dialer{}
	dstConn, err := d.DialContext(r.Context(), "tcp", host)
	if err != nil {
		hlog.FromRequest(r).Error().Err(err).Msg("unable to dial")
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if proxyURL != nil {
		b, err := httputil.DumpRequest(r, true)
		if err != nil {
			hlog.FromRequest(r).Error().Err(err).Msg("unable to dump request")
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		if _, err := io.Copy(dstConn, bytes.NewReader(b)); err != nil {
			hlog.FromRequest(r).Error().Err(err).Msg("unable to send connection")
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	} else {
		w.WriteHeader(http.StatusOK)
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Error().Msg("Hijacking not supported")
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

func auth(f http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := "direct"
		auth := r.Header.Get("Proxy-Authorization")
		switch auth {
		case authSmart:
			user = "smart"
		case authDirect:
		default:
			if config.Auth.Force {
				hlog.FromRequest(r).Error().Msg("unauthorized")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		r = r.WithContext(context.WithValue(r.Context(), userKey{}, user))
		f.ServeHTTP(w, r)
	}
}

func getHandler(f http.HandlerFunc) http.Handler {
	var h http.Handler = f
	h = auth(h)
	h = hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Info().Int("status", status).Int("size", size).
			Dur("duration", duration).Msg("done")
	})(h)
	h = hlog.RequestHandler("req")(h)
	h = hlog.RemoteAddrHandler("ip")(h)
	h = hlog.UserAgentHandler("user_agent")(h)
	h = hlog.RequestIDHandler("req_id", "")(h)
	h = hlog.NewHandler(log.Logger)(h)
	return h
}

func main() {
	server := http.Server{
		Addr: ":" + strconv.Itoa(config.Port),
		Handler: getHandler(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleConnect(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	log.Info().Msg("serving...")
	var err error
	if config.TLS.Enabled {
		err = server.ListenAndServeTLS(config.TLS.Cert, config.TLS.Key)
	} else {
		err = server.ListenAndServe()
	}
	log.Fatal().Err(err).Msg("error while serving")
}
