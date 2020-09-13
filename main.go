package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"flag"
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
	"gopkg.in/yaml.v2"
)

var config struct {
	Port int `yaml:"port"`
	Auth struct {
		User     string `yaml:"user"`
		Password string `yaml:"password"`
	}
	TLS struct {
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
	authString   string
	proxyFunc    func(*http.Request) (*url.URL, error)
	roundTripper http.RoundTripper
)

func loadConfig(configFile string) error {
	b, err := ioutil.ReadFile(configFile)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, &config)
}

func setupAutoProxy() {
	sd, err := time.ParseDuration(config.AutoProxy.SortDuration)
	if err != nil {
		log.Fatal().Err(err).Str("duration", config.AutoProxy.SortDuration).Msg("bad sort duration")
	}
	ap = autoproxy.New(&autoproxy.Option{
		SortPeriod: sd,
	})
	for _, fileName := range config.AutoProxy.Files {
		b, err := ioutil.ReadFile(fileName)
		if err != nil {
			log.Fatal().Err(err).Str("file", fileName).Msg("unable to read autoproxy file")
		}
		err = ap.Read(bytes.NewReader(b))
		if err != nil {
			log.Fatal().Err(err).Str("file", fileName).Msg("unable to read autoproxy file")
		}
	}
	proxyFunc = func(req *http.Request) (*url.URL, error) {
		match := ap.Match(req.URL)
		hlog.FromRequest(req).Info().Bool("match", match).Msg("proxy")
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
}

func setupAuthString() {
	auth := config.Auth.User + ":" + config.Auth.Password
	authString = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
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
		log.Logger = zerolog.New(&lumberjack.Logger{
			Filename:   config.Log.Path,
			MaxSize:    1,
			MaxBackups: 3,
			Compress:   true,
		}).With().Timestamp().Logger()
	}

	setupAutoProxy()
	setupAuthString()
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	proxyURL, err := proxyFunc(r)
	if err != nil {
		hlog.FromRequest(r).Error().Err(err).Msg("unable to get proxy url")
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
		if auth := r.Header.Get("Proxy-Authorization"); auth != authString {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		f.ServeHTTP(w, r)
	}
}

func getHandler(f http.HandlerFunc) http.Handler {
	var h http.Handler = f
	if config.Auth.User != "" || config.Auth.Password != "" {
		log.Info().Msg("using authorization")
		h = auth(h)
	}
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
