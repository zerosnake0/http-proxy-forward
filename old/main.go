package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"strconv"
	"fmt"
	"bytes"
	"net/url"

	"golang.org/x/sync/errgroup"
	"golang.org/x/net/http/httpproxy"
)

var (
	port        int
	proxy       string
	proxyConfig = httpproxy.FromEnvironment()
	proxyFunc   = proxyConfig.ProxyFunc()
)

func init() {
	flag.IntVar(&port, "port", 9000, "port")
	flag.StringVar(&proxy, "proxy", "", "proxy")
	flag.Parse()
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	l, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		log.Panic(err)
	}

	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}
		log.Println("accepted", client)
		go handleClientRequest2(client)
	}
}

type readerFunc func(p []byte) (n int, err error)

func (rf readerFunc) Read(p []byte) (n int, err error) { return rf(p) }

func ctxCopy(ctx context.Context, dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, readerFunc(func(p []byte) (n int, err error) {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
			n, err = src.Read(p)
			log.Println(string(p))
			return
		}
	}))
	return err
}

func handleClientRequest2(client net.Conn) {
	if client == nil {
		return
	}
	defer client.Close()

	server, err := net.Dial("tcp", proxy)
	if err != nil {
		log.Println("dial failed", err)
		return
	}
	defer server.Close()

	eg, ctx := errgroup.WithContext(context.TODO())
	eg.Go(func() error {
		return ctxCopy(ctx, server, client)
	})
	eg.Go(func() error {
		return ctxCopy(ctx, client, server)
	})
	if err := eg.Wait(); err != nil {
		log.Println(err)
	}
}

func handleClientRequest(client net.Conn) {
	if client == nil {
		return
	}
	defer client.Close()

	var b [1024]byte
	n, err := client.Read(b[:])
	if err != nil {
		log.Println("unable to read first bytes", err)
		return
	}
	var method, host, address string
	fmt.Sscanf(string(b[:bytes.IndexByte(b[:], '\n')]), "%s%s", &method, &host)
	log.Println(method, host)
	reqURL, err := url.Parse(host)
	if err != nil {
		log.Println("bad url", err)
		return
	}
	log.Println("request url", reqURL.Scheme, reqURL.String())
	proxyURL, err := proxyFunc(reqURL)
	if err != nil {
		log.Println("bad proxy url", err)
		return
	}

	if proxyURL == nil {
		address = reqURL.Host
	} else {
		address = proxyURL.Host
	}

	server, err := net.Dial("tcp", address)
	if err != nil {
		log.Println(err)
		return
	}
	defer server.Close()

	if _, err := io.Copy(server, bytes.NewReader(b[:n])); err != nil {
		log.Println("unable to send analysed bytes to server", err)
		return
	}

	eg, ctx := errgroup.WithContext(context.TODO())
	eg.Go(func() error {
		return ctxCopy(ctx, server, client)
	})
	eg.Go(func() error {
		return ctxCopy(ctx, client, server)
	})
	if err := eg.Wait(); err != nil {
		log.Println(err)
	}
}
