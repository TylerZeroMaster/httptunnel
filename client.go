package httptunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"
)

// A Dialer contains options for connecting to an http tunneling server.
//
// It is safe to call Dialer's methods concurrently.
type Dialer struct {
	// NetDial specifies the dial function for creating TCP connections. If
	// NetDial is nil, net.Dialer DialContext is used.
	NetDial func(network, addr string) (net.Conn, error)

	// NetDialContext specifies the dial function for creating TCP connections. If
	// NetDialContext is nil, NetDial is used.
	NetDialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// NetDialTLSContext specifies the dial function for creating TLS/TCP connections. If
	// NetDialTLSContext is nil, NetDialContext is used.
	// If NetDialTLSContext is set, Dial assumes the TLS handshake is done there and
	// TLSClientConfig is ignored.
	NetDialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// Proxy specifies a function to return a proxy for a given
	// Request. If the function returns a non-nil error, the
	// request is aborted with the provided error.
	// If Proxy is nil or returns a nil *URL, no proxy is used.
	Proxy func(*http.Request) (*url.URL, error)

	// TLSClientConfig specifies the TLS configuration to use with tls.Client.
	// If nil, the default configuration is used.
	// If either NetDialTLS or NetDialTLSContext are set, Dial assumes the TLS handshake
	// is done there and TLSClientConfig is ignored.
	TLSClientConfig *tls.Config

	// HandshakeTimeout specifies the duration for the handshake to complete.
	HandshakeTimeout time.Duration

	// ReadBufferSize and WriteBufferSize specify I/O buffer sizes in bytes. If a buffer
	// size is zero, then a useful default size is used. The I/O buffer sizes
	// do not limit the size of the messages that can be sent or received.
	ReadBufferSize, WriteBufferSize int

	// Jar specifies the cookie jar.
	// If Jar is nil, cookies are not sent in requests and ignored
	// in responses.
	Jar http.CookieJar

	OverrideGetUrl    func(string) (*url.URL, error)
	PrepareRequest    func(r *http.Request) error
	OverrideNewReader func(net.Conn) (*bufio.Reader, error)
}

// Dial creates a new client connection by calling DialContext with a background context.
func (d *Dialer) Dial(urlStr string) (net.Conn, *bufio.Reader, *http.Response, error) {
	return d.DialContext(context.Background(), urlStr)
}

func (d *Dialer) GetUrl(urlString string) (*url.URL, error) {
	if d.OverrideGetUrl != nil {
		return d.OverrideGetUrl(urlString)
	} else {
		return url.Parse(urlString)
	}
}

func (d *Dialer) NewReader(conn net.Conn) (*bufio.Reader, error) {
	if d.OverrideNewReader != nil {
		return d.OverrideNewReader(conn)
	} else {
		return bufio.NewReader(conn), nil
	}
}

// DialContext creates a new client connection.
// Use ConnectionOptions.PrepareRequest to customize the request before it is
// sent.
//
// The context will be used in the request and in the Dialer.
func (d *Dialer) DialContext(ctx context.Context, urlStr string) (net.Conn, *bufio.Reader, *http.Response, error) {
	if d == nil {
		panic("nil dialer")
	}

	u, err := d.GetUrl(urlStr)
	if err != nil {
		return nil, nil, nil, err
	}

	req := &http.Request{
		Method:     http.MethodGet,
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Host:       u.Host,
	}
	req = req.WithContext(ctx)

	// Set the cookies present in the cookie jar of the dialer
	if d.Jar != nil {
		for _, cookie := range d.Jar.Cookies(u) {
			req.AddCookie(cookie)
		}
	}

	if d.PrepareRequest != nil {
		if err := d.PrepareRequest(req); err != nil {
			return nil, nil, nil, err
		}
	}

	if d.HandshakeTimeout != 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, d.HandshakeTimeout)
		defer cancel()
	}

	netDial := dialerFuncForURL(u, d)
	netDial = maybeWrapDeadline(netDial, ctx)
	netDial, err = maybeWrapProxy(netDial, d, req)
	if err != nil {
		return nil, nil, nil, err
	}

	hostPort, hostNoPort := hostPortNoPort(u)
	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.GetConn != nil {
		trace.GetConn(hostPort)
	}

	netConn, err := netDial(ctx, "tcp", hostPort)
	if err != nil {
		return nil, nil, nil, err
	}
	if trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{
			Conn: netConn,
		})
	}

	// Close the network connection when returning an error. The variable
	// netConn is set to nil before the success return at the end of the
	// function.
	defer func() {
		if netConn != nil {
			// It's safe to ignore the error from Close() because this code is
			// only executed when returning a more important error to the
			// application.
			_ = netConn.Close()
		}
	}()

	if u.Scheme == "https" && d.NetDialTLSContext == nil {
		// If NetDialTLSContext is set, assume that the TLS handshake has already been done

		cfg := cloneTLSConfig(d.TLSClientConfig)
		if cfg.ServerName == "" {
			cfg.ServerName = hostNoPort
		}
		tlsConn := tls.Client(netConn, cfg)
		netConn = tlsConn

		if trace != nil && trace.TLSHandshakeStart != nil {
			trace.TLSHandshakeStart()
		}
		err := doHandshake(ctx, tlsConn, cfg)
		if trace != nil && trace.TLSHandshakeDone != nil {
			trace.TLSHandshakeDone(tlsConn.ConnectionState(), err)
		}

		if err != nil {
			return nil, nil, nil, err
		}
	}

	conn := netConn
	br, err := d.NewReader(netConn)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := req.Write(netConn); err != nil {
		return nil, nil, nil, err
	}

	if trace != nil && trace.GotFirstResponseByte != nil {
		if peek, err := br.Peek(1); err == nil && len(peek) == 1 {
			trace.GotFirstResponseByte()
		}
	}

	resp, err := http.ReadResponse(br, req)
	if err != nil {
		if d.TLSClientConfig != nil {
			for _, proto := range d.TLSClientConfig.NextProtos {
				if proto != "http/1.1" {
					return nil, nil, nil, fmt.Errorf(
						"http-tunnel: protocol %q was given but is not supported;"+
							"sharing tls.Config with net/http Transport can cause this error: %w",
						proto, err,
					)
				}
			}
		}
		return nil, nil, nil, err
	}

	if d.Jar != nil {
		if rc := resp.Cookies(); len(rc) > 0 {
			d.Jar.SetCookies(u, rc)
		}
	}

	resp.Body = io.NopCloser(bytes.NewReader([]byte{}))

	if err := netConn.SetDeadline(time.Time{}); err != nil {
		return nil, br, resp, err
	}

	// Success! Set netConn to nil to stop the deferred function above from
	// closing the network connection.
	netConn = nil

	return conn, br, resp, nil
}
