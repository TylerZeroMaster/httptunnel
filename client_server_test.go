package httptunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"sync"
	"testing"
	"time"
)

type mockServer struct {
	URL    string
	Server *httptest.Server
	wg     sync.WaitGroup
}

const (
	testPath       = "/mock/server"
	testQueryRaw   = "n=1"
	testRequestURI = testPath + "?" + testQueryRaw
	testProtocol   = "test"
)

var testHeaders = map[string]string{
	"x-test-value-1": "1",
	"x-test-value-2": "2",
}

var testHijacker = &Hijacker{}
var testDialer = Dialer{
	HandshakeTimeout: 30 * time.Second,
}
var testDialOptions = &ConnectionOptions{
	PrepareRequest: func(r *http.Request) error {
		for k, v := range testHeaders {
			r.Header.Set(k, v)
		}
		return nil
	},
}

func (s *mockServer) Close() {
	s.Server.Close()
	// Wait for handler functions to complete.
	s.wg.Wait()
}

func newServer(t *testing.T) *mockServer {
	var s mockServer
	s.Server = httptest.NewServer(testHandler{T: t, s: &s, hijacker: testHijacker})
	s.Server.URL += testRequestURI
	s.URL = s.Server.URL
	return &s
}

func newServerHijacker(t *testing.T, hijacker *Hijacker) *mockServer {
	var s mockServer
	s.Server = httptest.NewServer(testHandler{T: t, s: &s, hijacker: hijacker})
	s.Server.URL += testRequestURI
	s.URL = s.Server.URL
	return &s
}

func newTLSServer(t *testing.T) *mockServer {
	var s mockServer
	s.Server = httptest.NewTLSServer(testHandler{T: t, s: &s, hijacker: testHijacker})
	s.Server.URL += testRequestURI
	s.URL = s.Server.URL
	return &s
}

type testHandler struct {
	*testing.T
	s        *mockServer
	hijacker *Hijacker
}

func (t testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Because tests wait for a response from a server, we are guaranteed that
	// the wait group count is incremented before the test waits on the group
	// in the call to (*cstServer).Close().
	t.s.wg.Add(1)
	defer t.s.wg.Done()

	if r.URL.Path != testPath {
		t.Logf("expected path %v, got: %v", testPath, r.URL.Path)
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	if r.URL.RawQuery != testQueryRaw {
		t.Logf("expected query %v, got: %v", testQueryRaw, r.URL.RawQuery)
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	for k, expected := range testHeaders {
		if actual := r.Header.Get(k); actual != expected {
			t.Errorf("expected header %v = %v, got: %v = %v", k, expected, k, actual)
		}
	}
	w.Header().Set("Connection", "upgrade")
	w.Header().Set("Upgrade", testProtocol)
	w.Header().Set("Set-Cookie", "sessionID=1234")
	w.WriteHeader(http.StatusSwitchingProtocols)
	conn, brw, err := t.hijacker.Hijack(w, r)
	if err != nil {
		t.Logf("Hijack: %v", err)
		return
	}
	defer conn.Close()
	buf := make([]byte, 256)
	buffered := brw.Reader.Buffered()
	offset := 0
	if buffered > 0 {
		n, err := brw.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		offset += n
	}
	n, err := conn.Read(buf[offset:])
	if err != nil {
		t.Fatal(err)
	}
	offset += n
	_, err = conn.Write(buf[:offset])
	if err != nil {
		t.Fatal(err)
	}
}

func sendRecv(conn net.Conn, resp *http.Response, t *testing.T) {
	var err error
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("expected status code %v, got: %v", http.StatusSwitchingProtocols, resp.StatusCode)
	}
	sent := "test"
	amt, err := conn.Write([]byte(sent))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if amt != len(sent) {
		t.Fatalf("expected to write %v, wrote: %v", len(sent), amt)
	}
	buf := make([]byte, 256)
	amt, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if actual := string(buf[:amt]); actual != sent {
		t.Errorf("expected %v, got: %v", sent, actual)
	}
}

func TestDial(t *testing.T) {
	s := newServer(t)
	defer s.Close()

	testDialer := testDialer

	dialers := []*Dialer{&testDialer, nil}
	for _, dialer := range dialers {
		conn, _, resp, err := dialer.Dial(s.URL, testDialOptions)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer conn.Close()
		sendRecv(conn, resp, t)
	}
}

func TestDialURLError(t *testing.T) {
	s := newServer(t)
	defer s.Close()

	expectedErr := errors.New("test")
	opts := &ConnectionOptions{
		OverrideGetUrl: func(s string) (*url.URL, error) {
			return nil, expectedErr
		},
	}
	conn, br, resp, err := testDialer.Dial(s.URL, opts)
	if conn != nil || br != nil || resp != nil {
		t.Fatalf("should only return error")
	}
	if err != expectedErr {
		t.Fatalf("expected %v, got: %v", expectedErr, err)
	}
}

func TestProxyDial(t *testing.T) {
	s := newServer(t)
	defer s.Close()

	surl, _ := url.Parse(s.Server.URL)

	testDialer := testDialer // make local copy for modification on next line.
	testDialer.Proxy = http.ProxyURL(surl)

	connect := false
	origHandler := s.Server.Config.Handler

	// Capture the request Host header.
	s.Server.Config.Handler = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				connect = true
				w.WriteHeader(http.StatusOK)
				return
			}

			if !connect {
				t.Log("connect not received")
				http.Error(w, "connect not received", http.StatusMethodNotAllowed)
				return
			}
			origHandler.ServeHTTP(w, r)
		})

	conn, _, resp, err := testDialer.Dial(s.URL, testDialOptions)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	sendRecv(conn, resp, t)
}

func TestProxyAuthorizationDial(t *testing.T) {
	s := newServer(t)
	defer s.Close()

	surl, _ := url.Parse(s.Server.URL)
	surl.User = url.UserPassword("username", "password")

	testDialer := testDialer
	testDialer.Proxy = http.ProxyURL(surl)

	connect := false
	origHandler := s.Server.Config.Handler

	// Capture the request Host header.
	s.Server.Config.Handler = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			proxyAuth := r.Header.Get("Proxy-Authorization")
			expectedProxyAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("username:password"))
			if r.Method == http.MethodConnect && proxyAuth == expectedProxyAuth {
				connect = true
				w.WriteHeader(http.StatusOK)
				return
			}

			if !connect {
				t.Log("connect with proxy authorization not received")
				http.Error(w, "connect with proxy authorization not received", http.StatusMethodNotAllowed)
				return
			}
			origHandler.ServeHTTP(w, r)
		})

	conn, _, resp, err := testDialer.Dial(s.URL, testDialOptions)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	sendRecv(conn, resp, t)
}

func rootCAs(t *testing.T, s *httptest.Server) *x509.CertPool {
	certs := x509.NewCertPool()
	for _, c := range s.TLS.Certificates {
		roots, err := x509.ParseCertificates(c.Certificate[len(c.Certificate)-1])
		if err != nil {
			t.Fatalf("error parsing server's root cert: %v", err)
		}
		for _, root := range roots {
			certs.AddCert(root)
		}
	}
	return certs
}

func TestDialTLS(t *testing.T) {
	s := newTLSServer(t)
	defer s.Close()

	d := testDialer
	d.TLSClientConfig = &tls.Config{RootCAs: rootCAs(t, s.Server)}
	conn, _, resp, err := d.Dial(s.URL, testDialOptions)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	sendRecv(conn, resp, t)
}

func TestDialCookieJar(t *testing.T) {
	s := newServer(t)
	defer s.Close()

	jar, _ := cookiejar.New(nil)
	d := testDialer
	d.Jar = jar

	u, _ := url.Parse(s.URL)

	cookieName := "name"
	cookieValue := "value"

	cookies := []*http.Cookie{{Name: cookieName, Value: cookieValue, Path: "/"}}
	d.Jar.SetCookies(u, cookies)

	conn, _, resp, err := d.Dial(s.URL, testDialOptions)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	cookiesByName := make(map[string]string)
	for _, c := range d.Jar.Cookies(u) {
		cookiesByName[c.Name] = c.Value
	}

	expectedCookies := map[string]string{
		cookieName:  cookieValue,
		"sessionID": "1234",
	}
	for name, expected := range expectedCookies {
		actual, ok := cookiesByName[name]
		if !ok {
			t.Errorf("cookie not present in jar: %v", name)
		} else if actual != expected {
			t.Errorf("expected %v, got: %v", expected, actual)
		}
	}

	sendRecv(conn, resp, t)
}

func TestTracingDialWithContext(t *testing.T) {
	var (
		wroteHeaders,
		wroteRequest,
		getConn,
		gotConn,
		connectDone,
		gotFirstResponseByte,
		tlsHandshakeStarted,
		tLSHandshakeDone,
		_ bool
	)
	trace := &httptrace.ClientTrace{
		WroteHeaders: func() {
			wroteHeaders = true
		},
		WroteRequest: func(httptrace.WroteRequestInfo) {
			wroteRequest = true
		},
		GetConn: func(hostPort string) {
			getConn = true
		},
		GotConn: func(info httptrace.GotConnInfo) {
			gotConn = true
		},
		ConnectDone: func(network, addr string, err error) {
			connectDone = true
		},
		GotFirstResponseByte: func() {
			gotFirstResponseByte = true
		},
		TLSHandshakeStart: func() {
			tlsHandshakeStarted = true
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			tLSHandshakeDone = true
		},
	}
	ctx := httptrace.WithClientTrace(context.Background(), trace)

	s := newTLSServer(t)
	defer s.Close()

	d := testDialer
	d.TLSClientConfig = &tls.Config{RootCAs: rootCAs(t, s.Server)}

	conn, _, resp, err := d.DialContext(ctx, s.URL, testDialOptions)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if !wroteHeaders {
		t.Fatal("Headers was not written")
	}
	if !wroteRequest {
		t.Fatal("Request was not written")
	}
	if !getConn {
		t.Fatal("getConn was not called")
	}
	if !gotConn {
		t.Fatal("gotConn was not called")
	}
	if !connectDone {
		t.Fatal("connectDone was not called")
	}
	if !gotFirstResponseByte {
		t.Fatal("GotFirstResponseByte was not called")
	}
	if !tlsHandshakeStarted {
		t.Fatal("tlsHandshakeStarted was not called")
	}
	if !tLSHandshakeDone {
		t.Fatal("tLSHandshakeDone was not called")
	}
	defer conn.Close()

	sendRecv(conn, resp, t)
}

func TestHijackWithError(t *testing.T) {
	expectedError := errors.New("test")
	hijacker := Hijacker{
		OverrideHandleRequest: func(r *http.Request) error {
			return expectedError
		},
	}
	s := newServerHijacker(t, &hijacker)
	defer s.Close()
	s.Server.Config.Handler = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			conn, _, err := hijacker.Hijack(w, r)
			if err == nil {
				t.Errorf("expected %v, got: nil", expectedError)
			}
			if conn != nil {
				conn.Close()
			}
		},
	)
	dialer := Dialer{
		HandshakeTimeout: 123 * time.Millisecond,
	}
	conn, _, _, err := dialer.Dial(s.URL, testDialOptions)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 256)
	conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestHijackBadOrigin(t *testing.T) {
	s := newServer(t)
	defer s.Close()

	dialer := testDialer
	options := &ConnectionOptions{
		PrepareRequest: func(r *http.Request) error {
			testDialOptions.PrepareRequest(r)
			r.Header.Set("Origin", "http://mortis.com/")
			return nil
		},
	}
	s.Server.Config.Handler = http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _, err := testHijacker.Hijack(w, r)
			if err != ErrBadOrigin {
				t.Fatalf("expected %v, got: %v", ErrBadOrigin, err)
			}
		},
	)
	conn, _, _, err := dialer.Dial(s.URL, options)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
}

// TestNetDialConnect tests selection of dial method between NetDial, NetDialContext, NetDialTLS or NetDialTLSContext
func TestNetDialConnect(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Connection") == "Upgrade" {
			c, _, err := testHijacker.Hijack(w, r)
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
		} else {
			w.Header().Set("X-Test-Host", r.Host)
		}
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	tlsServer := httptest.NewTLSServer(handler)
	defer tlsServer.Close()

	testUrls := map[*httptest.Server]string{
		server:    "http://" + server.Listener.Addr().String() + "/",
		tlsServer: "https://" + tlsServer.Listener.Addr().String() + "/",
	}

	cas := rootCAs(t, tlsServer)
	tlsConfig := &tls.Config{
		RootCAs:            cas,
		ServerName:         "example.com",
		InsecureSkipVerify: false,
	}

	tests := []struct {
		name              string
		server            *httptest.Server // server to use
		netDial           func(network, addr string) (net.Conn, error)
		netDialContext    func(ctx context.Context, network, addr string) (net.Conn, error)
		netDialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
		tlsClientConfig   *tls.Config
	}{

		{
			name:   "HTTP server, all NetDial* defined, shall use NetDialContext",
			server: server,
			netDial: func(network, addr string) (net.Conn, error) {
				return nil, errors.New("NetDial should not be called")
			},
			netDialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				return net.Dial(network, addr)
			},
			netDialTLSContext: func(_ context.Context, network, addr string) (net.Conn, error) {
				return nil, errors.New("NetDialTLSContext should not be called")
			},
			tlsClientConfig: nil,
		},
		{
			name:              "HTTP server, all NetDial* undefined",
			server:            server,
			netDial:           nil,
			netDialContext:    nil,
			netDialTLSContext: nil,
			tlsClientConfig:   nil,
		},
		{
			name:   "HTTP server, NetDialContext undefined, shall fallback to NetDial",
			server: server,
			netDial: func(network, addr string) (net.Conn, error) {
				return net.Dial(network, addr)
			},
			netDialContext: nil,
			netDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return nil, errors.New("NetDialTLSContext should not be called")
			},
			tlsClientConfig: nil,
		},
		{
			name:   "HTTPS server, all NetDial* defined, shall use NetDialTLSContext",
			server: tlsServer,
			netDial: func(network, addr string) (net.Conn, error) {
				return nil, errors.New("NetDial should not be called")
			},
			netDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return nil, errors.New("NetDialContext should not be called")
			},
			netDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				netConn, err := net.Dial(network, addr)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(netConn, tlsConfig)
				err = tlsConn.Handshake()
				if err != nil {
					return nil, err
				}
				return tlsConn, nil
			},
			tlsClientConfig: nil,
		},
		{
			name:   "HTTPS server, NetDialTLSContext undefined, shall fallback to NetDialContext and do handshake",
			server: tlsServer,
			netDial: func(network, addr string) (net.Conn, error) {
				return nil, errors.New("NetDial should not be called")
			},
			netDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial(network, addr)
			},
			netDialTLSContext: nil,
			tlsClientConfig:   tlsConfig,
		},
		{
			name:   "HTTPS server, NetDialTLSContext and NetDialContext undefined, shall fallback to NetDial and do handshake",
			server: tlsServer,
			netDial: func(network, addr string) (net.Conn, error) {
				return net.Dial(network, addr)
			},
			netDialContext:    nil,
			netDialTLSContext: nil,
			tlsClientConfig:   tlsConfig,
		},
		{
			name:              "HTTPS server, all NetDial* undefined",
			server:            tlsServer,
			netDial:           nil,
			netDialContext:    nil,
			netDialTLSContext: nil,
			tlsClientConfig:   tlsConfig,
		},
		{
			name:   "HTTPS server, all NetDialTLSContext defined, dummy TlsClientConfig defined, shall not do handshake",
			server: tlsServer,
			netDial: func(network, addr string) (net.Conn, error) {
				return nil, errors.New("NetDial should not be called")
			},
			netDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return nil, errors.New("NetDialContext should not be called")
			},
			netDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				netConn, err := net.Dial(network, addr)
				if err != nil {
					return nil, err
				}
				tlsConn := tls.Client(netConn, tlsConfig)
				err = tlsConn.Handshake()
				if err != nil {
					return nil, err
				}
				return tlsConn, nil
			},
			tlsClientConfig: &tls.Config{
				RootCAs:            nil,
				ServerName:         "badserver.com",
				InsecureSkipVerify: false,
			},
		},
	}

	for _, tc := range tests {
		dialer := Dialer{
			NetDial:           tc.netDial,
			NetDialContext:    tc.netDialContext,
			NetDialTLSContext: tc.netDialTLSContext,
			TLSClientConfig:   tc.tlsClientConfig,
		}

		// Test websocket dial
		c, _, _, err := dialer.Dial(testUrls[tc.server], nil)
		if err != nil {
			t.Errorf("FAILED %s, err: %s", tc.name, err.Error())
		} else {
			c.Close()
		}
	}
}

func TestNextProtos(t *testing.T) {
	ts := httptest.NewUnstartedServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	d := Dialer{
		TLSClientConfig: ts.Client().Transport.(*http.Transport).TLSClientConfig,
	}

	r, err := ts.Client().Get(ts.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	r.Body.Close()

	// Asserts that Dialer.TLSClientConfig.NextProtos contains "h2"
	// after the Client.Get call from net/http above.
	var containsHTTP2 bool = false
	for _, proto := range d.TLSClientConfig.NextProtos {
		if proto == "h2" {
			containsHTTP2 = true
		}
	}
	if !containsHTTP2 {
		t.Fatalf("Dialer.TLSClientConfig.NextProtos does not contain \"h2\"")
	}

	_, _, _, err = d.Dial(ts.URL, nil)
	if err == nil {
		t.Fatalf("Dial succeeded, expect fail ")
	}
}
