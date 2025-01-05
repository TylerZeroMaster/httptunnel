package httptunnel

import (
	"bufio"
	"errors"
	"net"
	"net/http"
)

var ErrBadOrigin = errors.New("httptunnel: request origin not allowed by HijackOptions.checkOrigin")

// Define a Hijacker for later use while handling a request
type Hijacker struct {
	// Customize handling of http request
	// Useful if you want to embed some reusable validation into the hijacker
	OverrideHandleRequest func(*http.Request) error
	// Customize how origin is checked.
	// Default behavior is to ignore origin if the header is unset, otherwise
	// check that host matches between header and url
	OverrideCheckOrigin func(*http.Request) error
}

func (h Hijacker) handleRequest(r *http.Request) error {
	if h.OverrideCheckOrigin == nil {
		if !checkSameOrigin(r) {
			return ErrBadOrigin
		}
	} else if err := h.OverrideCheckOrigin(r); err != nil {
		return err
	}
	if h.OverrideHandleRequest == nil {
		return nil
	}
	return h.OverrideHandleRequest(r)
}

// Hijack the underlying TCP connection
func (h Hijacker) Hijack(
	w http.ResponseWriter,
	r *http.Request,
) (net.Conn, *bufio.ReadWriter, error) {
	err := h.handleRequest(r)
	if err != nil {
		return nil, nil, err
	}
	netConn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		if netConn != nil {
			_ = netConn.Close()
		}
		return nil, nil, err
	}
	return netConn, brw, nil
}
