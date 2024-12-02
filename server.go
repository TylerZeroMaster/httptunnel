package httptunnel

import (
	"bufio"
	"errors"
	"net"
	"net/http"
)

var errBadOrigin = errors.New("http-tunnel: request origin not allowed by HijackOptions.checkOrigin")

// TODO: Add more overrides?
type Hijacker struct {
	OverrideHandleRequest func(*http.Request) error
	OverrideCheckOrigin   func(*http.Request) error
}

func (h Hijacker) HandleRequest(r *http.Request) error {
	if h.OverrideCheckOrigin == nil {
		if !checkSameOrigin(r) {
			return errBadOrigin
		}
	} else if err := h.OverrideCheckOrigin(r); err != nil {
		return err
	}
	if h.OverrideHandleRequest == nil {
		return nil
	}
	return h.OverrideHandleRequest(r)
}

func (h Hijacker) Hijack(
	w http.ResponseWriter,
	r *http.Request,
) (net.Conn, *bufio.ReadWriter, error) {
	err := h.HandleRequest(r)
	if err != nil {
		return nil, nil, err
	}
	// TODO: deadlines?
	// TODO: handle buffered data?
	netConn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		if netConn != nil {
			_ = netConn.Close()
		}
		return nil, nil, err
	}
	return netConn, brw, nil
}
