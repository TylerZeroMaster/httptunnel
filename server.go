package httptunnel

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"time"
)

type HijackOptions struct {
	HandshakeTimeout      time.Duration
	OverrideHandleRequest func(*http.Request) error
	OverrideCheckOrigin   func(*http.Request) error
}

func (options *HijackOptions) HandleRequest(r *http.Request) error {
	if options.OverrideCheckOrigin == nil {
		if !checkSameOrigin(r) {
			return errors.New("http-tunnel: request origin not allowed by HijackOptions.checkOrigin")
		}
	} else if err := options.OverrideCheckOrigin(r); err != nil {
		return err
	}
	if options.OverrideHandleRequest == nil {
		return nil
	}
	return options.OverrideHandleRequest(r)
}

func Hijack(
	w http.ResponseWriter,
	r *http.Request,
	options *HijackOptions,
) (net.Conn, *bufio.ReadWriter, error) {
	err := options.HandleRequest(r)
	if err != nil {
		return nil, nil, err
	}
	netConn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return nil, nil, err
	}
	return netConn, brw, nil
}
