package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	httptunnel "github.com/TylerZeroMaster/http-tunnel"
	"github.com/docopt/docopt-go"
)

const usage = `
Dial ssh over http

Usage:
    ssh-dialer <http-url> <ssh-host> <ssh-port>
`

var dialer *httptunnel.Dialer = httptunnel.DefaultDialer

func assertNilErr(err error) {
	if err != nil {
		panic(err)
	}
}

func statusIs(status int, ok ...int) error {
	for _, code := range ok {
		if status == code {
			return nil
		}
	}
	return fmt.Errorf("request failed with status: %d", status)
}

func dialSsh(urlString, sshHost, sshPort string) {
	options := &httptunnel.ConnectionOptions{
		PrepareRequest: func(r *http.Request) error {
			r.Header.Set("x-ssh-host", sshHost)
			r.Header.Set("x-ssh-port", sshPort)
			return nil
		},
	}
	netConn, br, resp, err := dialer.Dial(urlString, options)
	assertNilErr(err)
	defer netConn.Close()
	assertNilErr(statusIs(resp.StatusCode, 101))
	go func() {
		_, err := br.WriteTo(os.Stdout)
		assertNilErr(err)
	}()
	// FIXME: This never dies if the connection fails
	// I think it gets stuck reading from ssh which gets stuck waiting for a
	// response (dead lock)
	_, err = os.Stdin.WriteTo(netConn)
	assertNilErr(err)
}

func isInt(s string) error {
	for _, b := range []byte(s) {
		if (b ^ 0x30) > 9 {
			return errors.New("not an integer: " + s)
		}
	}
	return nil
}

func main() {
	opts, err := docopt.ParseDoc(usage)
	assertNilErr(err)
	urlString := opts["<http-url>"].(string)
	sshHost := opts["<ssh-host>"].(string)
	sshPort := opts["<ssh-port>"].(string)
	assertNilErr(isInt(sshPort))
	dialSsh(urlString, sshHost, sshPort)
}
