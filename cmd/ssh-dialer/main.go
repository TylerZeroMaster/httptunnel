package main

import (
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TylerZeroMaster/httptunnel"
	"github.com/TylerZeroMaster/httptunnel/internal/totp"
	"github.com/TylerZeroMaster/httptunnel/internal/totu"
	"github.com/docopt/docopt-go"
)

const usage = `Dial ssh over http

Usage:
    ssh-dialer <http-url> <ssh-host> <ssh-port> [--totp-config=<path>]

Options:
    --totp-config=<path>    Path to TOTP config
`

var versionString = "Version: " + httptunnel.Version + "\n" + httptunnel.License

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
	netConn, _, resp, err := dialer.Dial(urlString, options)
	tcpConn := httptunnel.AssertTCPConn(netConn)

	assertNilErr(err)
	defer netConn.Close()
	assertNilErr(statusIs(resp.StatusCode, 101))
	go func() {
		_, err := tcpConn.WriteTo(os.Stdout)
		assertNilErr(err)
	}()
	// TODO: Add deadlines?
	_, err = tcpConn.ReadFrom(os.Stdin)
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

func subTotpCode(input, totpPath string) (string, error) {
	config, err := totp.LoadConfig(totpPath)
	if err != nil {
		return "", err
	}
	code := totu.GenerateCode(time.Now(), config)
	return strings.ReplaceAll(input, "{{code}}", code), nil
}

type CLIOptions struct {
	HTTPUrl    string `docopt:"<http-url>"`
	SSHHost    string `docopt:"<ssh-host>"`
	SSHPort    string `docopt:"<ssh-port>"`
	TotpConfig string
}

func main() {
	var options CLIOptions
	opts, err := docopt.ParseArgs(usage, os.Args[1:], versionString)
	assertNilErr(err)
	opts.Bind(&options)
	urlString := options.HTTPUrl
	totpPath := options.TotpConfig
	assertNilErr(isInt(options.SSHPort))
	if len(totpPath) > 0 {
		urlString, err = subTotpCode(urlString, totpPath)
		assertNilErr(err)
	}
	dialSsh(urlString, options.SSHHost, options.SSHPort)
}
