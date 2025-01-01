package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TylerZeroMaster/httptunnel"
	"github.com/TylerZeroMaster/httptunnel/internal/totu"
	"github.com/docopt/docopt-go"
	"github.com/rs/zerolog"
)

const usage = `Tunnel ssh over http

Usage:
    ssh-tunnel-server [--port=<port>] [--totp-config=<path>]...

Options:
    --port=<port>           The port for the http server to listen on [default: 8080]
    --totp-config=<path>    Path to TOTP config
`

var versionString = "Version: " + httptunnel.Version + "\n" + httptunnel.License

var log = zerolog.New(os.Stderr).
	With().
	Timestamp().
	Logger().
	Level(zerolog.DebugLevel)

var hijacker = &httptunnel.Hijacker{}

type SSHTunnelHandler struct{}

func (handler SSHTunnelHandler) sendHttpResp(w http.ResponseWriter) {
	w.Header().Set("Connection", "upgrade")
	w.Header().Set("Upgrade", "ssh")
	w.WriteHeader(http.StatusSwitchingProtocols)
}

func (handler SSHTunnelHandler) getSSHAddress(r *http.Request) string {
	sshHost := r.Header.Get("x-ssh-host")
	sshPort := r.Header.Get("x-ssh-port")
	if len(sshHost) == 0 {
		sshHost = "localhost"
	}
	if len(sshPort) == 0 {
		sshPort = "22"
	}
	return fmt.Sprintf("%s:%s", sshHost, sshPort)
}

func (handler SSHTunnelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := log.With().Str("url", r.URL.String()).Logger()
	log.Info().Msg("Connection opened")
	defer log.Info().Msg("Connection closed")
	address := handler.getSSHAddress(r)
	log.Debug().Str("address", address).Msg("dialing ssh")
	if sshConn, err := net.DialTimeout("tcp", address, 45*time.Second); err != nil {
		log.Error().Err(err).Msg("dial ssh")
		http.Error(w, err.Error(), 500)
	} else {
		sshTcpConn := httptunnel.AssertTCPConn(sshConn)
		handler.sendHttpResp(w)
		if httpConn, brw, err := hijacker.Hijack(w, r); err != nil {
			log.Error().Err(err).Msg("hijack")
		} else {
			defer httpConn.Close()
			httpTcpConn := httptunnel.AssertTCPConn(httpConn)
			if brw.Reader.Buffered() > 0 {
				log.Warn().Msg("client sent data prematurely")
				brw.WriteTo(sshTcpConn)
			}
			go func() {
				defer sshConn.Close()
				readAmt, err := httpTcpConn.WriteTo(sshTcpConn)
				if err != nil {
					log.Error().Err(err).Msg("copy to ssh")
				}
				log.Debug().Int64("bytes_read", readAmt).Msg("read finished")
			}()
			// FIXME: ssh connection remains open in certain conditions.
			// One fix is to close `sshConn` above. Granted, this creates
			// a "use of closed network connection"  error.
			// Maybe there's a better way?
			writeAmt, err := httpTcpConn.ReadFrom(sshTcpConn)
			if err != nil && !errors.Is(err, net.ErrClosed) {
				log.Error().Err(err).Msg("copy to http")
			}
			log.Debug().Int64("bytes_written", writeAmt).Msg("write finished")
		}
	}
}

type TOTUHandler struct {
	next      http.Handler
	validator totu.Validator
}

func (handler TOTUHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := handler.validator.Validate(time.Now(), r.PathValue("code"))
	switch err {
	case nil:
		handler.next.ServeHTTP(w, r)
		return
	case totu.ErrCodeAlreadyUsed:
		http.Error(w, "401 unauthorized", http.StatusUnauthorized)
	default:
		http.Error(w, "404 page not found", http.StatusNotFound)
	}
	log.Err(err).Msg("totu validation error")
}

func NewTOTUHandler(validator totu.Validator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return TOTUHandler{next, validator}
	}
}

type CLIOptions struct {
	Port       string
	TotpConfig []string
}

func main() {
	var options CLIOptions
	opts, err := docopt.ParseArgs(usage, os.Args[1:], versionString)
	if err != nil {
		panic(err)
	}
	opts.Bind(&options)
	port := options.Port
	port = ":" + strings.Trim(port, ": ")
	if port == ":" {
		panic("empty port")
	}
	totpPaths := options.TotpConfig
	if len(totpPaths) > 0 {
		log.Info().Strs("path", totpPaths).Msg("using totp config")
		validator, err := totu.NewValidator(totpPaths)
		if err != nil {
			panic(err)
		}
		http.Handle("GET /{code}", NewTOTUHandler(validator)(SSHTunnelHandler{}))
	} else {
		http.Handle("GET /ssh", SSHTunnelHandler{})
	}
	log.Info().Str("port", port).Msg("listening")
	log.Error().Err(http.ListenAndServe(port, nil)).Send()
}
