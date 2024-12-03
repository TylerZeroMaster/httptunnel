package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	httptunnel "github.com/TylerZeroMaster/http-tunnel"
	"github.com/docopt/docopt-go"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

const usage = `Tunnel ssh over http

Usage:
    ssh-tunnel-server [--port=<port>]

Options:
	--port=<port>    The port for the http server to listen on [default: 8080]
`

var log = zerolog.New(os.Stderr).
	With().
	Timestamp().
	Logger().
	Level(zerolog.DebugLevel)

type HTTPSSHTunnel struct{}

func (tun HTTPSSHTunnel) sendHttpResp(w http.ResponseWriter) {
	w.Header().Set("Connection", "upgrade")
	w.Header().Set("Upgrade", "ssh")
	w.WriteHeader(101)
}

func (tun HTTPSSHTunnel) getSSHAddress(r *http.Request) string {
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

var hijacker = &httptunnel.Hijacker{}

func (tun HTTPSSHTunnel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := log.With().Str("connection_id", uuid.NewString()).Logger()
	log.Info().Msg("Connection opened")
	defer log.Info().Msg("Connection closed")
	address := tun.getSSHAddress(r)
	log.Debug().Str("address", address).Msg("dialing ssh")
	if sshConn, err := net.DialTimeout("tcp", address, 45*time.Second); err != nil {
		log.Error().Err(err).Msg("dial ssh")
		http.Error(w, err.Error(), 500)
	} else {
		defer sshConn.Close()
		tun.sendHttpResp(w)
		if netConn, brw, err := hijacker.Hijack(w, r); err != nil {
			log.Error().Err(err).Msg("hijack")
		} else {
			defer netConn.Close()
			go func() {
				readAmt, err := brw.WriteTo(sshConn)
				if err != nil {
					log.Error().Err(err).Msg("copy to ssh")
				}
				log.Debug().Int64("bytes_read", readAmt).Msg("read finished")
			}()
			writeAmt, err := brw.ReadFrom(sshConn)
			if err != nil {
				log.Error().Err(err).Msg("copy to http")
			}
			log.Debug().Int64("bytes_written", writeAmt).Msg("write finished")
		}
	}
}

func envOrElse(name string, orElse string) string {
	if value := strings.TrimSpace(os.Getenv(name)); len(value) > 0 {
		return value
	} else {
		return orElse
	}
}

type CLIOptions struct {
	Port string
}

func main() {
	var options CLIOptions
	opts, err := docopt.ParseDoc(usage)
	if err != nil {
		panic(err)
	}
	opts.Bind(&options)
	port := ":" + strings.TrimLeft(envOrElse("PORT", options.Port), ":")
	if port == ":" {
		panic("empty port")
	}
	http.Handle("GET /ssh", HTTPSSHTunnel{})
	log.Info().Str("port", port).Msg("listening")
	log.Error().Err(http.ListenAndServe(port, nil)).Send()
}
