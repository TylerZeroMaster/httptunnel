package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	httptunnel "github.com/TylerZeroMaster/http-tunnel"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

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

func main() {
	port := ":8080"
	http.Handle("GET /ssh", HTTPSSHTunnel{})
	log.Error().Err(http.ListenAndServe(port, nil)).Send()
}
