package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"time"

	"github.com/TylerZeroMaster/httptunnel"
	"github.com/TylerZeroMaster/httptunnel/internal/totp"
	"github.com/TylerZeroMaster/httptunnel/internal/totu"
	"github.com/docopt/docopt-go"
	"github.com/google/uuid"
)

const (
	sha1   = "--sha1"
	sha256 = "--sha256"
	sha512 = "--sha512"
	md5    = "--md5"
)
const algOptions = sha1 + "|" + sha256 + "|" + sha512 + "|" + md5
const usage = `Create and use TOTP keys for proprietary onetime urls

These TOTP keys do not follow any existing standards. Use at your own risk.

Usage:
    totp <key-path> [--totu]
    totp new <key-path> [--period=<seconds>] [` + algOptions + `]
    totp dump <key-path>

Options:
    --period=<seconds>    Period between TOTP codes [default: 30]
    --sha1                Use sha1 algorithm for hmac
    --sha256              Use sha256 algorithm for hmac
    --sha512              Use sha512 algorithm for hmac
    --md5                 Use md5 algorithm for hmac
    --totu                Print the code for use as a url (id + code base64 encoded)
`

var versionString = "Version: " + httptunnel.Version

func assertNilErr(err error) {
	if err != nil {
		panic(err)
	}
}

func algorithmFromOpts(opts docopt.Opts) totp.Algorithm {
	switch true {
	case opts[sha1].(bool):
		return totp.AlgorithmSHA1
	case opts[sha256].(bool):
		return totp.AlgorithmSHA256
	case opts[sha512].(bool):
		return totp.AlgorithmSHA512
	case opts[md5].(bool):
		return totp.AlgorithmMD5
	default:
		return totp.AlgorithmSHA256
	}
}

func dump(config *totp.Config) {
	fmt.Println("Version:", config.Version)
	fmt.Println("Id:", uuid.UUID(config.Id))
	fmt.Printf("Period: %ds\n", config.Period)
	fmt.Println("Algorithm:", config.Algorithm.String())
	fmt.Println("")
	encoded := []byte(base64.StdEncoding.EncodeToString(config.Secret[:]))
	for chunk := range slices.Chunk(encoded, 76) {
		fmt.Println(string(chunk))
	}
}

func writeNewConfig(path string, period int, algorithm totp.Algorithm) (*totp.Config, error) {
	config, err := totp.NewConfig(uint64(period), algorithm)
	if err != nil {
		return nil, err
	}
	fout, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	defer fout.Close()
	_, err = config.WriteTo(fout)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func main() {
	var encoded string
	opts, err := docopt.ParseArgs(usage, os.Args[1:], versionString)
	assertNilErr(err)
	path := opts["<key-path>"].(string)
	period, err := opts.Int("--period")
	assertNilErr(err)
	new := opts["new"].(bool)
	doDump := opts["dump"].(bool)
	var config *totp.Config
	algorithm := algorithmFromOpts(opts)
	if doDump {
		config, err := totp.LoadConfig(path)
		assertNilErr(err)
		dump(config)
		return
	}
	if new {
		config, err = writeNewConfig(path, period, algorithm)
		assertNilErr(err)
		assertNilErr(os.Chmod(path, 0o600))
		fmt.Fprintf(os.Stderr, "Key created: %s\n", path)
	} else {
		config, err = totp.LoadConfig(path)
		assertNilErr(err)
	}
	if opts["--totu"].(bool) {
		fmt.Println(totu.GenerateCode(time.Now(), config))
	} else {
		bytes := totp.HmacSum(time.Now(), config)
		encoded = hex.EncodeToString(bytes)
		fmt.Println(encoded)
	}
}
