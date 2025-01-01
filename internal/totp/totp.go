package totp

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"math"
	"os"
	"time"

	"github.com/google/uuid"
)

type Algorithm uint8

const (
	AlgorithmSHA1 Algorithm = iota
	AlgorithmSHA256
	AlgorithmSHA512
	AlgorithmMD5
)
const ConfigSize = 1064
const IDSize = 16

var (
	ErrUnsupportedVersion = errors.New("unsupported config version")
)

func (alg Algorithm) Decode() func() hash.Hash {
	switch alg {
	case AlgorithmSHA1:
		return sha1.New
	case AlgorithmSHA256:
		return sha256.New
	case AlgorithmSHA512:
		return sha512.New
	case AlgorithmMD5:
		return md5.New
	default:
		return nil
	}
}

func (alg Algorithm) String() string {
	switch alg {
	case AlgorithmSHA1:
		return "sha1"
	case AlgorithmSHA256:
		return "sha256"
	case AlgorithmSHA512:
		return "sha512"
	case AlgorithmMD5:
		return "md5"
	default:
		return ""
	}
}

type Config struct {
	Version   uint8
	Id        [IDSize]byte
	Secret    [1024]byte
	Period    uint64
	Algorithm Algorithm
}

func (config *Config) Marshal() ([]byte, error) {
	buf := make([]byte, ConfigSize)
	_, err := binary.Encode(buf, binary.LittleEndian, config)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (config *Config) WriteTo(w io.Writer) (int64, error) {
	return ConfigSize, binary.Write(w, binary.LittleEndian, config)
}

func Unmarshal(b []byte, config *Config) (err error) {
	if version := b[0]; version != 1 {
		err = ErrUnsupportedVersion
	} else {
		_, err = binary.Decode(b, binary.LittleEndian, config)
	}
	return
}

func ReadConfig(r io.Reader) (p *Config, err error) {
	var config Config
	p = &config
	b, err := io.ReadAll(r)
	if err != nil {
		return
	}
	err = Unmarshal(b, p)
	return
}

func NewConfig(period uint64, algorithm Algorithm) (config *Config, err error) {
	secret := [1024]byte{}
	_, err = rand.Reader.Read(secret[:])
	if err != nil {
		return
	}
	config = &Config{
		Version:   1,
		Id:        uuid.New(),
		Period:    period,
		Algorithm: algorithm,
		Secret:    secret,
	}
	return
}

func HmacSum(t time.Time, config *Config) []byte {
	secretBytes := &config.Secret
	period := config.Period
	algorithm := config.Algorithm
	counter := uint64(math.Floor(float64(t.Unix()) / float64(period)))
	mac := hmac.New(algorithm.Decode(), secretBytes[:])
	binary.Write(mac, binary.BigEndian, counter)
	return mac.Sum(nil)
}

func GenerateCode(t time.Time, config *Config) string {
	sum := HmacSum(t, config)
	return hex.EncodeToString(sum)
}

func LoadConfig(path string) (*Config, error) {
	fin, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fin.Close()
	config, err := ReadConfig(fin)
	if err != nil {
		return nil, err
	}
	return config, nil
}
