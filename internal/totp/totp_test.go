package totp

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"os"
	"path"
	"slices"
	"testing"
	"time"
)

func configsEqual(t *testing.T, a, b *Config) {
	if a.Version != b.Version {
		t.Error("bad version")
	}
	if a.Id != b.Id {
		t.Error("bad id")
	}
	if !slices.Equal(a.Secret[:], b.Secret[:]) {
		t.Error("bad secret")
	}
	if a.Period != b.Period {
		t.Error("bad period")
	}
	if a.Algorithm != b.Algorithm {
		t.Error("bad algorithm")
	}
}

func TestOTP(t *testing.T) {
	config := &Config{
		Version:   1,
		Id:        [IDSize]byte{1},
		Secret:    [1024]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		Period:    30,
		Algorithm: AlgorithmMD5,
	}
	t.Run("generate codes", func(t *testing.T) {
		code := GenerateCode(time.Unix(1, 1), config)

		if expected := "e9d0328d77472ec81248fe28a1bf063a"; code != expected {
			t.Errorf("codes do not match: (%s) vs (%s)", expected, code)
		}

		code = GenerateCode(time.Unix(29, 1), config)

		if expected := "e9d0328d77472ec81248fe28a1bf063a"; code != expected {
			t.Errorf("codes do not match: (%s) vs (%s)", expected, code)
		}

		code = GenerateCode(time.Unix(30, 1), config)

		if expected := "6a3c23a3ac025bfd1e05b32e262bd210"; code != expected {
			t.Errorf("codes do not match: (%s) vs (%s)", expected, code)
		}

		code = GenerateCode(time.Unix(59, 1), config)

		if expected := "6a3c23a3ac025bfd1e05b32e262bd210"; code != expected {
			t.Errorf("codes do not match: (%s) vs (%s)", expected, code)
		}
	})

	t.Run("marshal unmarshal", func(t *testing.T) {
		b, err := config.Marshal()
		if err != nil {
			t.Error(err)
		}
		var configParsed Config
		err = Unmarshal(b, &configParsed)
		if err != nil {
			t.Error(err)
		}
		configsEqual(t, &configParsed, config)
	})

	t.Run("write to/read from", func(t *testing.T) {
		buf := bytes.NewBuffer(nil)
		if _, err := config.WriteTo(buf); err != nil {
			t.Error(err)
		}
		r := bytes.NewReader(buf.Bytes())
		configParsed, err := ReadConfig(r)
		if err != nil {
			t.Error(err)
		}
		configsEqual(t, configParsed, config)
	})

	t.Run("unmarshal unsupported version", func(t *testing.T) {
		config := *config
		config.Version = 255
		buf := bytes.NewBuffer(nil)
		config.WriteTo(buf)
		r := bytes.NewReader(buf.Bytes())
		_, err := ReadConfig(r)
		if err != ErrUnsupportedVersion {
			t.Error("version should be unsupported")
		}
	})

	t.Run("create config", func(t *testing.T) {
		config, err := NewConfig(1, AlgorithmMD5)
		if err != nil {
			t.Error(err)
		}
		if config.Period != 1 {
			t.Errorf("period should be 1, got %d", config.Period)
		}
		if config.Algorithm != AlgorithmMD5 {
			t.Errorf("algorithm should be %d, got %d", AlgorithmMD5, config.Algorithm)
		}
		if slices.Max(config.Secret[:]) == 0 {
			t.Error("secret was not set")
		}
	})

	t.Run("load config", func(t *testing.T) {
		d := t.TempDir()
		path := path.Join(d, "testkey.bin")
		fout, err := os.Create(path)
		if err != nil {
			t.Error(err)
		}
		_, err = config.WriteTo(fout)
		if err != nil {
			t.Error(err)
		}
		fout.Close()
		configParsed, err := LoadConfig(path)
		if err != nil {
			t.Error(err)
		}
		configsEqual(t, config, configParsed)
	})
}

func TestAlgorithm(t *testing.T) {
	nilMatch := Algorithm(255)
	t.Run("Decode", func(t *testing.T) {
		encoded := map[uint8]func() hash.Hash{
			0: sha1.New,
			1: sha256.New,
			2: sha512.New,
			3: md5.New,
		}
		for k, v := range encoded {
			h1 := Algorithm(k).Decode()()
			h2 := v()
			if !slices.Equal(h1.Sum([]byte{0}), h2.Sum([]byte{0})) {
				t.Errorf("hashing function did not match: %d", k)
			}
		}
		if nilMatch.Decode() != nil {
			t.Errorf("expected no matching hasher for value %d", nilMatch)
		}
	})
	t.Run("String", func(t *testing.T) {
		encoded := map[Algorithm]string{
			AlgorithmSHA1:   "sha1",
			AlgorithmSHA256: "sha256",
			AlgorithmSHA512: "sha512",
			AlgorithmMD5:    "md5",
		}
		for k, v := range encoded {
			if Algorithm(k).String() != v {
				t.Errorf("string value did not match: %d", k)
			}
		}
		if nilMatch.String() != "" {
			t.Errorf("expected no matching string for value %d", nilMatch)
		}
	})
}
