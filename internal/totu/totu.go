package totu

import (
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"slices"
	"time"

	"github.com/TylerZeroMaster/httptunnel/internal/totp"
)

const IDSize = totp.IDSize

var (
	ErrCodeMismatch    = errors.New("code did not match")
	ErrCodeTooShort    = errors.New("code too short")
	ErrKeyNotFound     = errors.New("key not found")
	ErrCodeAlreadyUsed = errors.New("code already used")
)

type CircularList[T comparable] struct {
	list []T
	idx  int
}

func (c CircularList[T]) Put(item T) CircularList[T] {
	c.list[c.idx] = item
	c.idx = (c.idx + 1) % len(c.list)
	return c
}

func (c CircularList[T]) Index(item T) int {
	return slices.Index(c.list, item)
}

func (c CircularList[T]) Has(item T) bool {
	return c.Index(item) != -1
}

type Validator struct {
	configPathsById map[[IDSize]byte]string
	keysUsed        CircularList[string]
}

func (validator *Validator) Validate(t time.Time, urlCode string) error {
	if len(urlCode) == 0 {
		return ErrCodeTooShort
	}
	if validator.keysUsed.Has(urlCode) {
		return ErrCodeAlreadyUsed
	}
	decoded, err := base64.URLEncoding.DecodeString(urlCode)
	if err != nil {
		return err
	}
	if len(decoded) <= IDSize {
		return ErrCodeTooShort
	}
	kid, clientSum := [IDSize]byte(decoded[:IDSize]), decoded[IDSize:]
	keyPath, ok := validator.configPathsById[kid]
	if !ok {
		return ErrKeyNotFound
	}
	config, err := totp.LoadConfig(keyPath)
	if err != nil {
		return err
	}
	serverSum := totp.HmacSum(t, config)
	if hmac.Equal(serverSum, clientSum) {
		validator.keysUsed = validator.keysUsed.Put(urlCode)
		return nil
	}
	return ErrCodeMismatch
}

func GetId(config *totp.Config) [16]byte {
	return config.Id
}

func GenerateCode(t time.Time, config *totp.Config) string {
	code := totp.HmacSum(t, config)
	id := GetId(config)
	idAndCode := slices.Concat(id[:], code)
	return base64.URLEncoding.EncodeToString(idAndCode)
}

func NewValidator(configPaths []string) (Validator, error) {
	configPathsById := make(map[[IDSize]byte]string)
	for _, configPath := range configPaths {
		config, err := totp.LoadConfig(configPath)
		if err != nil {
			return Validator{}, err
		}
		id := GetId(config)
		configPathsById[id] = configPath
	}
	return Validator{
			configPathsById,
			CircularList[string]{make([]string, 100), 0},
		},
		nil
}
