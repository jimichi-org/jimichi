//go:build !linux || !amd64 || !goexperiment.jsonv2

package nodeview

import (
	"os"
	"reflect"
)

func outputInputInspectCore([]byte, reflect.Type, func(uint64) error, func(), func()) error {
	return ErrUnsupported
}

func outputReadExactCore(string, int64, bool, func(uint64) error, func()) ([]byte, error) {
	return nil, ErrUnsupported
}

func outputLoadInput(path string, destination any, regular bool) error {
	f, err := os.Open(path)
	if err != nil {
		return ErrInvalid
	}
	defer f.Close()
	if regular {
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return ErrInvalid
		}
	}
	return strictJSON(f, destination)
}

func outputExecutableBytes(path string) ([]byte, error) { return os.ReadFile(path) }

func outputInputCodec([]byte, reflect.Type, bool) (uint64, error)      { return 0, ErrUnsupported }
func outputInputShapeBound([]byte, reflect.Type, bool) (uint64, error) { return 0, ErrUnsupported }
func outputInputMask(reflect.Type) (uint64, uint64, error)             { return 0, 0, ErrUnsupported }
func outputInputNumber(string, reflect.Type) error                     { return ErrUnsupported }
func outputInputBucketHistory(uint64, *outputArithmetic) uint64        { return 0 }
