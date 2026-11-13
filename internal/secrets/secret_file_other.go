//go:build !linux

package secrets

func readPrivateFile(_ string, _ int64) ([]byte, error) {
	return nil, ErrUnsupportedPlatform
}
