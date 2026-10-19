//go:build !linux

package secrets

func createMasterKeyFile(_ string, _ []byte) error {
	return ErrUnsupportedPlatform
}

func readMasterKeyFile(_ string) ([]byte, error) {
	return nil, ErrUnsupportedPlatform
}

func masterKeyFilesSupported() bool {
	return false
}

func isSecureMasterKeyDirectory(_ string) bool {
	return false
}
