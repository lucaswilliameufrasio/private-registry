package gomod

import (
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/mod/module"
)

// VersionInfo contains the Go proxy's public version metadata. Time must be
// provided by the publisher; the registry does not infer a VCS origin.
type VersionInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
}

// NewVersionInfo validates the module/version pair and the caller-supplied
// timestamp. Pseudo-version timestamps must match their encoded UTC second.
// This does not prove that the supplied timestamp or revision came from VCS.
func NewVersionInfo(modulePath, version string, timestamp time.Time) (VersionInfo, error) {
	if timestamp.IsZero() || module.CanonicalVersion(version) != version || module.Check(modulePath, version) != nil {
		return VersionInfo{}, errors.New("Go module version metadata is invalid")
	}
	timestamp = timestamp.UTC()
	if _, err := timestamp.MarshalJSON(); err != nil {
		return VersionInfo{}, errors.New("Go module version timestamp is invalid")
	}
	if module.IsPseudoVersion(version) {
		pseudoTime, err := module.PseudoVersionTime(version)
		if err != nil || !timestamp.Equal(pseudoTime) {
			return VersionInfo{}, errors.New("Go pseudo-version timestamp does not match")
		}
		if _, err := module.PseudoVersionBase(version); err != nil {
			return VersionInfo{}, errors.New("Go pseudo-version base is invalid")
		}
	}
	return VersionInfo{Version: version, Time: timestamp}, nil
}

// MarshalVersionInfo emits the minimal GOPROXY .info response.
func MarshalVersionInfo(modulePath string, info VersionInfo) ([]byte, error) {
	validated, err := NewVersionInfo(modulePath, info.Version, info.Time)
	if err != nil {
		return nil, err
	}
	return json.Marshal(validated)
}
