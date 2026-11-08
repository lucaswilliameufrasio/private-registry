package gomod

import (
	"encoding/json"
	"testing"
	"time"
)

func TestVersionInfoPseudoVersionTimestamp(t *testing.T) {
	modulePath := "example.com/private/parent/v2"
	version := "v2.0.1-0.20260102150405-0123456789ab"
	timestamp := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	info, err := NewVersionInfo(modulePath, version, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	body, err := MarshalVersionInfo(modulePath, info)
	if err != nil {
		t.Fatal(err)
	}
	var decoded VersionInfo
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Version != version || !decoded.Time.Equal(timestamp) {
		t.Fatalf("version info round trip=%+v err=%v", decoded, err)
	}
	if _, err := NewVersionInfo(modulePath, version, timestamp.Add(time.Second)); err == nil {
		t.Fatal("pseudo-version accepted mismatched timestamp")
	}
	if _, err := NewVersionInfo(modulePath, "v1.0.0", timestamp); err == nil {
		t.Fatal("wrong major version accepted")
	}
	if _, err := NewVersionInfo(modulePath, "v2.0.0", time.Time{}); err == nil {
		t.Fatal("missing timestamp accepted")
	}
	if _, err := NewVersionInfo(modulePath, "v2.0.0", time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("unencodable timestamp accepted")
	}
}
