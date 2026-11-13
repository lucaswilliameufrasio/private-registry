package server

import (
	"errors"
	"testing"

	"private-registry/internal/artifacts"
)

func TestParseArtifactRange(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		size       int64
		wantOffset int64
		wantLength int64
		wantPart   bool
		wantErr    bool
	}{
		{name: "no range", size: 10, wantLength: 10},
		{name: "explicit range", value: "bytes=2-5", size: 10, wantOffset: 2, wantLength: 4, wantPart: true},
		{name: "open ended range", value: "bytes=7-", size: 10, wantOffset: 7, wantLength: 3, wantPart: true},
		{name: "suffix range", value: "bytes=-4", size: 10, wantOffset: 6, wantLength: 4, wantPart: true},
		{name: "suffix larger than file", value: "bytes=-100", size: 10, wantLength: 10, wantPart: true},
		{name: "end clipped to file", value: "bytes=8-100", size: 10, wantOffset: 8, wantLength: 2, wantPart: true},
		{name: "zero file without range", size: 0},
		{name: "unsatisfiable start", value: "bytes=10-", size: 10, wantErr: true},
		{name: "end precedes start", value: "bytes=5-4", size: 10, wantErr: true},
		{name: "multiple ranges", value: "bytes=0-1,3-4", size: 10, wantErr: true},
		{name: "unsupported unit", value: "items=0-1", size: 10, wantErr: true},
		{name: "range on empty file", value: "bytes=0-0", size: 0, wantErr: true},
		{name: "integer overflow", value: "bytes=9223372036854775808-", size: 10, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			offset, length, partial, err := parseArtifactRange(test.value, test.size)
			if test.wantErr {
				if !errors.Is(err, artifacts.ErrInvalidRange) {
					t.Fatalf("parseArtifactRange(%q, %d) error = %v; want ErrInvalidRange", test.value, test.size, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseArtifactRange(%q, %d): %v", test.value, test.size, err)
			}
			if offset != test.wantOffset || length != test.wantLength || partial != test.wantPart {
				t.Fatalf("parseArtifactRange(%q, %d) = (%d, %d, %t); want (%d, %d, %t)",
					test.value, test.size, offset, length, partial, test.wantOffset, test.wantLength, test.wantPart)
			}
		})
	}
}
