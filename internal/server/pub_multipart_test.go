package server

import (
	"bytes"
	"context"
	"mime/multipart"
	"testing"
	"time"
)

func TestReadPubMultipart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, tt := range []struct {
		name   string
		fields []string
		file   string
		limit  int64
		valid  bool
	}{
		{"valid", []string{"upload_id", "file"}, "archive", 7, true},
		{"reversed", []string{"file", "upload_id"}, "archive", 7, true},
		{"duplicate ID", []string{"upload_id", "upload_id", "file"}, "archive", 7, false},
		{"duplicate file", []string{"upload_id", "file", "file"}, "archive", 7, false},
		{"missing ID", []string{"file"}, "archive", 7, false},
		{"unknown field", []string{"upload_id", "file", "other"}, "archive", 7, false},
		{"oversize", []string{"upload_id", "file"}, "archive", 6, false},
		{"empty", []string{"upload_id", "file"}, "", 7, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			for _, field := range tt.fields {
				if field == "file" {
					part, err := writer.CreateFormFile("file", "package.tar.gz")
					if err != nil {
						t.Fatal(err)
					}
					if _, err := part.Write([]byte(tt.file)); err != nil {
						t.Fatal(err)
					}
				} else if err := writer.WriteField(field, "synthetic-id"); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			var stage bytes.Buffer
			size, err := readPubMultipart(ctx, multipart.NewReader(&body, writer.Boundary()), &stage, "synthetic-id", tt.limit)
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v err=%v", tt.valid, err)
			}
			if tt.valid && (size != int64(len(tt.file)) || stage.String() != tt.file) {
				t.Fatal("staged archive differs")
			}
		})
	}
}
