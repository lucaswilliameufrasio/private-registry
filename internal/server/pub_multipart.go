package server

import (
	"context"
	"errors"
	"io"
	"mime/multipart"
	"strings"
)

// readPubMultipart stages exactly one archive and one matching upload ID. The
// caller must authenticate and check the session before invoking it, enforce a
// deadline and bound the entire request separately from the archive limit.
func readPubMultipart(ctx context.Context, source *multipart.Reader, stage io.Writer, uploadID string, maxArchive int64) (int64, error) {
	if ctx == nil || source == nil || stage == nil || uploadID == "" || maxArchive < 1 || maxArchive > 64<<20 {
		return 0, errors.New("Pub multipart parameters are invalid")
	}
	if _, ok := ctx.Deadline(); !ok {
		return 0, errors.New("Pub multipart requires a deadline")
	}
	var foundID, foundFile bool
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		part, err := source.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, errors.New("Pub multipart could not be read")
		}
		switch part.FormName() {
		case "upload_id":
			if foundID || part.FileName() != "" {
				return 0, errors.New("Pub upload ID is invalid")
			}
			value, err := io.ReadAll(io.LimitReader(part, int64(len(uploadID))+1))
			if err != nil || string(value) != uploadID {
				return 0, errors.New("Pub upload ID does not match")
			}
			foundID = true
		case "file":
			if foundFile || strings.TrimSpace(part.FileName()) == "" {
				return 0, errors.New("Pub archive part is invalid")
			}
			size, err = io.Copy(stage, io.LimitReader(part, maxArchive+1))
			if err != nil || size < 1 || size > maxArchive {
				return 0, errors.New("Pub archive exceeds limits or could not be staged")
			}
			foundFile = true
		default:
			return 0, errors.New("Pub multipart contains an unexpected field")
		}
		if err := part.Close(); err != nil {
			return 0, errors.New("Pub multipart part could not be closed")
		}
	}
	if !foundID || !foundFile {
		return 0, errors.New("Pub multipart is incomplete")
	}
	return size, nil
}
